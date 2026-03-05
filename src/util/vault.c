/*
 * util/vault.c — AES-256-GCM encrypted secret vault
 *
 * File format:
 *   Bytes 0-7:    Magic "SCVAULT\x01"
 *   Bytes 8-23:   Salt (16 bytes, RAND_bytes)
 *   Bytes 24-35:  IV/Nonce (12 bytes, fresh per save)
 *   Bytes 36-39:  Payload length (uint32_t big-endian)
 *   Bytes 40-55:  GCM auth tag (16 bytes)
 *   Bytes 56-N:   AES-256-GCM ciphertext
 *
 * Plaintext payload is JSON: {"key_name": "secret_value", ...}
 * Key derivation: PBKDF2-HMAC-SHA256 with 600,000 iterations.
 */

#include "util/vault.h"
#include "util/str.h"
#include "logger.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <cJSON.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>

#define LOG_TAG "vault"

#define VAULT_MAGIC      "SCVAULT\x01"
#define VAULT_MAGIC_LEN  8
#define VAULT_SALT_LEN   16
#define VAULT_IV_LEN     12
#define VAULT_TAG_LEN    16
#define VAULT_KEY_LEN    32       /* AES-256 */
#define VAULT_PBKDF2_ITER 600000
#define VAULT_HEADER_LEN (VAULT_MAGIC_LEN + VAULT_SALT_LEN + VAULT_IV_LEN + 4 + VAULT_TAG_LEN)
#define VAULT_MAX_SIZE   (1024 * 1024)  /* 1 MB max */

struct sc_vault {
    char *path;
    unsigned char key[VAULT_KEY_LEN];
    unsigned char salt[VAULT_SALT_LEN];
    cJSON *data;       /* Decrypted JSON object */
    int unlocked;
};

/* Derive AES-256 key from password + salt */
static int derive_key(const char *password, const unsigned char *salt,
                      unsigned char *key_out)
{
    int rc = PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                                salt, VAULT_SALT_LEN,
                                VAULT_PBKDF2_ITER,
                                EVP_sha256(),
                                VAULT_KEY_LEN, key_out);
    return (rc == 1) ? 0 : -1;
}

/* Encrypt plaintext with AES-256-GCM. Returns ciphertext (malloc'd).
 * Sets *out_len and writes tag to tag_out. */
static unsigned char *encrypt_gcm(const unsigned char *key,
                                   const unsigned char *iv,
                                   const unsigned char *plaintext,
                                   int plaintext_len,
                                   unsigned char *tag_out,
                                   int *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    unsigned char *ciphertext = malloc((size_t)plaintext_len + VAULT_TAG_LEN);
    if (!ciphertext) { EVP_CIPHER_CTX_free(ctx); return NULL; }

    int len = 0;
    *out_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, VAULT_IV_LEN, NULL) != 1)
        goto fail;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto fail;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        goto fail;
    *out_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        goto fail;
    *out_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, VAULT_TAG_LEN, tag_out) != 1)
        goto fail;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;

fail:
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    *out_len = 0;
    return NULL;
}

/* Decrypt ciphertext with AES-256-GCM. Returns plaintext (malloc'd).
 * Sets *out_len. Returns NULL on auth failure. */
static unsigned char *decrypt_gcm(const unsigned char *key,
                                   const unsigned char *iv,
                                   const unsigned char *ciphertext,
                                   int ciphertext_len,
                                   const unsigned char *tag,
                                   int *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    unsigned char *plaintext = malloc((size_t)ciphertext_len + 1);
    if (!plaintext) { EVP_CIPHER_CTX_free(ctx); return NULL; }

    int len = 0;
    *out_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, VAULT_IV_LEN, NULL) != 1)
        goto fail;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto fail;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        goto fail;
    *out_len = len;

    /* Set expected tag before finalize */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, VAULT_TAG_LEN,
                             (void *)tag) != 1)
        goto fail;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        /* Auth tag mismatch — wrong password or tampered data */
        goto fail;
    }
    *out_len += len;
    plaintext[*out_len] = '\0';

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;

fail:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(plaintext, (size_t)ciphertext_len + 1);
    free(plaintext);
    *out_len = 0;
    return NULL;
}

/* Write uint32 big-endian */
static void write_be32(unsigned char *buf, uint32_t val)
{
    buf[0] = (unsigned char)(val >> 24);
    buf[1] = (unsigned char)(val >> 16);
    buf[2] = (unsigned char)(val >> 8);
    buf[3] = (unsigned char)(val);
}

/* Read uint32 big-endian */
static uint32_t read_be32(const unsigned char *buf)
{
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) |
           ((uint32_t)buf[3]);
}

sc_vault_t *sc_vault_new(const char *path)
{
    if (!path) return NULL;
    sc_vault_t *v = calloc(1, sizeof(*v));
    if (!v) return NULL;
    v->path = sc_strdup(path);
    return v;
}

/* Recursively cleanse all string values in a cJSON tree before deletion */
static void cjson_cleanse_strings(cJSON *item)
{
    for (cJSON *child = item; child; child = child->next) {
        if (child->valuestring) {
            OPENSSL_cleanse(child->valuestring, strlen(child->valuestring));
        }
        if (child->string) {
            OPENSSL_cleanse(child->string, strlen(child->string));
        }
        if (child->child) {
            cjson_cleanse_strings(child->child);
        }
    }
}

void sc_vault_free(sc_vault_t *v)
{
    if (!v) return;
    OPENSSL_cleanse(v->key, VAULT_KEY_LEN);
    OPENSSL_cleanse(v->salt, VAULT_SALT_LEN);
    if (v->data) {
        char *json_str = cJSON_PrintUnformatted(v->data);
        if (json_str) {
            OPENSSL_cleanse(json_str, strlen(json_str));
            free(json_str);
        }
        cjson_cleanse_strings(v->data);
        cJSON_Delete(v->data);
    }
    free(v->path);
    free(v);
}

int sc_vault_init(sc_vault_t *v, const char *password)
{
    if (!v || !password) return -1;

    /* Generate random salt */
    if (RAND_bytes(v->salt, VAULT_SALT_LEN) != 1) {
        SC_LOG_ERROR(LOG_TAG, "Failed to generate random salt");
        return -1;
    }

    /* Derive key */
    if (derive_key(password, v->salt, v->key) != 0) {
        SC_LOG_ERROR(LOG_TAG, "Key derivation failed");
        return -1;
    }

    /* Start with empty JSON object */
    v->data = cJSON_CreateObject();
    v->unlocked = 1;

    /* Save to disk */
    return sc_vault_save(v);
}

int sc_vault_unlock(sc_vault_t *v, const char *password)
{
    if (!v || !password) return -1;

    /* Read file */
    FILE *f = fopen(v->path, "rb");
    if (!f) {
        SC_LOG_ERROR(LOG_TAG, "Cannot open vault: %s", strerror(errno));
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long flen = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (flen < VAULT_HEADER_LEN || flen > VAULT_MAX_SIZE) {
        SC_LOG_ERROR(LOG_TAG, "Vault file invalid size: %ld", flen);
        fclose(f);
        return -1;
    }

    unsigned char *raw = malloc((size_t)flen);
    if (!raw) { fclose(f); return -1; }

    size_t nread = fread(raw, 1, (size_t)flen, f);
    fclose(f);

    if ((long)nread != flen) {
        free(raw);
        return -1;
    }

    /* Verify magic */
    if (memcmp(raw, VAULT_MAGIC, VAULT_MAGIC_LEN) != 0) {
        SC_LOG_ERROR(LOG_TAG, "Invalid vault magic");
        free(raw);
        return -1;
    }

    /* Parse header */
    const unsigned char *salt = raw + VAULT_MAGIC_LEN;
    const unsigned char *iv = salt + VAULT_SALT_LEN;
    uint32_t payload_len = read_be32(iv + VAULT_IV_LEN);
    const unsigned char *tag = iv + VAULT_IV_LEN + 4;
    const unsigned char *ciphertext = tag + VAULT_TAG_LEN;

    int ct_len = (int)((size_t)flen - VAULT_HEADER_LEN);
    if (ct_len < 0 || (uint32_t)ct_len != payload_len) {
        SC_LOG_ERROR(LOG_TAG, "Vault payload size mismatch");
        free(raw);
        return -1;
    }

    /* Copy salt and derive key */
    memcpy(v->salt, salt, VAULT_SALT_LEN);
    if (derive_key(password, v->salt, v->key) != 0) {
        free(raw);
        return -1;
    }

    /* Decrypt */
    int pt_len = 0;
    unsigned char *plaintext = decrypt_gcm(v->key, iv, ciphertext,
                                           ct_len, tag, &pt_len);
    free(raw);

    if (!plaintext) {
        SC_LOG_ERROR(LOG_TAG, "Decryption failed (wrong password or corrupted vault)");
        OPENSSL_cleanse(v->key, VAULT_KEY_LEN);
        return -1;
    }

    /* Parse JSON */
    v->data = cJSON_Parse((char *)plaintext);
    OPENSSL_cleanse(plaintext, (size_t)pt_len);
    free(plaintext);

    if (!v->data || !cJSON_IsObject(v->data)) {
        SC_LOG_ERROR(LOG_TAG, "Vault JSON parse failed");
        if (v->data) cjson_cleanse_strings(v->data);
        cJSON_Delete(v->data);
        v->data = NULL;
        OPENSSL_cleanse(v->key, VAULT_KEY_LEN);
        return -1;
    }

    v->unlocked = 1;
    SC_LOG_INFO(LOG_TAG, "Vault unlocked (%d keys)",
                cJSON_GetArraySize(v->data));
    return 0;
}

const char *sc_vault_get(const sc_vault_t *v, const char *key)
{
    if (!v || !v->unlocked || !v->data || !key) return NULL;
    cJSON *item = cJSON_GetObjectItemCaseSensitive(v->data, key);
    if (!item || !cJSON_IsString(item)) return NULL;
    return item->valuestring;
}

int sc_vault_set(sc_vault_t *v, const char *key, const char *value)
{
    if (!v || !v->unlocked || !v->data || !key || !value) return -1;

    cJSON *old = cJSON_DetachItemFromObjectCaseSensitive(v->data, key);
    if (old) {
        cjson_cleanse_strings(old);
        cJSON_Delete(old);
    }
    cJSON_AddStringToObject(v->data, key, value);
    return 0;
}

int sc_vault_remove(sc_vault_t *v, const char *key)
{
    if (!v || !v->unlocked || !v->data || !key) return -1;

    cJSON *item = cJSON_DetachItemFromObjectCaseSensitive(v->data, key);
    if (!item) return -1;

    cjson_cleanse_strings(item);
    cJSON_Delete(item);
    return 0;
}

int sc_vault_list(const sc_vault_t *v, char ***keys)
{
    if (!v || !v->unlocked || !v->data || !keys) return 0;

    int count = cJSON_GetArraySize(v->data);
    if (count == 0) {
        *keys = NULL;
        return 0;
    }

    *keys = calloc((size_t)count, sizeof(char *));
    if (!*keys) return 0;

    int i = 0;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, v->data) {
        (*keys)[i] = sc_strdup(item->string);
        i++;
    }
    return i;
}

int sc_vault_save(sc_vault_t *v)
{
    if (!v || !v->unlocked || !v->data) return -1;

    /* Serialize JSON */
    char *json_str = cJSON_PrintUnformatted(v->data);
    if (!json_str) return -1;

    int pt_len = (int)strlen(json_str);

    /* Fresh IV for every save */
    unsigned char iv[VAULT_IV_LEN];
    if (RAND_bytes(iv, VAULT_IV_LEN) != 1) {
        OPENSSL_cleanse(json_str, (size_t)pt_len);
        free(json_str);
        return -1;
    }

    /* Encrypt */
    unsigned char tag[VAULT_TAG_LEN];
    int ct_len = 0;
    unsigned char *ciphertext = encrypt_gcm(v->key, iv,
                                             (unsigned char *)json_str,
                                             pt_len, tag, &ct_len);
    OPENSSL_cleanse(json_str, (size_t)pt_len);
    free(json_str);

    if (!ciphertext) {
        SC_LOG_ERROR(LOG_TAG, "Encryption failed");
        return -1;
    }

    /* Build file: header + ciphertext */
    size_t total_len = VAULT_HEADER_LEN + (size_t)ct_len;
    unsigned char *raw = malloc(total_len);
    if (!raw) {
        OPENSSL_cleanse(ciphertext, (size_t)ct_len);
        free(ciphertext);
        return -1;
    }

    unsigned char *p = raw;
    memcpy(p, VAULT_MAGIC, VAULT_MAGIC_LEN);  p += VAULT_MAGIC_LEN;
    memcpy(p, v->salt, VAULT_SALT_LEN);       p += VAULT_SALT_LEN;
    memcpy(p, iv, VAULT_IV_LEN);              p += VAULT_IV_LEN;
    write_be32(p, (uint32_t)ct_len);          p += 4;
    memcpy(p, tag, VAULT_TAG_LEN);            p += VAULT_TAG_LEN;
    memcpy(p, ciphertext, (size_t)ct_len);

    OPENSSL_cleanse(ciphertext, (size_t)ct_len);
    free(ciphertext);

    /* Atomic write: temp file + fsync + rename */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s.tmp.XXXXXX", v->path);
    char *tmp_path = sc_strbuf_finish(&sb);

    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        SC_LOG_ERROR(LOG_TAG, "mkstemp failed: %s", strerror(errno));
        free(tmp_path);
        OPENSSL_cleanse(raw, total_len);
        free(raw);
        return -1;
    }

    /* Set permissions before writing */
    fchmod(fd, 0600);

    FILE *f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        unlink(tmp_path);
        free(tmp_path);
        OPENSSL_cleanse(raw, total_len);
        free(raw);
        return -1;
    }

    size_t written = fwrite(raw, 1, total_len, f);
    fflush(f);
    fsync(fileno(f));
    fclose(f);

    OPENSSL_cleanse(raw, total_len);
    free(raw);

    if (written != total_len) {
        unlink(tmp_path);
        free(tmp_path);
        return -1;
    }

    if (rename(tmp_path, v->path) != 0) {
        SC_LOG_ERROR(LOG_TAG, "rename failed: %s", strerror(errno));
        unlink(tmp_path);
        free(tmp_path);
        return -1;
    }

    free(tmp_path);
    SC_LOG_DEBUG(LOG_TAG, "Vault saved (%d bytes)", (int)total_len);
    return 0;
}

int sc_vault_change_password(sc_vault_t *v, const char *new_password)
{
    if (!v || !v->unlocked || !new_password) return -1;

    /* Generate new salt */
    if (RAND_bytes(v->salt, VAULT_SALT_LEN) != 1) return -1;

    /* Derive new key */
    unsigned char old_key[VAULT_KEY_LEN];
    memcpy(old_key, v->key, VAULT_KEY_LEN);

    if (derive_key(new_password, v->salt, v->key) != 0) {
        /* Restore old key on failure */
        memcpy(v->key, old_key, VAULT_KEY_LEN);
        OPENSSL_cleanse(old_key, VAULT_KEY_LEN);
        return -1;
    }

    OPENSSL_cleanse(old_key, VAULT_KEY_LEN);

    return sc_vault_save(v);
}

int sc_vault_exists(const char *path)
{
    if (!path) return 0;
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

char *sc_vault_get_path(void)
{
    return sc_expand_home("~/.smolclaw/vault.enc");
}

char *sc_vault_prompt_password(const char *prompt)
{
    if (!isatty(STDIN_FILENO)) return NULL;

    struct termios old, new_term;
    if (tcgetattr(STDIN_FILENO, &old) != 0) return NULL;

    fprintf(stderr, "%s", prompt ? prompt : "Password: ");
    fflush(stderr);

    new_term = old;
    new_term.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    char buf[256];
    char *result = NULL;
    if (fgets(buf, (int)sizeof(buf), stdin)) {
        /* Strip trailing newline */
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
            buf[--len] = '\0';
        result = sc_strdup(buf);
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    fprintf(stderr, "\n");

    OPENSSL_cleanse(buf, sizeof(buf));
    return result;
}

void sc_vault_free_password(char *pw)
{
    if (!pw) return;
    OPENSSL_cleanse(pw, strlen(pw));
    free(pw);
}
