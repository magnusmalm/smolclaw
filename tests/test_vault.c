/*
 * smolclaw - vault encryption tests
 */

#include "test_main.h"
#include "util/vault.h"
#include "util/str.h"

#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>

/* Helper: create temp dir */
static char *make_tmpdir(void)
{
    static char tmpdir[64];
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/sc_test_vault_XXXXXX");
    return mkdtemp(tmpdir);
}

/* Helper: cleanup temp dir */
static void cleanup_tmpdir(const char *dir)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "rm -rf %s", dir);
    char *cmd = sc_strbuf_finish(&sb);
    system(cmd);
    free(cmd);
}

/* Helper: get vault path in temp dir */
static char *vault_path(const char *dir)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/vault.enc", dir);
    return sc_strbuf_finish(&sb);
}

/* ---- Tests ---- */

static void test_vault_init(void)
{
    char *dir = make_tmpdir();
    ASSERT_NOT_NULL(dir);
    char *path = vault_path(dir);

    sc_vault_t *v = sc_vault_new(path);
    ASSERT_NOT_NULL(v);

    int rc = sc_vault_init(v, "testpass123");
    ASSERT_INT_EQ(rc, 0);

    /* Vault file should exist with 0600 permissions */
    struct stat st;
    ASSERT_INT_EQ(stat(path, &st), 0);
    ASSERT((st.st_mode & 0777) == 0600, "vault should have 0600 permissions");

    sc_vault_free(v);
    free(path);
    cleanup_tmpdir(dir);
}

static void test_vault_set_get(void)
{
    char *dir = make_tmpdir();
    char *path = vault_path(dir);

    sc_vault_t *v = sc_vault_new(path);
    sc_vault_init(v, "testpass");

    sc_vault_set(v, "api_key", "sk-ant-test123456789");
    sc_vault_set(v, "other_key", "value2");

    const char *val = sc_vault_get(v, "api_key");
    ASSERT_NOT_NULL(val);
    ASSERT_STR_EQ(val, "sk-ant-test123456789");

    val = sc_vault_get(v, "other_key");
    ASSERT_NOT_NULL(val);
    ASSERT_STR_EQ(val, "value2");

    /* Non-existent key */
    ASSERT(sc_vault_get(v, "no_such_key") == NULL,
           "non-existent key should return NULL");

    sc_vault_free(v);
    free(path);
    cleanup_tmpdir(dir);
}

static void test_vault_save_and_reload(void)
{
    char *dir = make_tmpdir();
    char *path = vault_path(dir);

    /* Create and populate vault */
    {
        sc_vault_t *v = sc_vault_new(path);
        sc_vault_init(v, "mypassword");
        sc_vault_set(v, "anthropic", "sk-ant-xxx");
        sc_vault_set(v, "openai", "sk-oai-yyy");
        sc_vault_save(v);
        sc_vault_free(v);
    }

    /* Reload and verify */
    {
        sc_vault_t *v = sc_vault_new(path);
        int rc = sc_vault_unlock(v, "mypassword");
        ASSERT_INT_EQ(rc, 0);

        const char *val = sc_vault_get(v, "anthropic");
        ASSERT_NOT_NULL(val);
        ASSERT_STR_EQ(val, "sk-ant-xxx");

        val = sc_vault_get(v, "openai");
        ASSERT_NOT_NULL(val);
        ASSERT_STR_EQ(val, "sk-oai-yyy");

        sc_vault_free(v);
    }

    free(path);
    cleanup_tmpdir(dir);
}

static void test_vault_wrong_password(void)
{
    char *dir = make_tmpdir();
    char *path = vault_path(dir);

    sc_vault_t *v = sc_vault_new(path);
    sc_vault_init(v, "correct_password");
    sc_vault_set(v, "secret", "value");
    sc_vault_save(v);
    sc_vault_free(v);

    /* Try to unlock with wrong password */
    v = sc_vault_new(path);
    int rc = sc_vault_unlock(v, "wrong_password");
    ASSERT(rc != 0, "wrong password should fail");

    sc_vault_free(v);
    free(path);
    cleanup_tmpdir(dir);
}

static void test_vault_remove(void)
{
    char *dir = make_tmpdir();
    char *path = vault_path(dir);

    sc_vault_t *v = sc_vault_new(path);
    sc_vault_init(v, "pass");
    sc_vault_set(v, "key1", "val1");
    sc_vault_set(v, "key2", "val2");

    int rc = sc_vault_remove(v, "key1");
    ASSERT_INT_EQ(rc, 0);

    ASSERT(sc_vault_get(v, "key1") == NULL, "removed key should be NULL");
    ASSERT_NOT_NULL(sc_vault_get(v, "key2"));

    /* Remove non-existent key */
    rc = sc_vault_remove(v, "no_such_key");
    ASSERT(rc != 0, "removing non-existent key should fail");

    sc_vault_free(v);
    free(path);
    cleanup_tmpdir(dir);
}

static void test_vault_list(void)
{
    char *dir = make_tmpdir();
    char *path = vault_path(dir);

    sc_vault_t *v = sc_vault_new(path);
    sc_vault_init(v, "pass");
    sc_vault_set(v, "alpha", "1");
    sc_vault_set(v, "beta", "2");
    sc_vault_set(v, "gamma", "3");

    char **keys = NULL;
    int count = sc_vault_list(v, &keys);
    ASSERT_INT_EQ(count, 3);
    ASSERT_NOT_NULL(keys);

    /* Verify all keys present (order may vary) */
    int found_alpha = 0, found_beta = 0, found_gamma = 0;
    for (int i = 0; i < count; i++) {
        if (strcmp(keys[i], "alpha") == 0) found_alpha = 1;
        if (strcmp(keys[i], "beta") == 0) found_beta = 1;
        if (strcmp(keys[i], "gamma") == 0) found_gamma = 1;
        free(keys[i]);
    }
    free(keys);

    ASSERT(found_alpha, "should have alpha");
    ASSERT(found_beta, "should have beta");
    ASSERT(found_gamma, "should have gamma");

    sc_vault_free(v);
    free(path);
    cleanup_tmpdir(dir);
}

static void test_vault_list_empty(void)
{
    char *dir = make_tmpdir();
    char *path = vault_path(dir);

    sc_vault_t *v = sc_vault_new(path);
    sc_vault_init(v, "pass");

    char **keys = NULL;
    int count = sc_vault_list(v, &keys);
    ASSERT_INT_EQ(count, 0);

    sc_vault_free(v);
    free(path);
    cleanup_tmpdir(dir);
}

static void test_vault_change_password(void)
{
    char *dir = make_tmpdir();
    char *path = vault_path(dir);

    /* Create with original password */
    sc_vault_t *v = sc_vault_new(path);
    sc_vault_init(v, "old_password");
    sc_vault_set(v, "key", "secret_value");
    sc_vault_save(v);
    sc_vault_free(v);

    /* Change password */
    v = sc_vault_new(path);
    ASSERT_INT_EQ(sc_vault_unlock(v, "old_password"), 0);
    ASSERT_INT_EQ(sc_vault_change_password(v, "new_password"), 0);
    sc_vault_free(v);

    /* Old password should fail */
    v = sc_vault_new(path);
    ASSERT(sc_vault_unlock(v, "old_password") != 0,
           "old password should fail after change");
    sc_vault_free(v);

    /* New password should work */
    v = sc_vault_new(path);
    ASSERT_INT_EQ(sc_vault_unlock(v, "new_password"), 0);
    const char *val = sc_vault_get(v, "key");
    ASSERT_NOT_NULL(val);
    ASSERT_STR_EQ(val, "secret_value");
    sc_vault_free(v);

    free(path);
    cleanup_tmpdir(dir);
}

static void test_vault_overwrite_key(void)
{
    char *dir = make_tmpdir();
    char *path = vault_path(dir);

    sc_vault_t *v = sc_vault_new(path);
    sc_vault_init(v, "pass");

    sc_vault_set(v, "key", "value1");
    ASSERT_STR_EQ(sc_vault_get(v, "key"), "value1");

    sc_vault_set(v, "key", "value2");
    ASSERT_STR_EQ(sc_vault_get(v, "key"), "value2");

    sc_vault_free(v);
    free(path);
    cleanup_tmpdir(dir);
}

static void test_vault_exists(void)
{
    char *dir = make_tmpdir();
    char *path = vault_path(dir);

    ASSERT_INT_EQ(sc_vault_exists(path), 0);

    sc_vault_t *v = sc_vault_new(path);
    sc_vault_init(v, "pass");
    sc_vault_free(v);

    ASSERT_INT_EQ(sc_vault_exists(path), 1);

    free(path);
    cleanup_tmpdir(dir);
}

static void test_vault_null_safety(void)
{
    ASSERT(sc_vault_new(NULL) == NULL, "NULL path should return NULL");
    sc_vault_free(NULL);  /* Should not crash */

    ASSERT_INT_EQ(sc_vault_exists(NULL), 0);

    sc_vault_t *v = sc_vault_new("/tmp/nonexistent");
    ASSERT(sc_vault_get(v, "key") == NULL,
           "get on locked vault should return NULL");
    ASSERT(sc_vault_set(v, "key", "val") != 0,
           "set on locked vault should fail");
    sc_vault_free(v);
}

static void test_vault_tampered_file(void)
{
    char *dir = make_tmpdir();
    char *path = vault_path(dir);

    /* Create valid vault */
    sc_vault_t *v = sc_vault_new(path);
    sc_vault_init(v, "password");
    sc_vault_set(v, "key", "value");
    sc_vault_save(v);
    sc_vault_free(v);

    /* Tamper with the ciphertext (flip a byte near the end) */
    FILE *f = fopen(path, "r+b");
    ASSERT_NOT_NULL(f);
    fseek(f, -5, SEEK_END);
    unsigned char byte;
    fread(&byte, 1, 1, f);
    byte ^= 0xFF;
    fseek(f, -1, SEEK_CUR);
    fwrite(&byte, 1, 1, f);
    fclose(f);

    /* Unlock should fail (GCM tag mismatch) */
    v = sc_vault_new(path);
    int rc = sc_vault_unlock(v, "password");
    ASSERT(rc != 0, "tampered vault should fail to unlock");
    sc_vault_free(v);

    free(path);
    cleanup_tmpdir(dir);
}

static void test_vault_get_path(void)
{
    char *path = sc_vault_get_path();
    ASSERT_NOT_NULL(path);
    ASSERT(strstr(path, "vault.enc") != NULL,
           "path should contain vault.enc");
    ASSERT(strstr(path, ".smolclaw") != NULL,
           "path should contain .smolclaw");
    free(path);
}

int main(void)
{
    RUN_TEST(test_vault_init);
    RUN_TEST(test_vault_set_get);
    RUN_TEST(test_vault_save_and_reload);
    RUN_TEST(test_vault_wrong_password);
    RUN_TEST(test_vault_remove);
    RUN_TEST(test_vault_list);
    RUN_TEST(test_vault_list_empty);
    RUN_TEST(test_vault_change_password);
    RUN_TEST(test_vault_overwrite_key);
    RUN_TEST(test_vault_exists);
    RUN_TEST(test_vault_null_safety);
    RUN_TEST(test_vault_tampered_file);
    RUN_TEST(test_vault_get_path);
    TEST_REPORT();
}
