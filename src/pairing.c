/*
 * smolclaw - pairing module
 * Challenge-code pairing flow for channel DM access control.
 */

#include "pairing.h"
#include "audit.h"
#include "constants.h"
#include "logger.h"
#include "util/str.h"
#include "util/json_helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <libgen.h>

#define LOG_TAG "pairing"

/* Alphabet: no 0/O/1/I to avoid ambiguity */
static const char CODE_ALPHA[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
#define CODE_ALPHA_LEN 32

#define SC_PAIRING_MAX_FAILED  5
#define SC_PAIRING_LOCKOUT_MS  (15L * 60 * 1000)

struct sc_pairing_store {
    char *channel;
    char *file_path;
    sc_pairing_request_t *requests;
    int count;
    int cap;
    int failed_attempts;
    long last_failed_ms;
};

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void ensure_dir(const char *path)
{
    char *tmp = sc_strdup(path);
    if (!tmp) return;
    char *dir = dirname(tmp);
    if (dir) {
        mkdir(dir, 0700);
    }
    free(tmp);
}

/* Generate a random code of SC_PAIRING_CODE_LEN chars */
static char *generate_code(void)
{
    unsigned char buf[SC_PAIRING_CODE_LEN];
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return NULL;

    if (fread(buf, 1, sizeof(buf), f) != sizeof(buf)) {
        fclose(f);
        return NULL;
    }
    fclose(f);

    char *code = malloc(SC_PAIRING_CODE_LEN + 1);
    if (!code) return NULL;

    for (int i = 0; i < SC_PAIRING_CODE_LEN; i++) {
        code[i] = CODE_ALPHA[buf[i] % CODE_ALPHA_LEN];
    }
    code[SC_PAIRING_CODE_LEN] = '\0';
    return code;
}

/* Remove expired requests */
static void prune_expired(sc_pairing_store_t *ps)
{
    long cutoff = now_ms() - SC_PAIRING_EXPIRY_MS;
    int dst = 0;
    for (int i = 0; i < ps->count; i++) {
        if (ps->requests[i].created_ms >= cutoff) {
            if (dst != i) {
                ps->requests[dst] = ps->requests[i];
            }
            dst++;
        } else {
            free(ps->requests[i].sender_id);
            free(ps->requests[i].code);
        }
    }
    ps->count = dst;
}

/* Load requests from JSON file */
static void load_store(sc_pairing_store_t *ps)
{
    cJSON *root = sc_json_load_file(ps->file_path);
    if (!root) return;

    cJSON *arr = sc_json_get_array(root, "requests");
    if (!arr) {
        cJSON_Delete(root);
        return;
    }

    int n = cJSON_GetArraySize(arr);
    if (n > 0) {
        ps->requests = calloc((size_t)n, sizeof(sc_pairing_request_t));
        if (!ps->requests) {
            cJSON_Delete(root);
            return;
        }
        ps->cap = n;
        ps->count = 0;

        const cJSON *item;
        cJSON_ArrayForEach(item, arr) {
            const char *sid = sc_json_get_string(item, "sender_id", NULL);
            const char *code = sc_json_get_string(item, "code", NULL);
            double ts = sc_json_get_double(item, "created_ms", 0);
            if (sid && code) {
                ps->requests[ps->count].sender_id = sc_strdup(sid);
                ps->requests[ps->count].code = sc_strdup(code);
                ps->requests[ps->count].created_ms = (long)ts;
                ps->count++;
            }
        }
    }

    cJSON_Delete(root);
}

/* Save requests to JSON file */
static void save_store(sc_pairing_store_t *ps)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return;

    cJSON *arr = cJSON_AddArrayToObject(root, "requests");
    for (int i = 0; i < ps->count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "sender_id", ps->requests[i].sender_id);
        cJSON_AddStringToObject(item, "code", ps->requests[i].code);
        cJSON_AddNumberToObject(item, "created_ms", (double)ps->requests[i].created_ms);
        cJSON_AddItemToArray(arr, item);
    }

    ensure_dir(ps->file_path);
    sc_json_save_file(ps->file_path, root);
    cJSON_Delete(root);
}

/* --- Public API --- */

sc_dm_policy_t sc_dm_policy_from_str(const char *s)
{
    if (!s) return SC_DM_POLICY_ALLOWLIST;  /* fail-closed: deny all if unconfigured */
    if (strcmp(s, "open") == 0)     return SC_DM_POLICY_OPEN;
    if (strcmp(s, "allowlist") == 0) return SC_DM_POLICY_ALLOWLIST;
    if (strcmp(s, "pairing") == 0)  return SC_DM_POLICY_PAIRING;
    return SC_DM_POLICY_ALLOWLIST;  /* unknown string → fail-closed */
}

const char *sc_dm_policy_to_str(sc_dm_policy_t policy)
{
    switch (policy) {
    case SC_DM_POLICY_ALLOWLIST: return "allowlist";
    case SC_DM_POLICY_PAIRING:  return "pairing";
    default:                     return "open";
    }
}

sc_pairing_store_t *sc_pairing_store_new(const char *channel, const char *store_dir)
{
    if (!channel || !store_dir) return NULL;

    sc_pairing_store_t *ps = calloc(1, sizeof(*ps));
    if (!ps) return NULL;

    ps->channel = sc_strdup(channel);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/%s.json", store_dir, channel);
    ps->file_path = sc_strbuf_finish(&sb);

    load_store(ps);
    return ps;
}

void sc_pairing_store_free(sc_pairing_store_t *ps)
{
    if (!ps) return;
    for (int i = 0; i < ps->count; i++) {
        free(ps->requests[i].sender_id);
        free(ps->requests[i].code);
    }
    free(ps->requests);
    free(ps->channel);
    free(ps->file_path);
    free(ps);
}

const char *sc_pairing_store_challenge(sc_pairing_store_t *ps, const char *sender_id)
{
    if (!ps || !sender_id) return NULL;

    prune_expired(ps);

    /* Check if sender already has a pending code */
    for (int i = 0; i < ps->count; i++) {
        if (strcmp(ps->requests[i].sender_id, sender_id) == 0) {
            return ps->requests[i].code;
        }
    }

    /* Check max pending */
    if (ps->count >= SC_PAIRING_MAX_PENDING) {
        SC_LOG_WARN(LOG_TAG, "Max pending pairing requests reached (%d)",
                    SC_PAIRING_MAX_PENDING);
        return NULL;
    }

    /* Generate new code */
    char *code = generate_code();
    if (!code) return NULL;

    /* Grow array if needed */
    if (ps->count >= ps->cap) {
        int new_cap = ps->cap ? ps->cap * 2 : 4;
        sc_pairing_request_t *tmp = realloc(ps->requests,
            (size_t)new_cap * sizeof(sc_pairing_request_t));
        if (!tmp) { free(code); return NULL; }
        ps->requests = tmp;
        ps->cap = new_cap;
    }

    ps->requests[ps->count].sender_id = sc_strdup(sender_id);
    ps->requests[ps->count].code = code;
    ps->requests[ps->count].created_ms = now_ms();
    ps->count++;

    save_store(ps);

    SC_LOG_INFO(LOG_TAG, "Generated pairing code for %s on %s",
                sender_id, ps->channel);
    sc_audit_log_ext("pairing", sender_id, 0, 0,
                     ps->channel, sender_id, "pairing_challenge");

    return code;
}

char *sc_pairing_store_approve(sc_pairing_store_t *ps, const char *code)
{
    if (!ps || !code) return NULL;

    /* Brute force lockout */
    if (ps->failed_attempts >= SC_PAIRING_MAX_FAILED) {
        long now = now_ms();
        if (now - ps->last_failed_ms < SC_PAIRING_LOCKOUT_MS) {
            SC_LOG_WARN(LOG_TAG, "Pairing approve locked out (%d failed attempts)",
                        ps->failed_attempts);
            sc_audit_log_ext("pairing", "lockout", 1, 0,
                             ps->channel, NULL, "pairing_lockout");
            return NULL;
        }
        ps->failed_attempts = 0;  /* lockout expired */
    }

    prune_expired(ps);

    for (int i = 0; i < ps->count; i++) {
        if (sc_timing_safe_cmp(ps->requests[i].code, code) == 0) {
            char *sender_id = ps->requests[i].sender_id;
            free(ps->requests[i].code);

            /* Remove by shifting */
            for (int j = i; j < ps->count - 1; j++) {
                ps->requests[j] = ps->requests[j + 1];
            }
            ps->count--;

            save_store(ps);

            ps->failed_attempts = 0;  /* reset on success */

            SC_LOG_INFO(LOG_TAG, "Approved pairing for %s on %s",
                        sender_id, ps->channel);
            sc_audit_log_ext("pairing", sender_id, 0, 0,
                             ps->channel, sender_id, "pairing_approved");
            return sender_id; /* Caller owns */
        }
    }

    /* No match — track failed attempt */
    ps->failed_attempts++;
    ps->last_failed_ms = now_ms();
    sc_audit_log_ext("pairing", "invalid_code", 1, 0,
                     ps->channel, NULL, "pairing_rejected");

    return NULL;
}

int sc_pairing_store_list(sc_pairing_store_t *ps, sc_pairing_request_t **out)
{
    if (!ps) { if (out) *out = NULL; return 0; }

    prune_expired(ps);

    if (out) *out = ps->requests;
    return ps->count;
}
