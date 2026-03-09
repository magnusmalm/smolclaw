/*
 * util/x_api.c - Shared X (Twitter) API layer
 *
 * OAuth 1.0a signing (HMAC-SHA1) and authenticated HTTP via libcurl.
 * Extracted from channels/x.c so both the X channel and X tools can
 * share the same crypto-critical OAuth implementation.
 */

#include "util/x_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <curl/curl.h>
#include "util/curl_common.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "cJSON.h"
#include "logger.h"
#include "util/str.h"
#include "constants.h"

#define LOG_TAG "x-api"
#define X_API_BASE_DEFAULT "https://api.x.com"

/* ---- Percent-encoding (RFC 3986) ---- */

static int is_unreserved(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '.' ||
           c == '_' || c == '~';
}

static char *percent_encode(const char *s)
{
    if (!s) return sc_strdup("");
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (is_unreserved(*p)) {
            sc_strbuf_append_char(&sb, (char)*p);
        } else {
            char hex[4];
            snprintf(hex, sizeof(hex), "%%%02X", *p);
            sc_strbuf_append(&sb, hex);
        }
    }
    return sc_strbuf_finish(&sb);
}

/* ---- OAuth 1.0a parameter sorting ---- */

typedef struct {
    char *key;
    char *val;
} oauth_param_t;

static int param_cmp(const void *a, const void *b)
{
    const oauth_param_t *pa = a, *pb = b;
    int r = strcmp(pa->key, pb->key);
    return r ? r : strcmp(pa->val, pb->val);
}

/* ---- OAuth 1.0a signature generation ---- */

static char *generate_nonce(void)
{
    unsigned char buf[16];
    RAND_bytes(buf, sizeof(buf));
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    for (int i = 0; i < 16; i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", buf[i]);
        sc_strbuf_append(&sb, hex);
    }
    return sc_strbuf_finish(&sb);
}

/*
 * Build OAuth 1.0a Authorization header value.
 * method: "GET" or "POST"
 * url: full URL (no query string)
 * query_params: key=val pairs from query string (NULL if none)
 * query_param_count: number of query params
 */
static char *oauth_sign(const sc_x_creds_t *creds, const char *method,
                         const char *url,
                         const oauth_param_t *query_params,
                         int query_param_count)
{
    char *nonce = generate_nonce();
    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp), "%ld", (long)time(NULL));

    /* OAuth params */
    oauth_param_t oauth_params[] = {
        { "oauth_consumer_key",     (char *)creds->consumer_key },
        { "oauth_nonce",            nonce },
        { "oauth_signature_method", "HMAC-SHA1" },
        { "oauth_timestamp",        timestamp },
        { "oauth_token",            (char *)creds->access_token },
        { "oauth_version",          "1.0" },
    };
    int n_oauth = 6;

    /* Merge all params: oauth + query */
    int total = n_oauth + query_param_count;
    oauth_param_t *all = calloc((size_t)total, sizeof(oauth_param_t));
    if (!all) { free(nonce); return NULL; }

    for (int i = 0; i < n_oauth; i++) {
        all[i].key = percent_encode(oauth_params[i].key);
        all[i].val = percent_encode(oauth_params[i].val);
    }
    for (int i = 0; i < query_param_count; i++) {
        all[n_oauth + i].key = percent_encode(query_params[i].key);
        all[n_oauth + i].val = percent_encode(query_params[i].val);
    }

    /* Sort alphabetically */
    qsort(all, (size_t)total, sizeof(oauth_param_t), param_cmp);

    /* Build parameter string */
    sc_strbuf_t param_str;
    sc_strbuf_init(&param_str);
    for (int i = 0; i < total; i++) {
        if (i > 0) sc_strbuf_append_char(&param_str, '&');
        sc_strbuf_append(&param_str, all[i].key);
        sc_strbuf_append_char(&param_str, '=');
        sc_strbuf_append(&param_str, all[i].val);
    }
    char *params = sc_strbuf_finish(&param_str);

    /* Build base string: METHOD&url&params */
    char *enc_url = percent_encode(url);
    char *enc_params = percent_encode(params);

    sc_strbuf_t base;
    sc_strbuf_init(&base);
    sc_strbuf_append(&base, method);
    sc_strbuf_append_char(&base, '&');
    sc_strbuf_append(&base, enc_url);
    sc_strbuf_append_char(&base, '&');
    sc_strbuf_append(&base, enc_params);
    char *base_string = sc_strbuf_finish(&base);

    /* Signing key: percent_encode(consumer_secret)&percent_encode(token_secret) */
    char *enc_cs = percent_encode(creds->consumer_secret);
    char *enc_ts = percent_encode(creds->access_token_secret);

    sc_strbuf_t key_buf;
    sc_strbuf_init(&key_buf);
    sc_strbuf_append(&key_buf, enc_cs);
    sc_strbuf_append_char(&key_buf, '&');
    sc_strbuf_append(&key_buf, enc_ts);
    char *signing_key = sc_strbuf_finish(&key_buf);

    /* HMAC-SHA1 */
    unsigned char hmac_result[20];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha1(),
         signing_key, (int)strlen(signing_key),
         (unsigned char *)base_string, strlen(base_string),
         hmac_result, &hmac_len);

    /* Base64 encode */
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    sc_strbuf_t sig;
    sc_strbuf_init(&sig);
    for (unsigned int i = 0; i < hmac_len; i += 3) {
        unsigned int n = ((unsigned int)hmac_result[i]) << 16;
        if (i + 1 < hmac_len) n |= ((unsigned int)hmac_result[i + 1]) << 8;
        if (i + 2 < hmac_len) n |= (unsigned int)hmac_result[i + 2];
        sc_strbuf_append_char(&sig, b64[(n >> 18) & 0x3F]);
        sc_strbuf_append_char(&sig, b64[(n >> 12) & 0x3F]);
        sc_strbuf_append_char(&sig, (i + 1 < hmac_len) ? b64[(n >> 6) & 0x3F] : '=');
        sc_strbuf_append_char(&sig, (i + 2 < hmac_len) ? b64[n & 0x3F] : '=');
    }
    char *signature = sc_strbuf_finish(&sig);

    /* Build Authorization header */
    char *enc_sig = percent_encode(signature);
    char *enc_nonce = percent_encode(nonce);
    char *enc_ck = percent_encode(creds->consumer_key);
    char *enc_at = percent_encode(creds->access_token);

    sc_strbuf_t auth;
    sc_strbuf_init(&auth);
    sc_strbuf_appendf(&auth,
        "OAuth oauth_consumer_key=\"%s\", "
        "oauth_nonce=\"%s\", "
        "oauth_signature=\"%s\", "
        "oauth_signature_method=\"HMAC-SHA1\", "
        "oauth_timestamp=\"%s\", "
        "oauth_token=\"%s\", "
        "oauth_version=\"1.0\"",
        enc_ck, enc_nonce, enc_sig, timestamp, enc_at);
    char *auth_header = sc_strbuf_finish(&auth);

    /* Cleanup */
    for (int i = 0; i < total; i++) {
        free(all[i].key);
        free(all[i].val);
    }
    free(all);
    free(params);
    free(enc_url);
    free(enc_params);
    free(base_string);
    /* Cleanse secret key material before freeing */
    OPENSSL_cleanse(enc_cs, strlen(enc_cs));
    free(enc_cs);
    OPENSSL_cleanse(enc_ts, strlen(enc_ts));
    free(enc_ts);
    OPENSSL_cleanse(signing_key, strlen(signing_key));
    free(signing_key);
    OPENSSL_cleanse(hmac_result, sizeof(hmac_result));
    free(signature);
    free(enc_sig);
    free(enc_nonce);
    free(enc_ck);
    free(enc_at);
    free(nonce);

    return auth_header;
}

/* ---- CURL write callback ---- */

static size_t write_cb(void *data, size_t size, size_t nmemb, void *userp)
{
    if (nmemb > 0 && size > SIZE_MAX / nmemb) return 0;
    size_t total = size * nmemb;
    sc_strbuf_t *sb = userp;
    if (sb->len + total > SC_CURL_MAX_RESPONSE) return 0;
    char *buf = malloc(total + 1);
    if (!buf) return 0;
    memcpy(buf, data, total);
    buf[total] = '\0';
    sc_strbuf_append(sb, buf);
    free(buf);
    return total;
}

/* ---- Public API ---- */

sc_x_creds_t *sc_x_creds_new(const char *consumer_key,
                               const char *consumer_secret,
                               const char *access_token,
                               const char *access_token_secret,
                               const char *api_base)
{
    if (!consumer_key || !consumer_secret ||
        !access_token || !access_token_secret)
        return NULL;

    sc_x_creds_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;

    c->consumer_key = sc_strdup(consumer_key);
    c->consumer_secret = sc_strdup(consumer_secret);
    c->access_token = sc_strdup(access_token);
    c->access_token_secret = sc_strdup(access_token_secret);
    c->api_base = sc_strdup(api_base && api_base[0] ? api_base : X_API_BASE_DEFAULT);
    return c;
}

void sc_x_creds_free(sc_x_creds_t *creds)
{
    if (!creds) return;
    free(creds->consumer_key);
    free(creds->consumer_secret);
    free(creds->access_token);
    free(creds->access_token_secret);
    free(creds->api_base);
    free(creds);
}

cJSON *sc_x_api_get(const sc_x_creds_t *creds, const char *path,
                     const sc_x_param_t *params, int param_count)
{
    if (!creds || !path) return NULL;

    /* Build base URL (no query string) for OAuth signing */
    sc_strbuf_t url_buf;
    sc_strbuf_init(&url_buf);
    sc_strbuf_appendf(&url_buf, "%s%s", creds->api_base, path);
    char *base_url = sc_strbuf_finish(&url_buf);

    /* Build full URL with query string for curl */
    sc_strbuf_t full_url;
    sc_strbuf_init(&full_url);
    sc_strbuf_append(&full_url, base_url);
    if (param_count > 0) {
        sc_strbuf_append_char(&full_url, '?');
        for (int i = 0; i < param_count; i++) {
            if (i > 0) sc_strbuf_append_char(&full_url, '&');
            char *ek = percent_encode(params[i].key);
            char *ev = percent_encode(params[i].val);
            sc_strbuf_appendf(&full_url, "%s=%s", ek, ev);
            free(ek);
            free(ev);
        }
    }
    char *curl_url = sc_strbuf_finish(&full_url);

    /* OAuth sign (base URL without query) */
    char *auth = oauth_sign(creds, "GET", base_url,
                             (const oauth_param_t *)params, param_count);
    free(base_url);

    if (!auth) { free(curl_url); return NULL; }

    CURL *curl = sc_curl_init();
    if (!curl) { free(curl_url); free(auth); return NULL; }

    sc_strbuf_t body;
    sc_strbuf_init(&body);

    sc_strbuf_t auth_hdr;
    sc_strbuf_init(&auth_hdr);
    sc_strbuf_appendf(&auth_hdr, "Authorization: %s", auth);
    char *auth_str = sc_strbuf_finish(&auth_hdr);
    free(auth);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_str);

    curl_easy_setopt(curl, CURLOPT_URL, curl_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(curl_url);
    free(auth_str);

    if (res != CURLE_OK) {
        SC_LOG_ERROR(LOG_TAG, "HTTP GET %s failed: %s",
                     path, curl_easy_strerror(res));
        sc_strbuf_free(&body);
        return NULL;
    }

    if (http_code == 429) {
        SC_LOG_WARN(LOG_TAG, "Rate limited (429) on GET %s", path);
        sc_strbuf_free(&body);
        return NULL;
    }

    if (http_code < 200 || http_code >= 300) {
        char *resp = sc_strbuf_finish(&body);
        SC_LOG_ERROR(LOG_TAG, "HTTP GET %s returned %ld: %.200s",
                     path, http_code, resp ? resp : "");
        free(resp);
        return NULL;
    }

    char *response = sc_strbuf_finish(&body);
    cJSON *json = cJSON_Parse(response);
    free(response);
    return json;
}

cJSON *sc_x_api_post(const sc_x_creds_t *creds, const char *path,
                      cJSON *payload)
{
    if (!creds || !path) return NULL;

    sc_strbuf_t url_buf;
    sc_strbuf_init(&url_buf);
    sc_strbuf_appendf(&url_buf, "%s%s", creds->api_base, path);
    char *url = sc_strbuf_finish(&url_buf);

    /* OAuth sign (no query params — JSON body excluded from signature) */
    char *auth = oauth_sign(creds, "POST", url, NULL, 0);
    if (!auth) { free(url); return NULL; }

    char *body_str = payload ? cJSON_PrintUnformatted(payload) : sc_strdup("{}");

    CURL *curl = sc_curl_init();
    if (!curl) { free(url); free(auth); free(body_str); return NULL; }

    sc_strbuf_t resp;
    sc_strbuf_init(&resp);

    sc_strbuf_t auth_hdr;
    sc_strbuf_init(&auth_hdr);
    sc_strbuf_appendf(&auth_hdr, "Authorization: %s", auth);
    char *auth_str = sc_strbuf_finish(&auth_hdr);
    free(auth);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_str);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(url);
    free(body_str);
    free(auth_str);

    if (res != CURLE_OK) {
        SC_LOG_ERROR(LOG_TAG, "HTTP POST %s failed: %s",
                     path, curl_easy_strerror(res));
        sc_strbuf_free(&resp);
        return NULL;
    }

    if (http_code == 429) {
        SC_LOG_WARN(LOG_TAG, "Rate limited (429) on POST %s", path);
        sc_strbuf_free(&resp);
        return NULL;
    }

    if (http_code < 200 || http_code >= 300) {
        char *r = sc_strbuf_finish(&resp);
        SC_LOG_ERROR(LOG_TAG, "HTTP POST %s returned %ld: %.200s",
                     path, http_code, r ? r : "");
        free(r);
        return NULL;
    }

    char *response = sc_strbuf_finish(&resp);
    cJSON *json = cJSON_Parse(response);
    free(response);
    return json;
}
