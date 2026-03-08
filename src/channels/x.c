/*
 * smolclaw - X (Twitter) channel
 * X API v2 via libcurl with OAuth 1.0a. REST polling for mentions, POST for tweets/DMs.
 */

#include "channels/x.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <curl/curl.h>
#include "util/curl_common.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>

#include "cJSON.h"
#include "constants.h"
#include "logger.h"
#include "pairing.h"
#include "util/str.h"
#include "util/json_helpers.h"

#define LOG_TAG "x"
#define X_API_BASE "https://api.x.com"
#define X_MAX_TWEET_LEN 280

typedef struct {
    char *consumer_key;
    char *consumer_secret;
    char *access_token;
    char *access_token_secret;
    char *api_base;
    char *bot_user_id;       /* authenticated user's numeric ID */
    char *bot_username;      /* authenticated user's screen name */
    char *since_id;          /* last-seen mention tweet ID */
    char *since_dm_id;       /* last-seen DM event ID */
    int poll_interval_sec;
    int enable_dms;
    int read_only;
    pthread_t poll_thread;
    int thread_started;
} x_data_t;

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
static char *oauth_sign(const x_data_t *xd, const char *method,
                         const char *url,
                         const oauth_param_t *query_params,
                         int query_param_count)
{
    char *nonce = generate_nonce();
    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp), "%ld", (long)time(NULL));

    /* OAuth params */
    oauth_param_t oauth_params[] = {
        { "oauth_consumer_key",     (char *)xd->consumer_key },
        { "oauth_nonce",            nonce },
        { "oauth_signature_method", "HMAC-SHA1" },
        { "oauth_timestamp",        timestamp },
        { "oauth_token",            (char *)xd->access_token },
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
    char *enc_cs = percent_encode(xd->consumer_secret);
    char *enc_ts = percent_encode(xd->access_token_secret);

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
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
    char *enc_ck = percent_encode(xd->consumer_key);
    char *enc_at = percent_encode(xd->access_token);

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
    free(enc_cs);
    free(enc_ts);
    free(signing_key);
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

/* ---- HTTP helpers ---- */

static cJSON *x_get(const x_data_t *xd, const char *path,
                     const oauth_param_t *params, int param_count)
{
    /* Build URL */
    sc_strbuf_t url_buf;
    sc_strbuf_init(&url_buf);
    sc_strbuf_appendf(&url_buf, "%s%s", xd->api_base, path);
    char *base_url = sc_strbuf_finish(&url_buf);

    /* URL with query string for curl */
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
    char *auth = oauth_sign(xd, "GET", base_url, params, param_count);
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
        SC_LOG_ERROR(LOG_TAG, "HTTP GET %s failed: %s", path, curl_easy_strerror(res));
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

static cJSON *x_post(const x_data_t *xd, const char *path, cJSON *payload)
{
    sc_strbuf_t url_buf;
    sc_strbuf_init(&url_buf);
    sc_strbuf_appendf(&url_buf, "%s%s", xd->api_base, path);
    char *url = sc_strbuf_finish(&url_buf);

    /* OAuth sign (no query params — JSON body is excluded from signature) */
    char *auth = oauth_sign(xd, "POST", url, NULL, 0);
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
        SC_LOG_ERROR(LOG_TAG, "HTTP POST %s failed: %s", path, curl_easy_strerror(res));
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

/* ---- Tweet splitting ---- */

/*
 * Split text into tweet-sized chunks (max 280 chars).
 * Tries to split at word boundaries. Returns array of strings (caller frees).
 */
static char **split_tweets(const char *text, int *out_count)
{
    *out_count = 0;
    if (!text || !text[0]) return NULL;

    size_t len = strlen(text);
    if (len <= X_MAX_TWEET_LEN) {
        char **arr = malloc(sizeof(char *));
        if (!arr) return NULL;
        arr[0] = sc_strdup(text);
        *out_count = 1;
        return arr;
    }

    /* Estimate max chunks */
    int max_chunks = (int)(len / (X_MAX_TWEET_LEN - 5)) + 2;
    char **chunks = calloc((size_t)max_chunks, sizeof(char *));
    if (!chunks) return NULL;

    const char *pos = text;
    int count = 0;

    while (*pos && count < max_chunks) {
        size_t remaining = strlen(pos);
        if (remaining <= X_MAX_TWEET_LEN) {
            chunks[count++] = sc_strdup(pos);
            break;
        }

        /* Find a good split point — walk back from limit to find space */
        int split = X_MAX_TWEET_LEN;
        while (split > X_MAX_TWEET_LEN / 2 && pos[split] != ' ' && pos[split] != '\n')
            split--;

        /* If no good split found, force at max length */
        if (split <= X_MAX_TWEET_LEN / 2)
            split = X_MAX_TWEET_LEN;

        char *chunk = malloc((size_t)split + 1);
        if (!chunk) break;
        memcpy(chunk, pos, (size_t)split);
        chunk[split] = '\0';
        chunks[count++] = chunk;

        pos += split;
        /* Skip leading whitespace in next chunk */
        while (*pos == ' ') pos++;
    }

    *out_count = count;
    return chunks;
}

/* ---- Bot identity ---- */

static int fetch_bot_identity(x_data_t *xd)
{
    oauth_param_t params[] = {
        { "user.fields", "username" },
    };
    cJSON *resp = x_get(xd, "/2/users/me", params, 1);
    if (!resp) return -1;

    const cJSON *data = cJSON_GetObjectItem(resp, "data");
    if (!data) {
        cJSON_Delete(resp);
        return -1;
    }

    const char *id = sc_json_get_string(data, "id", NULL);
    const char *username = sc_json_get_string(data, "username", NULL);

    if (!id) {
        cJSON_Delete(resp);
        return -1;
    }

    free(xd->bot_user_id);
    xd->bot_user_id = sc_strdup(id);
    free(xd->bot_username);
    xd->bot_username = username ? sc_strdup(username) : NULL;

    SC_LOG_INFO(LOG_TAG, "Authenticated as @%s (id=%s)",
                xd->bot_username ? xd->bot_username : "?", xd->bot_user_id);

    cJSON_Delete(resp);
    return 0;
}

/* ---- Mention processing ---- */

static void strip_bot_mention(char *text, const char *bot_username)
{
    if (!text || !bot_username) return;

    /* Find @bot_username at start */
    if (text[0] != '@') return;

    size_t ulen = strlen(bot_username);
    if (strncasecmp(text + 1, bot_username, ulen) != 0) return;

    char after = text[1 + ulen];
    if (after != '\0' && after != ' ' && after != '\t' && after != '\n')
        return;

    /* Skip the mention and trailing whitespace */
    const char *src = text + 1 + ulen;
    while (*src == ' ' || *src == '\t') src++;
    memmove(text, src, strlen(src) + 1);
}

static void process_mention(sc_channel_t *ch, const cJSON *tweet)
{
    x_data_t *xd = ch->data;

    const char *tweet_id = sc_json_get_string(tweet, "id", NULL);
    const char *text = sc_json_get_string(tweet, "text", NULL);
    const char *author_id = sc_json_get_string(tweet, "author_id", NULL);

    if (!tweet_id || !text || !author_id) return;

    /* Update since_id */
    if (!xd->since_id || strcmp(tweet_id, xd->since_id) > 0) {
        free(xd->since_id);
        xd->since_id = sc_strdup(tweet_id);
    }

    /* Skip our own tweets */
    if (xd->bot_user_id && strcmp(author_id, xd->bot_user_id) == 0)
        return;

    /* Strip bot mention from text */
    char *content = sc_strdup(text);
    if (content)
        strip_bot_mention(content, xd->bot_username);

    if (!content || content[0] == '\0') {
        free(content);
        content = sc_strdup("[empty mention]");
    }

    SC_LOG_DEBUG(LOG_TAG, "Mention from user %s: tweet %s", author_id, tweet_id);

    /* Use tweet_id as chat_id (for threading replies) and author_id as sender_id */
    sc_channel_handle_message(ch, author_id, tweet_id, content);
    free(content);
}

/* ---- DM processing ---- */

static void process_dm(sc_channel_t *ch, const cJSON *event)
{
    x_data_t *xd = ch->data;

    const char *event_id = sc_json_get_string(event, "id", NULL);
    const char *text = sc_json_get_string(event, "text", NULL);
    const char *sender_id = sc_json_get_string(event, "sender_id", NULL);

    if (!event_id || !sender_id) return;

    /* Update since_dm_id */
    if (!xd->since_dm_id || strcmp(event_id, xd->since_dm_id) > 0) {
        free(xd->since_dm_id);
        xd->since_dm_id = sc_strdup(event_id);
    }

    /* Skip our own DMs */
    if (xd->bot_user_id && strcmp(sender_id, xd->bot_user_id) == 0)
        return;

    const char *content = (text && text[0]) ? text : "[empty DM]";

    SC_LOG_DEBUG(LOG_TAG, "DM from user %s", sender_id);

    /* Use "dm:<sender_id>" as chat_id so x_send() can route to DM reply */
    sc_strbuf_t dm_chat;
    sc_strbuf_init(&dm_chat);
    sc_strbuf_appendf(&dm_chat, "dm:%s", sender_id);
    char *dm_chat_id = sc_strbuf_finish(&dm_chat);
    sc_channel_handle_message(ch, sender_id, dm_chat_id, content);
    free(dm_chat_id);
}

/* ---- Polling ---- */

static void poll_mentions(sc_channel_t *ch)
{
    x_data_t *xd = ch->data;

    if (!xd->bot_user_id) return;

    sc_strbuf_t path;
    sc_strbuf_init(&path);
    sc_strbuf_appendf(&path, "/2/users/%s/mentions", xd->bot_user_id);
    char *endpoint = sc_strbuf_finish(&path);

    /* Build query params */
    oauth_param_t params[3];
    int n = 0;
    params[n].key = "tweet.fields"; params[n].val = "author_id,text"; n++;
    params[n].key = "max_results"; params[n].val = "100"; n++;
    if (xd->since_id) {
        params[n].key = "since_id"; params[n].val = xd->since_id; n++;
    }

    cJSON *resp = x_get(xd, endpoint, params, n);
    free(endpoint);
    if (!resp) return;

    const cJSON *data = cJSON_GetObjectItem(resp, "data");
    if (data && cJSON_IsArray(data)) {
        const cJSON *tweet;
        cJSON_ArrayForEach(tweet, data) {
            if (ch->running)
                process_mention(ch, tweet);
        }
    }

    cJSON_Delete(resp);
}

static void poll_dms(sc_channel_t *ch)
{
    x_data_t *xd = ch->data;
    if (!xd->enable_dms) return;

    oauth_param_t params[2];
    int n = 0;
    params[n].key = "dm_event.fields"; params[n].val = "sender_id,text"; n++;
    if (xd->since_dm_id) {
        params[n].key = "since_id"; params[n].val = xd->since_dm_id; n++;
    }

    cJSON *resp = x_get(xd, "/2/dm_events", params, n);
    if (!resp) return;

    const cJSON *data = cJSON_GetObjectItem(resp, "data");
    if (data && cJSON_IsArray(data)) {
        const cJSON *event;
        cJSON_ArrayForEach(event, data) {
            if (ch->running)
                process_dm(ch, event);
        }
    }

    cJSON_Delete(resp);
}

/* ---- Outbound: send tweet or DM ---- */

static int send_tweet(const x_data_t *xd, const char *text,
                       const char *reply_to_tweet_id)
{
    cJSON *payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "text", text);

    if (reply_to_tweet_id) {
        cJSON *reply = cJSON_CreateObject();
        cJSON_AddStringToObject(reply, "in_reply_to_tweet_id", reply_to_tweet_id);
        cJSON_AddItemToObject(payload, "reply", reply);
    }

    cJSON *resp = x_post(xd, "/2/tweets", payload);
    cJSON_Delete(payload);

    if (!resp) return -1;

    /* Check for data.id in response */
    const cJSON *data = cJSON_GetObjectItem(resp, "data");
    int ok = (data && cJSON_GetObjectItem(data, "id"));
    if (!ok)
        SC_LOG_ERROR(LOG_TAG, "Tweet post failed");
    cJSON_Delete(resp);
    return ok ? 0 : -1;
}

static int send_dm(const x_data_t *xd, const char *participant_id,
                    const char *text)
{
    sc_strbuf_t path;
    sc_strbuf_init(&path);
    sc_strbuf_appendf(&path, "/2/dm_conversations/with/%s/messages", participant_id);
    char *endpoint = sc_strbuf_finish(&path);

    cJSON *payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "text", text);

    cJSON *resp = x_post(xd, endpoint, payload);
    cJSON_Delete(payload);
    free(endpoint);

    if (!resp) return -1;

    const cJSON *data = cJSON_GetObjectItem(resp, "data");
    int ok = (data && cJSON_GetObjectItem(data, "dm_event_id"));
    if (!ok)
        SC_LOG_ERROR(LOG_TAG, "DM send failed");
    cJSON_Delete(resp);
    return ok ? 0 : -1;
}

/* ---- Channel vtable ---- */

static void *poll_thread(void *arg)
{
    sc_channel_t *ch = arg;
    x_data_t *xd = ch->data;

    SC_LOG_INFO(LOG_TAG, "Polling thread started (interval=%ds)", xd->poll_interval_sec);

    /* Fetch bot identity */
    int backoff = SC_X_RECONNECT_DELAY;
    while (ch->running && fetch_bot_identity(xd) != 0) {
        SC_LOG_WARN(LOG_TAG, "Failed to fetch bot identity, retrying in %ds...", backoff);
        sc_channel_sleep(&ch->running, backoff);
        if (backoff < SC_X_RECONNECT_MAX_DELAY)
            backoff *= 2;
    }

    backoff = SC_X_RECONNECT_DELAY;

    while (ch->running) {
        poll_mentions(ch);
        poll_dms(ch);

        /* Reset backoff on successful poll */
        backoff = SC_X_RECONNECT_DELAY;

        sc_channel_sleep(&ch->running, xd->poll_interval_sec);
    }

    SC_LOG_INFO(LOG_TAG, "Polling thread stopped");
    return NULL;
}

static int x_start(sc_channel_t *self)
{
    x_data_t *xd = self->data;

    self->running = 1;
    xd->thread_started = 1;

    int ret = pthread_create(&xd->poll_thread, NULL, poll_thread, self);
    if (ret != 0) {
        SC_LOG_ERROR(LOG_TAG, "Failed to create polling thread");
        self->running = 0;
        xd->thread_started = 0;
        return -1;
    }

    SC_LOG_INFO(LOG_TAG, "X channel started (REST polling%s)",
                xd->read_only ? ", read-only" : "");
    return 0;
}

static int x_stop(sc_channel_t *self)
{
    x_data_t *xd = self->data;
    self->running = 0;

    if (xd->thread_started)
        pthread_join(xd->poll_thread, NULL);

    SC_LOG_INFO(LOG_TAG, "X channel stopped");
    return 0;
}

static int x_send(sc_channel_t *self, sc_outbound_msg_t *msg)
{
    if (!self->running) return -1;
    x_data_t *xd = self->data;

    if (xd->read_only) {
        SC_LOG_WARN(LOG_TAG, "Send blocked: X channel is in read-only mode");
        return -1;
    }

    /* Check if this is a DM reply (chat_id prefixed with "dm:") */
    if (msg->chat_id && strncmp(msg->chat_id, "dm:", 3) == 0) {
        const char *user_id = msg->chat_id + 3;
        /* DMs have no length limit per-message (10000 chars), but split at 10000 */
        return send_dm(xd, user_id, msg->content);
    }

    /* Tweet reply — split into thread if needed */
    int chunk_count = 0;
    char **chunks = split_tweets(msg->content, &chunk_count);
    if (!chunks || chunk_count == 0) return -1;

    const char *reply_to = msg->chat_id;  /* original mention tweet ID */
    int result = 0;

    for (int i = 0; i < chunk_count; i++) {
        if (send_tweet(xd, chunks[i], reply_to) != 0) {
            SC_LOG_ERROR(LOG_TAG, "Failed to send tweet chunk %d/%d", i + 1, chunk_count);
            result = -1;
            break;
        }
        /* TODO: ideally chain replies using the new tweet's ID,
         * but that requires parsing the response. For now, all chunks
         * reply to the original mention. */
    }

    for (int i = 0; i < chunk_count; i++)
        free(chunks[i]);
    free(chunks);

    return result;
}

static int x_send_typing(sc_channel_t *self, const char *chat_id)
{
    /* X has no typing indicator API */
    (void)self;
    (void)chat_id;
    return 0;
}

static int x_is_running(sc_channel_t *self)
{
    return self ? self->running : 0;
}

static void x_destroy(sc_channel_t *self)
{
    if (!self) return;
    x_data_t *xd = self->data;
    if (xd) {
        free(xd->consumer_key);
        free(xd->consumer_secret);
        free(xd->access_token);
        free(xd->access_token_secret);
        free(xd->api_base);
        free(xd->bot_user_id);
        free(xd->bot_username);
        free(xd->since_id);
        free(xd->since_dm_id);
        free(xd);
    }
    self->data = NULL;
    sc_channel_base_free(self);
}

/* ---- Factory ---- */

sc_channel_t *sc_channel_x_new(sc_x_config_t *cfg, sc_bus_t *bus)
{
    if (!cfg || !cfg->consumer_key || !cfg->consumer_secret ||
        !cfg->access_token || !cfg->access_token_secret)
        return NULL;

    sc_channel_t *ch = calloc(1, sizeof(*ch));
    if (!ch) return NULL;

    x_data_t *xd = calloc(1, sizeof(*xd));
    if (!xd) { free(ch); return NULL; }

    xd->consumer_key = sc_strdup(cfg->consumer_key);
    xd->consumer_secret = sc_strdup(cfg->consumer_secret);
    xd->access_token = sc_strdup(cfg->access_token);
    xd->access_token_secret = sc_strdup(cfg->access_token_secret);
    xd->api_base = sc_strdup(cfg->api_base && cfg->api_base[0]
                             ? cfg->api_base : X_API_BASE);
    xd->poll_interval_sec = cfg->poll_interval_sec > 0 ? cfg->poll_interval_sec : 60;
    xd->enable_dms = cfg->enable_dms;
    xd->read_only = cfg->read_only;
    xd->thread_started = 0;

    ch->name = SC_CHANNEL_X;
    ch->start = x_start;
    ch->stop = x_stop;
    ch->send = x_send;
    ch->send_typing = x_send_typing;
    ch->is_running = x_is_running;
    ch->destroy = x_destroy;
    ch->bus = bus;
    ch->running = 0;
    ch->data = xd;

    sc_channel_init_security(ch, cfg->dm_policy, cfg->allow_from,
                              cfg->allow_from_count, "x");

    return ch;
}
