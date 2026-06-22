/*
 * tools/notify.c - Notification tool
 *
 * Sends notifications to external services (Discord, Telegram, generic
 * webhook) via HTTP POST. Uses Apprise-compatible URL schemes for
 * consistency with common notification dispatchers.
 */

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/notify.h"
#include "tools/types.h"
#include "util/curl_common.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "logger.h"
#include "cJSON.h"

#define TAG "notify"

/* Maximum URLs per config */
#define MAX_URLS 16

/* HTTP timeout */
#define NOTIFY_TIMEOUT_SEC 10

/* ---------- URL parsing (Apprise-compatible scheme handling) ---------- */

typedef enum {
    SCHEME_DISCORD,
    SCHEME_TELEGRAM,
    SCHEME_JSON,
} notify_scheme_t;

typedef struct {
    notify_scheme_t scheme;
    char *param1;
    char *param2;
} parsed_url_t;

static void
parsed_url_free(parsed_url_t *u)
{
    free(u->param1);
    free(u->param2);
    u->param1 = u->param2 = NULL;
}

static int
parse_one_url(const char *s, parsed_url_t *out)
{
    memset(out, 0, sizeof(*out));

    if (strncmp(s, "discord://", 10) == 0) {
        out->scheme = SCHEME_DISCORD;
        const char *rest = s + 10;
        const char *slash = strchr(rest, '/');
        if (!slash || slash == rest || !*(slash + 1))
            return -1;
        size_t id_len = (size_t)(slash - rest);
        out->param1 = sc_strdup(rest);
        if (out->param1) out->param1[id_len] = '\0';
        out->param2 = sc_strdup(slash + 1);
        return (out->param1 && out->param2) ? 0 : -1;
    }
    if (strncmp(s, "tg://", 5) == 0) {
        out->scheme = SCHEME_TELEGRAM;
        const char *rest = s + 5;
        const char *slash = strchr(rest, '/');
        if (!slash || slash == rest || !*(slash + 1))
            return -1;
        size_t tok_len = (size_t)(slash - rest);
        out->param1 = sc_strdup(rest);
        if (out->param1) out->param1[tok_len] = '\0';
        out->param2 = sc_strdup(slash + 1);
        return (out->param1 && out->param2) ? 0 : -1;
    }
    if (strncmp(s, "json://", 7) == 0) {
        out->scheme = SCHEME_JSON;
        out->param1 = sc_strdup(s + 7);
        return out->param1 ? 0 : -1;
    }
    return -1;
}

/* ---------- curl helpers ------------------------------------------------ */

static size_t
discard_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    (void)ptr; (void)userdata;
    return size * nmemb;
}

static char *
json_escape_str(const char *s)
{
    /* Worst case: every char needs escaping (\X = 2 chars) + NUL */
    size_t slen = strlen(s);
    char *out = malloc(slen * 2 + 1);
    if (!out) return NULL;

    char *w = out;
    for (const char *p = s; *p; p++) {
        switch (*p) {
        case '"':  *w++ = '\\'; *w++ = '"';  break;
        case '\\': *w++ = '\\'; *w++ = '\\'; break;
        case '\n': *w++ = '\\'; *w++ = 'n';  break;
        case '\r': *w++ = '\\'; *w++ = 'r';  break;
        case '\t': *w++ = '\\'; *w++ = 't';  break;
        default:   *w++ = *p;                 break;
        }
    }
    *w = '\0';
    return out;
}

static int
http_post_json(const char *url, const char *json_body)
{
    CURL *curl = sc_curl_init();
    if (!curl) return -1;

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)NOTIFY_TIMEOUT_SEC);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)NOTIFY_TIMEOUT_SEC);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_cb);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    if (res == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK && code >= 200 && code < 300) ? 0 : -1;
}

/* ---------- Send to each backend ---------------------------------------- */

static int
send_one(const parsed_url_t *u, const char *title, const char *body)
{
    char *esc_title = json_escape_str(title);
    char *esc_body  = json_escape_str(body);
    if (!esc_title || !esc_body) {
        free(esc_title); free(esc_body);
        return -1;
    }

    char url[512];
    char json[2048];
    int rc = -1;

    switch (u->scheme) {
    case SCHEME_DISCORD:
        snprintf(url, sizeof(url),
                 "https://discord.com/api/webhooks/%s/%s",
                 u->param1, u->param2);
        snprintf(json, sizeof(json),
                 "{\"embeds\":[{\"title\":\"%s\",\"description\":\"%s\","
                 "\"color\":5814783}]}",
                 esc_title, esc_body);
        rc = http_post_json(url, json);
        break;

    case SCHEME_TELEGRAM:
        snprintf(url, sizeof(url),
                 "https://api.telegram.org/bot%s/sendMessage",
                 u->param1);
        snprintf(json, sizeof(json),
                 "{\"chat_id\":\"%s\",\"text\":\"%s\\n%s\","
                 "\"parse_mode\":\"Markdown\"}",
                 u->param2, esc_title, esc_body);
        rc = http_post_json(url, json);
        break;

    case SCHEME_JSON:
        snprintf(json, sizeof(json),
                 "{\"title\":\"%s\",\"message\":\"%s\","
                 "\"source\":\"smolclaw\"}",
                 esc_title, esc_body);
        rc = http_post_json(u->param1, json);
        break;
    }

    free(esc_title);
    free(esc_body);
    return rc;
}

/* ---------- Tool implementation ----------------------------------------- */

typedef struct {
    char *notify_urls;   /* comma-separated URL string */
} notify_data_t;

static void notify_destroy(sc_tool_t *self)
{
    if (!self) return;
    notify_data_t *d = self->data;
    if (d) {
        free(d->notify_urls);
        free(d);
    }
    free(self);
}

static cJSON *notify_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "title",
                         "Short notification title (e.g. 'Task complete')", 1);
    sc_schema_add_string(schema, "body",
                         "Notification body with details", 1);
    return schema;
}

static sc_tool_result_t *notify_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    notify_data_t *d = self->data;
    if (!d || !d->notify_urls || !d->notify_urls[0])
        return sc_tool_result_error("no notification URLs configured");

    const char *title = sc_json_get_string(args, "title", NULL);
    const char *body  = sc_json_get_string(args, "body", NULL);
    if (!title || !body)
        return sc_tool_result_error("title and body are required");

    /* Parse and send to each URL */
    char *buf = sc_strdup(d->notify_urls);
    if (!buf) return sc_tool_result_error("out of memory");

    int sent = 0;
    int failed = 0;
    char *saveptr = NULL;
    char *tok = strtok_r(buf, ",", &saveptr);

    while (tok) {
        /* Trim whitespace */
        while (*tok == ' ') tok++;
        char *end = tok + strlen(tok) - 1;
        while (end > tok && *end == ' ') *end-- = '\0';

        if (*tok) {
            parsed_url_t u;
            if (parse_one_url(tok, &u) == 0) {
                if (send_one(&u, title, body) == 0)
                    sent++;
                else
                    failed++;
                parsed_url_free(&u);
            } else {
                sc_log(SC_LOG_WARN, TAG, "skipping invalid URL: %s", tok);
                failed++;
            }
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
    free(buf);

    char result_msg[256];
    if (failed > 0)
        snprintf(result_msg, sizeof(result_msg),
                 "Notification sent to %d endpoint(s), %d failed", sent, failed);
    else
        snprintf(result_msg, sizeof(result_msg),
                 "Notification sent to %d endpoint(s)", sent);

    return sc_tool_result_new(result_msg);
}

sc_tool_t *sc_tool_notify_new(const char *notify_urls)
{
    notify_data_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->notify_urls = sc_strdup(notify_urls);

    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) { free(d->notify_urls); free(d); return NULL; }

    t->name = "notify";
    t->description = "Send a notification to external services (Discord, Telegram, webhook). "
                     "Use this when you want to alert the user outside of the chat channel, "
                     "e.g. when a long task completes or something important happens.";
    t->parameters = notify_parameters;
    t->execute = notify_execute;
    t->destroy = notify_destroy;
    t->needs_confirm = 0;
    t->data = d;
    return t;
}
