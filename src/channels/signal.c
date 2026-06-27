/*
 * smolclaw - Signal channel (task 3.1)
 *
 * Talks JSON-RPC over HTTP to an EXTERNAL signal-cli daemon (or the
 * bbernhard/signal-cli-rest-api container). smolclaw does not implement the
 * Signal protocol or manage the Java daemon. Text-only DMs + groups, polling
 * receive. Pairing / allow_from / strict-mode security come from
 * channels/base.c. See docs/design/signal-channel.md.
 */

#include "channels/signal.h"
#include "channels/signal_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <curl/curl.h>

#include "cJSON.h"
#include "constants.h"
#include "logger.h"
#include "util/curl_common.h"
#include "util/str.h"

#define TAG "signal"

/* Local network tuning (kept self-contained to avoid touching shared headers). */
#define SIGNAL_RECONNECT_DELAY      5    /* initial backoff seconds */
#define SIGNAL_RECONNECT_MAX_DELAY  300  /* cap at 5 minutes */
#define SIGNAL_RECEIVE_TIMEOUT      5    /* daemon-side receive block (seconds) */
#define SIGNAL_POLL_INTERVAL        2    /* idle gap between receive calls */
#define SIGNAL_HTTP_TIMEOUT         (SIGNAL_RECEIVE_TIMEOUT + 25L)
#define SIGNAL_ID_MAX_LEN           512

/* ====================================================================== *
 *  Pure helpers (declared in signal_internal.h, unit-tested directly)    *
 * ====================================================================== */

int sc_signal_id_looks_valid(const char *s)
{
    if (!s || !s[0]) return 0;
    size_t n = 0;
    for (const char *p = s; *p; p++, n++) {
        if (n >= SIGNAL_ID_MAX_LEN) return 0;
        unsigned char c = (unsigned char)*p;
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') ||
                 c == '+' || c == '/' || c == '=' ||
                 c == '_' || c == '-' || c == ':' || c == '.';
        if (!ok) return 0;
    }
    return 1;
}

char *sc_signal_normalize_sender(const char *source, const char *source_uuid)
{
    /* Prefer the UUID form — it is stable across number changes. */
    if (source_uuid && source_uuid[0] && sc_signal_id_looks_valid(source_uuid)) {
        size_t len = strlen("uuid:") + strlen(source_uuid) + 1;
        char *out = malloc(len);
        if (out) snprintf(out, len, "uuid:%s", source_uuid);
        return out;
    }
    if (source && source[0] && sc_signal_id_looks_valid(source))
        return sc_strdup(source);
    return NULL;
}

char *sc_signal_normalize_group_chat_id(const char *group_id)
{
    if (!group_id || !group_id[0] || !sc_signal_id_looks_valid(group_id))
        return NULL;
    size_t len = strlen("signal:group:") + strlen(group_id) + 1;
    char *out = malloc(len);
    if (out) snprintf(out, len, "signal:group:%s", group_id);
    return out;
}

int sc_signal_group_should_handle(const char *content, const char *group_trigger)
{
    if (!group_trigger || !group_trigger[0]) return 1;
    if (!content) return 0;
    return strstr(content, group_trigger) != NULL;
}

const char *sc_signal_recipient_from_chat_id(const char *chat_id, int *is_group)
{
    if (is_group) *is_group = 0;
    if (!chat_id || !chat_id[0]) return NULL;

    static const char grp[] = "signal:group:";
    if (strncmp(chat_id, grp, sizeof(grp) - 1) == 0) {
        if (is_group) *is_group = 1;
        return chat_id + sizeof(grp) - 1;
    }
    if (strncmp(chat_id, "uuid:", 5) == 0)
        return chat_id + 5;
    return chat_id;
}

char *sc_signal_build_base_url(const char *http_url, const char *host, int port)
{
    if (http_url && http_url[0]) {
        char *out = sc_strdup(http_url);
        if (out) {
            size_t n = strlen(out);
            while (n > 0 && out[n - 1] == '/') out[--n] = '\0';
        }
        return out;
    }
    const char *h = (host && host[0]) ? host : "127.0.0.1";
    if (port <= 0) port = 7583;
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "http://%s:%d", h, port);
    return sc_strbuf_finish(&sb);
}

void sc_signal_inbound_free(sc_signal_inbound_t *in)
{
    if (!in) return;
    free(in->sender);
    free(in->chat_id);
    free(in->content);
    in->sender = in->chat_id = in->content = NULL;
    in->is_group = 0;
}

int sc_signal_envelope_extract(const cJSON *envelope, sc_signal_inbound_t *out)
{
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!envelope) return 0;

    /* Only data messages carry user text; ignore sync/receipt/typing. */
    const cJSON *data = cJSON_GetObjectItemCaseSensitive(envelope, "dataMessage");
    if (!data || !cJSON_IsObject(data)) return 0;

    const cJSON *msg = cJSON_GetObjectItemCaseSensitive(data, "message");
    if (!cJSON_IsString(msg) || !msg->valuestring || !msg->valuestring[0])
        return 0;  /* empty / attachment-only / reaction — text-only MVP */

    const cJSON *src  = cJSON_GetObjectItemCaseSensitive(envelope, "source");
    const cJSON *uuid = cJSON_GetObjectItemCaseSensitive(envelope, "sourceUuid");
    char *sender = sc_signal_normalize_sender(
        cJSON_IsString(src)  ? src->valuestring  : NULL,
        cJSON_IsString(uuid) ? uuid->valuestring : NULL);
    if (!sender) return 0;

    char *chat_id = NULL;
    int is_group = 0;
    const cJSON *ginfo = cJSON_GetObjectItemCaseSensitive(data, "groupInfo");
    const cJSON *gid = ginfo ? cJSON_GetObjectItemCaseSensitive(ginfo, "groupId")
                             : NULL;
    if (cJSON_IsString(gid) && gid->valuestring && gid->valuestring[0]) {
        chat_id = sc_signal_normalize_group_chat_id(gid->valuestring);
        is_group = 1;
        if (!chat_id) { free(sender); return 0; }  /* invalid group id */
    } else {
        chat_id = sc_strdup(sender);  /* DM: reply to the sender */
    }

    char *content = sc_strdup(msg->valuestring);
    if (!chat_id || !content) {
        free(sender); free(chat_id); free(content);
        return 0;
    }

    out->sender   = sender;
    out->chat_id  = chat_id;
    out->content  = content;
    out->is_group = is_group;
    return 1;
}

/* ====================================================================== *
 *  Channel runtime                                                       *
 * ====================================================================== */

typedef struct {
    char *account;
    char *base_url;        /* e.g. "http://127.0.0.1:7583" */
    char *rpc_url;         /* base_url + "/api/v1/rpc" */
    char *proxy;
    char *group_trigger;
    pthread_t poll_thread;
    int thread_started;
} signal_data_t;

/* CURL write callback (bounded). */
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

/* Issue one JSON-RPC call. Takes ownership of `params` (freed via the request
 * object). Returns the full parsed response (caller cJSON_Delete), or NULL on
 * transport/parse failure. */
static cJSON *signal_rpc(const signal_data_t *sd, const char *method, cJSON *params)
{
    cJSON *req = cJSON_CreateObject();
    if (!req) { cJSON_Delete(params); return NULL; }
    cJSON_AddStringToObject(req, "jsonrpc", "2.0");
    cJSON_AddStringToObject(req, "method", method);
    if (params) cJSON_AddItemToObject(req, "params", params);
    cJSON_AddStringToObject(req, "id", "1");

    char *body_str = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);
    if (!body_str) return NULL;

    CURL *curl = sc_curl_init();
    if (!curl) { free(body_str); return NULL; }

    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");

    sc_strbuf_t resp;
    sc_strbuf_init(&resp);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, sd->rpc_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, SIGNAL_HTTP_TIMEOUT);
    if (sd->proxy && sd->proxy[0])
        curl_easy_setopt(curl, CURLOPT_PROXY, sd->proxy);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(body_str);

    if (res != CURLE_OK) {
        SC_LOG_WARN(TAG, "JSON-RPC %s transport error: %s", method,
                    curl_easy_strerror(res));
        sc_strbuf_free(&resp);
        return NULL;
    }
    if (http_code < 200 || http_code >= 300) {
        SC_LOG_WARN(TAG, "JSON-RPC %s HTTP %ld", method, http_code);
        sc_strbuf_free(&resp);
        return NULL;
    }

    char *response = sc_strbuf_finish(&resp);
    cJSON *json = cJSON_Parse(response);
    free(response);
    if (!json) {
        SC_LOG_WARN(TAG, "JSON-RPC %s: malformed response", method);
        return NULL;
    }
    /* JSON-RPC error object => surface and fail. */
    cJSON *err = cJSON_GetObjectItemCaseSensitive(json, "error");
    if (err) {
        cJSON *errmsg = cJSON_GetObjectItemCaseSensitive(err, "message");
        SC_LOG_WARN(TAG, "JSON-RPC %s error: %s", method,
                    cJSON_IsString(errmsg) ? errmsg->valuestring : "(unknown)");
        cJSON_Delete(json);
        return NULL;
    }
    return json;
}

/* Dispatch one extracted message through the base channel (pairing/allow_from). */
static void handle_envelope(sc_channel_t *ch, const cJSON *envelope)
{
    signal_data_t *sd = ch->data;
    sc_signal_inbound_t in;
    if (!sc_signal_envelope_extract(envelope, &in))
        return;

    if (in.is_group &&
        !sc_signal_group_should_handle(in.content, sd->group_trigger)) {
        SC_LOG_DEBUG(TAG, "group message ignored (no trigger match)");
        sc_signal_inbound_free(&in);
        return;
    }

    SC_LOG_DEBUG(TAG, "received from %s in %s", in.sender, in.chat_id);
    sc_channel_handle_message(ch, in.sender, in.chat_id, in.content);
    sc_signal_inbound_free(&in);
}

/* Walk a `receive` result array. */
static void process_receive_result(sc_channel_t *ch, cJSON *resp)
{
    cJSON *result = cJSON_GetObjectItemCaseSensitive(resp, "result");
    if (!cJSON_IsArray(result)) return;

    cJSON *elem = NULL;
    cJSON_ArrayForEach(elem, result) {
        if (!ch->running) break;
        /* Each element wraps an "envelope"; tolerate either shape. */
        cJSON *env = cJSON_GetObjectItemCaseSensitive(elem, "envelope");
        handle_envelope(ch, env ? env : elem);
    }
}

static void *poll_thread(void *arg)
{
    sc_channel_t *ch = arg;
    signal_data_t *sd = ch->data;

    SC_LOG_INFO(TAG, "Polling thread started (account %s)", sd->account);

    int backoff = SIGNAL_RECONNECT_DELAY;

    while (ch->running) {
        cJSON *params = cJSON_CreateObject();
        if (params) {
            cJSON_AddStringToObject(params, "account", sd->account);
            cJSON_AddNumberToObject(params, "timeout", SIGNAL_RECEIVE_TIMEOUT);
        }
        cJSON *resp = signal_rpc(sd, "receive", params);

        if (!resp) {
            SC_LOG_WARN(TAG, "receive failed, retrying in %ds", backoff);
            sc_channel_sleep(&ch->running, backoff);
            if (backoff < SIGNAL_RECONNECT_MAX_DELAY) backoff *= 2;
            continue;
        }

        backoff = SIGNAL_RECONNECT_DELAY;  /* reset on success */
        process_receive_result(ch, resp);
        cJSON_Delete(resp);

        sc_channel_sleep(&ch->running, SIGNAL_POLL_INTERVAL);
    }

    SC_LOG_INFO(TAG, "Polling thread stopped");
    return NULL;
}

static int signal_start(sc_channel_t *self)
{
    signal_data_t *sd = self->data;
    self->running = 1;
    sd->thread_started = 1;

    if (pthread_create(&sd->poll_thread, NULL, poll_thread, self) != 0) {
        SC_LOG_ERROR(TAG, "Failed to create polling thread");
        self->running = 0;
        sd->thread_started = 0;
        return -1;
    }
    SC_LOG_INFO(TAG, "Signal channel started (polling)");
    return 0;
}

static int signal_stop(sc_channel_t *self)
{
    signal_data_t *sd = self->data;
    self->running = 0;
    if (sd->thread_started)
        pthread_join(sd->poll_thread, NULL);
    SC_LOG_INFO(TAG, "Signal channel stopped");
    return 0;
}

static int signal_send(sc_channel_t *self, sc_outbound_msg_t *msg)
{
    if (!self->running) return -1;
    signal_data_t *sd = self->data;
    if (!msg || !msg->chat_id || !msg->content) return -1;

    int is_group = 0;
    const char *recipient = sc_signal_recipient_from_chat_id(msg->chat_id, &is_group);
    if (!recipient || !recipient[0]) {
        SC_LOG_WARN(TAG, "send: empty recipient from chat_id");
        return -1;
    }

    cJSON *params = cJSON_CreateObject();
    if (!params) return -1;
    cJSON_AddStringToObject(params, "account", sd->account);
    cJSON_AddStringToObject(params, "message", msg->content);
    if (is_group) {
        cJSON_AddStringToObject(params, "groupId", recipient);
    } else {
        cJSON *rcpts = cJSON_CreateArray();
        if (rcpts) {
            cJSON_AddItemToArray(rcpts, cJSON_CreateString(recipient));
            cJSON_AddItemToObject(params, "recipient", rcpts);
        }
    }

    cJSON *resp = signal_rpc(sd, "send", params);
    if (!resp) return -1;
    cJSON_Delete(resp);
    return 0;
}

static int signal_is_running(sc_channel_t *self)
{
    return self ? self->running : 0;
}

static void signal_destroy(sc_channel_t *self)
{
    if (!self) return;
    signal_data_t *sd = self->data;
    if (sd) {
        free(sd->account);
        free(sd->base_url);
        free(sd->rpc_url);
        free(sd->proxy);
        free(sd->group_trigger);
        free(sd);
    }
    self->data = NULL;
    sc_channel_base_free(self);
}

sc_channel_t *sc_channel_signal_new(sc_signal_config_t *cfg, sc_bus_t *bus)
{
    if (!cfg || !cfg->account || !cfg->account[0]) return NULL;

    sc_channel_t *ch = calloc(1, sizeof(*ch));
    if (!ch) return NULL;

    signal_data_t *sd = calloc(1, sizeof(*sd));
    if (!sd) { free(ch); return NULL; }

    sd->account = sc_strdup(cfg->account);
    sd->base_url = sc_signal_build_base_url(cfg->http_url, cfg->http_host,
                                            cfg->http_port);
    sd->proxy = sc_strdup(cfg->proxy);
    sd->group_trigger = sc_strdup(cfg->group_trigger);

    if (!sd->account || !sd->base_url) {
        free(sd->account); free(sd->base_url); free(sd->proxy);
        free(sd->group_trigger); free(sd); free(ch);
        return NULL;
    }

    size_t rlen = strlen(sd->base_url) + strlen("/api/v1/rpc") + 1;
    sd->rpc_url = malloc(rlen);
    if (!sd->rpc_url) {
        free(sd->account); free(sd->base_url); free(sd->proxy);
        free(sd->group_trigger); free(sd); free(ch);
        return NULL;
    }
    snprintf(sd->rpc_url, rlen, "%s/api/v1/rpc", sd->base_url);

    ch->name = SC_CHANNEL_SIGNAL;
    ch->start = signal_start;
    ch->stop = signal_stop;
    ch->send = signal_send;
    ch->is_running = signal_is_running;
    ch->destroy = signal_destroy;
    ch->bus = bus;
    ch->running = 0;
    ch->data = sd;

    sc_channel_init_security(ch, cfg->dm_policy, cfg->allow_from,
                             cfg->allow_from_count, "signal");
    return ch;
}
