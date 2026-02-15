/*
 * smolclaw - Slack channel
 * Slack Bot via Socket Mode WSS (receive) and Web API (send).
 *
 * Socket Mode uses a persistent WSS connection to receive events.
 * Each event envelope must be acknowledged immediately.
 * Outbound messages are sent via the Web API (chat.postMessage).
 */

#include "channels/slack.h"
#include "sc_features.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <curl/curl.h>

#include "cJSON.h"
#include "constants.h"
#include "logger.h"
#include "pairing.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "util/websocket.h"

#define SLACK_TAG "slack"
#define SLACK_RECONNECT_DELAY 5
#define SLACK_RECONNECT_MAX_DELAY 300
#define SLACK_MAX_MSG_LEN 4000  /* Slack limits messages to ~4000 chars */

typedef struct {
    char *bot_token;
    char *app_token;
    sc_ws_t *ws;
    pthread_t ws_thread;
    int thread_started;
} slack_data_t;

/* CURL write callback */
static size_t write_cb(void *data, size_t size, size_t nmemb, void *userp)
{
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

/* POST to Slack Web API */
static cJSON *slack_api_post(const slack_data_t *sd, const char *method,
                              cJSON *payload)
{
    sc_strbuf_t url_buf;
    sc_strbuf_init(&url_buf);
    sc_strbuf_appendf(&url_buf, "https://slack.com/api/%s", method);
    char *url = sc_strbuf_finish(&url_buf);

    char *body = cJSON_PrintUnformatted(payload);

    CURL *curl = curl_easy_init();
    if (!curl) { free(url); free(body); return NULL; }

    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");

    sc_strbuf_t resp;
    sc_strbuf_init(&resp);

    sc_strbuf_t auth_buf;
    sc_strbuf_init(&auth_buf);
    sc_strbuf_appendf(&auth_buf, "Authorization: Bearer %s", sd->bot_token);
    char *auth = sc_strbuf_finish(&auth_buf);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth);
    headers = curl_slist_append(headers, "Content-Type: application/json; charset=utf-8");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(url);
    free(body);
    free(auth);

    if (res != CURLE_OK) {
        SC_LOG_ERROR(SLACK_TAG, "API call %s failed: %s", method,
                     curl_easy_strerror(res));
        sc_strbuf_free(&resp);
        return NULL;
    }

    char *resp_str = sc_strbuf_finish(&resp);
    cJSON *json = cJSON_Parse(resp_str);
    free(resp_str);
    return json;
}

/* Get Socket Mode WSS URL via apps.connections.open */
static char *slack_get_wss_url(const slack_data_t *sd)
{
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");

    sc_strbuf_t resp;
    sc_strbuf_init(&resp);

    sc_strbuf_t auth_buf;
    sc_strbuf_init(&auth_buf);
    sc_strbuf_appendf(&auth_buf, "Authorization: Bearer %s", sd->app_token);
    char *auth = sc_strbuf_finish(&auth_buf);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth);
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

    curl_easy_setopt(curl, CURLOPT_URL, "https://slack.com/api/apps.connections.open");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(auth);

    if (res != CURLE_OK) {
        sc_strbuf_free(&resp);
        return NULL;
    }

    char *resp_str = sc_strbuf_finish(&resp);
    cJSON *json = cJSON_Parse(resp_str);
    free(resp_str);

    if (!json) return NULL;

    int ok = sc_json_get_bool(json, "ok", 0);
    char *wss_url = NULL;
    if (ok) {
        const char *url = sc_json_get_string(json, "url", NULL);
        if (url) wss_url = sc_strdup(url);
    } else {
        const char *err = sc_json_get_string(json, "error", "unknown");
        SC_LOG_ERROR(SLACK_TAG, "apps.connections.open failed: %s", err);
    }

    cJSON_Delete(json);
    return wss_url;
}

/* Acknowledge a Socket Mode envelope */
static void slack_ack_envelope(sc_ws_t *ws, const char *envelope_id)
{
    if (!ws || !envelope_id) return;

    cJSON *ack = cJSON_CreateObject();
    cJSON_AddStringToObject(ack, "envelope_id", envelope_id);
    char *ack_str = cJSON_PrintUnformatted(ack);
    cJSON_Delete(ack);

    if (ack_str) {
        sc_ws_send_text(ws, ack_str, strlen(ack_str));
        free(ack_str);
    }
}

/* Handle a Socket Mode message */
static void slack_handle_ws_message(sc_channel_t *ch, const char *text)
{
    slack_data_t *sd = ch->data;
    cJSON *json = cJSON_Parse(text);
    if (!json) return;

    const char *envelope_id = sc_json_get_string(json, "envelope_id", NULL);
    const char *type = sc_json_get_string(json, "type", NULL);

    /* Always acknowledge envelopes immediately */
    if (envelope_id)
        slack_ack_envelope(sd->ws, envelope_id);

    if (!type) {
        cJSON_Delete(json);
        return;
    }

    if (strcmp(type, "hello") == 0) {
        SC_LOG_INFO(SLACK_TAG, "Socket Mode connection established");
    } else if (strcmp(type, "disconnect") == 0) {
        SC_LOG_WARN(SLACK_TAG, "Received disconnect, will reconnect");
        if (sd->ws) sc_ws_close(sd->ws);
    } else if (strcmp(type, "events_api") == 0) {
        /* Parse the inner event */
        const cJSON *payload = sc_json_get_object(json, "payload");
        const cJSON *event = payload ? sc_json_get_object(payload, "event") : NULL;

        if (event) {
            const char *event_type = sc_json_get_string(event, "type", NULL);

            if (event_type && strcmp(event_type, "message") == 0) {
                /* Ignore bot messages */
                const char *bot_id = sc_json_get_string(event, "bot_id", NULL);
                const char *subtype = sc_json_get_string(event, "subtype", NULL);

                if (bot_id || (subtype && strcmp(subtype, "bot_message") == 0)) {
                    cJSON_Delete(json);
                    return;
                }

                const char *user = sc_json_get_string(event, "user", NULL);
                const char *channel_id = sc_json_get_string(event, "channel", NULL);
                const char *msg_text = sc_json_get_string(event, "text", NULL);

                if (user && channel_id && msg_text && msg_text[0]) {
                    SC_LOG_DEBUG(SLACK_TAG, "Message from %s in %s: %.50s",
                                 user, channel_id, msg_text);
                    sc_channel_handle_message(ch, user, channel_id, msg_text);
                }
            }
        }
    }

    cJSON_Delete(json);
}

/* WebSocket receive thread */
static void *ws_thread_fn(void *arg)
{
    sc_channel_t *ch = arg;
    slack_data_t *sd = ch->data;
    int backoff = SLACK_RECONNECT_DELAY;

    while (ch->running) {
        /* Get fresh WSS URL via apps.connections.open */
        char *wss_url = slack_get_wss_url(sd);
        if (!wss_url) {
            SC_LOG_ERROR(SLACK_TAG, "Failed to get WSS URL, retry in %ds", backoff);
            for (int i = 0; i < backoff * 10 && ch->running; i++)
                usleep(100000);
            if (backoff < SLACK_RECONNECT_MAX_DELAY)
                backoff = backoff * 2 < SLACK_RECONNECT_MAX_DELAY ? backoff * 2
                                                                    : SLACK_RECONNECT_MAX_DELAY;
            continue;
        }

        SC_LOG_INFO(SLACK_TAG, "Connecting to Socket Mode");
        sd->ws = sc_ws_connect(wss_url);
        free(wss_url);

        if (!sd->ws) {
            SC_LOG_ERROR(SLACK_TAG, "WSS connect failed, retry in %ds", backoff);
            for (int i = 0; i < backoff * 10 && ch->running; i++)
                usleep(100000);
            if (backoff < SLACK_RECONNECT_MAX_DELAY)
                backoff = backoff * 2 < SLACK_RECONNECT_MAX_DELAY ? backoff * 2
                                                                    : SLACK_RECONNECT_MAX_DELAY;
            continue;
        }

        /* Reset backoff on successful connect */
        backoff = SLACK_RECONNECT_DELAY;

        /* Read loop */
        while (ch->running) {
            char *msg = sc_ws_recv(sd->ws);
            if (!msg) {
                SC_LOG_WARN(SLACK_TAG, "WSS read failed, reconnecting");
                break;
            }
            slack_handle_ws_message(ch, msg);
            free(msg);
        }

        sc_ws_close(sd->ws);
        sd->ws = NULL;

        if (ch->running) {
            SC_LOG_INFO(SLACK_TAG, "Reconnecting in %ds", SLACK_RECONNECT_DELAY);
            for (int i = 0; i < SLACK_RECONNECT_DELAY * 10 && ch->running; i++)
                usleep(100000);
        }
    }

    return NULL;
}

/* Channel vtable implementations */

static int slack_start(sc_channel_t *self)
{
    slack_data_t *sd = self->data;
    self->running = 1;
    sd->thread_started = 1;

    int ret = pthread_create(&sd->ws_thread, NULL, ws_thread_fn, self);
    if (ret != 0) {
        SC_LOG_ERROR(SLACK_TAG, "Failed to create WSS thread");
        self->running = 0;
        sd->thread_started = 0;
        return -1;
    }

    SC_LOG_INFO(SLACK_TAG, "Slack channel started (Socket Mode)");
    return 0;
}

static int slack_stop(sc_channel_t *self)
{
    self->running = 0;
    slack_data_t *sd = self->data;
    if (sd->ws) sc_ws_close(sd->ws);

    if (sd->thread_started)
        pthread_join(sd->ws_thread, NULL);

    SC_LOG_INFO(SLACK_TAG, "Slack channel stopped");
    return 0;
}

static int slack_send(sc_channel_t *self, sc_outbound_msg_t *msg)
{
    slack_data_t *sd = self->data;
    if (!msg || !msg->chat_id || !msg->content) return -1;

    /* Rate limiting */
    if (self->rate_limiter && !sc_rate_limiter_check(self->rate_limiter,
                                                      msg->chat_id)) {
        SC_LOG_WARN(SLACK_TAG, "Rate limited for %s", msg->chat_id);
        return -1;
    }

    /* Split long messages */
    const char *text = msg->content;
    size_t text_len = strlen(text);

    while (text_len > 0) {
        size_t chunk = text_len > SLACK_MAX_MSG_LEN ? SLACK_MAX_MSG_LEN : text_len;

        cJSON *payload = cJSON_CreateObject();
        cJSON_AddStringToObject(payload, "channel", msg->chat_id);

        /* Add chunk as string */
        char *chunk_str = malloc(chunk + 1);
        if (chunk_str) {
            memcpy(chunk_str, text, chunk);
            chunk_str[chunk] = '\0';
            cJSON_AddStringToObject(payload, "text", chunk_str);
            free(chunk_str);
        }

        cJSON *resp = slack_api_post(sd, "chat.postMessage", payload);
        cJSON_Delete(payload);

        if (resp) {
            int ok = sc_json_get_bool(resp, "ok", 0);
            if (!ok) {
                const char *err = sc_json_get_string(resp, "error", "unknown");
                SC_LOG_ERROR(SLACK_TAG, "chat.postMessage failed: %s", err);
            }
            cJSON_Delete(resp);
        }

        text += chunk;
        text_len -= chunk;
    }

    return 0;
}

static int slack_is_running(sc_channel_t *self)
{
    return self->running;
}

static void slack_destroy(sc_channel_t *self)
{
    if (!self) return;
    slack_data_t *sd = self->data;
    if (sd) {
        if (sd->ws) sc_ws_close(sd->ws);
        free(sd->bot_token);
        free(sd->app_token);
        free(sd);
    }
    self->data = NULL;
    sc_channel_base_free(self);
}

sc_channel_t *sc_channel_slack_new(sc_slack_config_t *cfg, sc_bus_t *bus)
{
    if (!cfg || !cfg->bot_token || !cfg->app_token) return NULL;

    sc_channel_t *ch = calloc(1, sizeof(*ch));
    if (!ch) return NULL;

    slack_data_t *sd = calloc(1, sizeof(*sd));
    if (!sd) { free(ch); return NULL; }

    sd->bot_token = sc_strdup(cfg->bot_token);
    sd->app_token = sc_strdup(cfg->app_token);
    sd->ws = NULL;
    sd->thread_started = 0;

    ch->name = SC_CHANNEL_SLACK;
    ch->start = slack_start;
    ch->stop = slack_stop;
    ch->send = slack_send;
    ch->send_typing = NULL;  /* Slack has no typing indicator API for bots */
    ch->is_running = slack_is_running;
    ch->destroy = slack_destroy;
    ch->bus = bus;
    ch->running = 0;
    ch->data = sd;

    /* Copy allow list */
    if (cfg->allow_from_count > 0 && cfg->allow_from) {
        ch->allow_list_count = cfg->allow_from_count;
        ch->allow_list = calloc((size_t)cfg->allow_from_count, sizeof(char *));
        for (int i = 0; i < cfg->allow_from_count; i++)
            ch->allow_list[i] = sc_strdup(cfg->allow_from[i]);
    }

    /* DM policy + pairing store */
    ch->dm_policy = sc_dm_policy_from_str(cfg->dm_policy);
    if (ch->dm_policy == SC_DM_POLICY_PAIRING) {
        char *dir = sc_expand_home("~/.smolclaw/pairing");
        ch->pairing_store = sc_pairing_store_new("slack", dir);
        free(dir);
    }

    return ch;
}
