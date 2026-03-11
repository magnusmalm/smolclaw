/*
 * smolclaw - Telegram channel
 * Telegram Bot API via libcurl. Long polling for updates, POST for sending.
 */

#include "channels/telegram.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <curl/curl.h>
#include "util/curl_common.h"

#include <unistd.h>

#include "cJSON.h"
#include "constants.h"
#include "logger.h"
#include "pairing.h"
#include "util/str.h"
#include "sc_features.h"
#if SC_ENABLE_VOICE
#include "voice/transcriber.h"
#endif

typedef struct {
    char *token;
    char *api_base;
    char *proxy;
    long offset;
    pthread_t poll_thread;
    int thread_started;
} telegram_data_t;

/* CURL write callback */
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

/* Build API URL */
static char *build_url(const telegram_data_t *td, const char *method)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/bot%s/%s", td->api_base, td->token, method);
    return sc_strbuf_finish(&sb);
}

/* Perform HTTP GET and return parsed JSON */
static cJSON *telegram_get(const telegram_data_t *td, const char *method,
                            const char *params)
{
    sc_strbuf_t url_buf;
    sc_strbuf_init(&url_buf);
    sc_strbuf_appendf(&url_buf, "%s/bot%s/%s", td->api_base, td->token, method);
    if (params && params[0]) {
        sc_strbuf_appendf(&url_buf, "?%s", params);
    }
    char *url = sc_strbuf_finish(&url_buf);

    CURL *curl = sc_curl_init();
    if (!curl) { free(url); return NULL; }

    sc_strbuf_t body;
    sc_strbuf_init(&body);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 35L);

    if (td->proxy && td->proxy[0]) {
        curl_easy_setopt(curl, CURLOPT_PROXY, td->proxy);
    }

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    free(url);

    if (res != CURLE_OK) {
        SC_LOG_ERROR("telegram", "HTTP GET failed: %s", curl_easy_strerror(res));
        sc_strbuf_free(&body);
        return NULL;
    }

    char *response = sc_strbuf_finish(&body);
    cJSON *json = cJSON_Parse(response);
    free(response);

    return json;
}

/* Perform HTTP POST with JSON body, return parsed JSON */
static cJSON *telegram_post(const telegram_data_t *td, const char *method,
                             cJSON *payload)
{
    char *url = build_url(td, method);
    char *body_str = cJSON_PrintUnformatted(payload);

    CURL *curl = sc_curl_init();
    if (!curl) { free(url); free(body_str); return NULL; }

    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");

    sc_strbuf_t resp;
    sc_strbuf_init(&resp);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    if (td->proxy && td->proxy[0]) {
        curl_easy_setopt(curl, CURLOPT_PROXY, td->proxy);
    }

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(url);
    free(body_str);

    if (res != CURLE_OK) {
        SC_LOG_ERROR("telegram", "HTTP POST failed: %s", curl_easy_strerror(res));
        sc_strbuf_free(&resp);
        return NULL;
    }

    char *response = sc_strbuf_finish(&resp);
    cJSON *json = cJSON_Parse(response);
    free(response);

    return json;
}

#if SC_ENABLE_VOICE
/* Download a Telegram file by file_id. Returns temp file path or NULL. */
static char *telegram_download_file(const telegram_data_t *td, const char *file_id)
{
    /* Call getFile to get the file path */
    sc_strbuf_t params;
    sc_strbuf_init(&params);
    sc_strbuf_appendf(&params, "file_id=%s", file_id);
    char *p = sc_strbuf_finish(&params);

    cJSON *resp = telegram_get(td, "getFile", p);
    free(p);
    if (!resp) return NULL;

    cJSON *ok = cJSON_GetObjectItem(resp, "ok");
    cJSON *result = cJSON_GetObjectItem(resp, "result");
    cJSON *file_path = result ? cJSON_GetObjectItem(result, "file_path") : NULL;

    if (!ok || !cJSON_IsTrue(ok) || !file_path || !cJSON_IsString(file_path)) {
        cJSON_Delete(resp);
        return NULL;
    }

    /* Build download URL */
    sc_strbuf_t url_buf;
    sc_strbuf_init(&url_buf);
    sc_strbuf_appendf(&url_buf, "%s/file/bot%s/%s",
                       td->api_base, td->token, file_path->valuestring);
    char *url = sc_strbuf_finish(&url_buf);
    cJSON_Delete(resp);

    /* Download to temp file */
    char *tmp_path = sc_download_to_temp(url, NULL);
    free(url);
    return tmp_path;
}
#endif

/* Send typing indicator */
static void send_typing(const telegram_data_t *td, const char *chat_id)
{
    cJSON *payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "chat_id", chat_id);
    cJSON_AddStringToObject(payload, "action", "typing");

    cJSON *resp = telegram_post(td, "sendChatAction", payload);
    cJSON_Delete(payload);
    cJSON_Delete(resp);
}

/* Typing indicator vtable wrapper */
static int telegram_send_typing(sc_channel_t *self, const char *chat_id)
{
    if (!self->running) return -1;
    send_typing(self->data, chat_id);
    return 0;
}

/* Process a single update */
static void process_update(sc_channel_t *ch, cJSON *update)
{
    telegram_data_t *td = ch->data;

    cJSON *update_id = cJSON_GetObjectItem(update, "update_id");
    if (update_id && cJSON_IsNumber(update_id)) {
        long uid = (long)update_id->valuedouble;
        if (uid >= td->offset) {
            td->offset = uid + 1;
        }
    }

    cJSON *message = cJSON_GetObjectItem(update, "message");
    if (!message) return;

    cJSON *from = cJSON_GetObjectItem(message, "from");
    if (!from) return;

    cJSON *text = cJSON_GetObjectItem(message, "text");
    cJSON *caption = cJSON_GetObjectItem(message, "caption");

    /* Extract content */
    sc_strbuf_t content_buf;
    sc_strbuf_init(&content_buf);

    if (text && cJSON_IsString(text)) {
        sc_strbuf_append(&content_buf, text->valuestring);
    }
    if (caption && cJSON_IsString(caption)) {
        if (content_buf.len > 0) sc_strbuf_append(&content_buf, "\n");
        sc_strbuf_append(&content_buf, caption->valuestring);
    }

    /* Handle voice messages */
    cJSON *voice = cJSON_GetObjectItem(message, "voice");
    if (voice) {
#if SC_ENABLE_VOICE
        cJSON *fid = cJSON_GetObjectItem(voice, "file_id");
        if (fid && cJSON_IsString(fid)) {
            if (ch->transcriber && sc_transcriber_is_available(ch->transcriber)) {
                char *tmp = telegram_download_file(td, fid->valuestring);
                if (tmp) {
                    char *transcript = sc_transcribe(ch->transcriber, tmp);
                    if (transcript) {
                        if (content_buf.len > 0)
                            sc_strbuf_append(&content_buf, "\n");
                        sc_strbuf_appendf(&content_buf,
                            "[voice transcription: %s]", transcript);
                        free(transcript);
                    } else {
                        sc_strbuf_append(&content_buf, "\n[voice (transcription failed)]");
                    }
                    remove(tmp);
                    free(tmp);
                } else {
                    sc_strbuf_append(&content_buf, "\n[voice (download failed)]");
                }
            } else {
                sc_strbuf_append(&content_buf, "\n[voice]");
            }
        }
#else
        sc_strbuf_append(&content_buf, "\n[voice]");
#endif
    }

    char *content = sc_strbuf_finish(&content_buf);
    if (!content || content[0] == '\0') {
        free(content);
        content = sc_strdup("[empty message]");
    }

    /* Extract sender ID */
    cJSON *user_id = cJSON_GetObjectItem(from, "id");
    if (!user_id || !cJSON_IsNumber(user_id)) {
        free(content);
        return;
    }
    cJSON *username = cJSON_GetObjectItem(from, "username");

    char sender_id[256];
    if (username && cJSON_IsString(username)) {
        snprintf(sender_id, sizeof(sender_id), "%.0f|%s",
                 user_id->valuedouble, username->valuestring);
    } else {
        snprintf(sender_id, sizeof(sender_id), "%.0f", user_id->valuedouble);
    }

    /* Extract chat ID */
    cJSON *chat = cJSON_GetObjectItem(message, "chat");
    cJSON *chat_id_json = chat ? cJSON_GetObjectItem(chat, "id") : NULL;

    char chat_id_str[64];
    if (chat_id_json && cJSON_IsNumber(chat_id_json)) {
        snprintf(chat_id_str, sizeof(chat_id_str), "%.0f", chat_id_json->valuedouble);
    } else {
        snprintf(chat_id_str, sizeof(chat_id_str), "0");
    }

    SC_LOG_DEBUG("telegram", "Received message from %s in chat %s",
                 sender_id, chat_id_str);

    /* Send typing indicator */
    send_typing(td, chat_id_str);

    /* Handle via base channel */
    sc_channel_handle_message(ch, sender_id, chat_id_str, content);
    free(content);
}

/* Polling thread */
static void *poll_thread(void *arg)
{
    sc_channel_t *ch = arg;
    telegram_data_t *td = ch->data;

    SC_LOG_INFO("telegram", "Polling thread started");

    int backoff = SC_TELEGRAM_RECONNECT_DELAY;

    while (ch->running) {
        char params[128];
        snprintf(params, sizeof(params), "timeout=30&offset=%ld", td->offset);

        cJSON *resp = telegram_get(td, "getUpdates", params);
        if (!resp) {
            SC_LOG_WARN("telegram", "getUpdates failed, retrying in %ds...", backoff);
            sc_channel_sleep(&ch->running, backoff);
            if (backoff < SC_TELEGRAM_RECONNECT_MAX_DELAY)
                backoff *= 2;
            continue;
        }

        /* Reset backoff on successful response */
        backoff = SC_TELEGRAM_RECONNECT_DELAY;

        cJSON *ok = cJSON_GetObjectItem(resp, "ok");
        cJSON *result = cJSON_GetObjectItem(resp, "result");

        if (ok && cJSON_IsTrue(ok) && result && cJSON_IsArray(result)) {
            cJSON *update = NULL;
            cJSON_ArrayForEach(update, result) {
                if (ch->running) {
                    process_update(ch, update);
                }
            }
        }

        cJSON_Delete(resp);
    }

    SC_LOG_INFO("telegram", "Polling thread stopped");
    return NULL;
}

static int telegram_start(sc_channel_t *self)
{
    telegram_data_t *td = self->data;

    self->running = 1;
    td->thread_started = 1;

    int ret = pthread_create(&td->poll_thread, NULL, poll_thread, self);
    if (ret != 0) {
        SC_LOG_ERROR("telegram", "Failed to create polling thread");
        self->running = 0;
        td->thread_started = 0;
        return -1;
    }

    SC_LOG_INFO("telegram", "Telegram channel started (long polling)");
    return 0;
}

static int telegram_stop(sc_channel_t *self)
{
    telegram_data_t *td = self->data;
    self->running = 0;

    if (td->thread_started)
        pthread_join(td->poll_thread, NULL);

    SC_LOG_INFO("telegram", "Telegram channel stopped");
    return 0;
}

static int telegram_send(sc_channel_t *self, sc_outbound_msg_t *msg)
{
    if (!self->running) return -1;
    telegram_data_t *td = self->data;

    cJSON *payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "chat_id", msg->chat_id);
    cJSON_AddStringToObject(payload, "text", msg->content);
    cJSON_AddStringToObject(payload, "parse_mode", "HTML");

    cJSON *resp = telegram_post(td, "sendMessage", payload);
    cJSON_Delete(payload);

    if (!resp) {
        /* Retry without parse mode */
        payload = cJSON_CreateObject();
        cJSON_AddStringToObject(payload, "chat_id", msg->chat_id);
        cJSON_AddStringToObject(payload, "text", msg->content);
        resp = telegram_post(td, "sendMessage", payload);
        cJSON_Delete(payload);
    }

    int success = 0;
    if (resp) {
        cJSON *ok = cJSON_GetObjectItem(resp, "ok");
        success = (ok && cJSON_IsTrue(ok));
        if (!success) {
            SC_LOG_ERROR("telegram", "sendMessage failed");
        }
        cJSON_Delete(resp);
    }

    return success ? 0 : -1;
}

static int telegram_is_running(sc_channel_t *self)
{
    return self ? self->running : 0;
}

static void telegram_destroy(sc_channel_t *self)
{
    if (!self) return;
    telegram_data_t *td = self->data;
    if (td) {
        free(td->token);
        free(td->api_base);
        free(td->proxy);
        free(td);
    }
    self->data = NULL;
    sc_channel_base_free(self);
}

sc_channel_t *sc_channel_telegram_new(sc_telegram_config_t *cfg, sc_bus_t *bus)
{
    if (!cfg || !cfg->token) return NULL;

    sc_channel_t *ch = calloc(1, sizeof(*ch));
    if (!ch) return NULL;

    telegram_data_t *td = calloc(1, sizeof(*td));
    if (!td) { free(ch); return NULL; }

    td->token = sc_strdup(cfg->token);
    td->api_base = sc_strdup(cfg->api_base && cfg->api_base[0]
                             ? cfg->api_base : "https://api.telegram.org");
    td->proxy = sc_strdup(cfg->proxy);
    td->offset = 0;
    td->thread_started = 0;

    ch->name = SC_CHANNEL_TELEGRAM;
    ch->start = telegram_start;
    ch->stop = telegram_stop;
    ch->send = telegram_send;
    ch->send_typing = telegram_send_typing;
    ch->is_running = telegram_is_running;
    ch->destroy = telegram_destroy;
    ch->bus = bus;
    ch->running = 0;
    ch->data = td;

    sc_channel_init_security(ch, cfg->dm_policy, cfg->allow_from,
                              cfg->allow_from_count, "telegram");

    return ch;
}
