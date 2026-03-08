/*
 * smolclaw - Discord channel
 * Discord Bot API via Gateway WebSocket (receive) and REST API (send).
 */

#include "channels/discord.h"
#include "sc_features.h"
#if SC_ENABLE_VOICE
#include "voice/transcriber.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <curl/curl.h>
#include "util/curl_common.h"

#include "cJSON.h"
#include "constants.h"
#include "logger.h"
#include "pairing.h"
#include "util/str.h"
#include "util/websocket.h"

#define DISCORD_TAG "discord"
#define DISCORD_MAX_MSG_LEN 2000

/* Gateway intents: GUILD_MESSAGES (1<<9) | DIRECT_MESSAGES (1<<12) | MESSAGE_CONTENT (1<<15) */
#define DISCORD_INTENTS ((1 << 9) | (1 << 12) | (1 << 15))

/* Gateway opcodes */
#define GW_DISPATCH         0
#define GW_HEARTBEAT        1
#define GW_IDENTIFY         2
#define GW_RESUME           6
#define GW_RECONNECT        7
#define GW_INVALID_SESSION   9
#define GW_HELLO            10
#define GW_HEARTBEAT_ACK    11

typedef struct {
    char *token;
    char *api_base;
    char *bot_user_id;      /* Our bot's user ID (from READY) */
    sc_ws_t *ws;
    pthread_t gateway_thread;
    pthread_t heartbeat_thread;
    int thread_started;
    int heartbeat_started;
    int heartbeat_interval_ms;
    atomic_int sequence;             /* Last sequence number (-1 = none) */
    atomic_int heartbeat_acked;      /* Whether last heartbeat was ACKed */
} discord_data_t;

/* Validate that a string contains only digits (Discord snowflake ID) */
static int is_numeric_id(const char *s)
{
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9') return 0;
    return 1;
}

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

/* Perform Discord REST API POST */
static cJSON *discord_post(const discord_data_t *dd, const char *endpoint,
                            cJSON *payload)
{
    sc_strbuf_t url_buf;
    sc_strbuf_init(&url_buf);
    sc_strbuf_appendf(&url_buf, "%s%s", dd->api_base, endpoint);
    char *url = sc_strbuf_finish(&url_buf);

    char *body_str = cJSON_PrintUnformatted(payload);

    CURL *curl = sc_curl_init();
    if (!curl) { free(url); free(body_str); return NULL; }

    sc_strbuf_t resp;
    sc_strbuf_init(&resp);

    sc_strbuf_t auth_buf;
    sc_strbuf_init(&auth_buf);
    sc_strbuf_appendf(&auth_buf, "Authorization: Bot %s", dd->token);
    char *auth_header = sc_strbuf_finish(&auth_buf);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth_header);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(url);
    free(body_str);
    free(auth_header);

    if (res != CURLE_OK) {
        SC_LOG_ERROR(DISCORD_TAG, "HTTP POST failed: %s", curl_easy_strerror(res));
        sc_strbuf_free(&resp);
        return NULL;
    }

    char *response = sc_strbuf_finish(&resp);
    cJSON *json = cJSON_Parse(response);
    free(response);
    return json;
}

/* Send typing indicator */
static void discord_send_typing(const discord_data_t *dd, const char *channel_id)
{
    if (!is_numeric_id(channel_id)) return;

    sc_strbuf_t ep;
    sc_strbuf_init(&ep);
    sc_strbuf_appendf(&ep, "/channels/%s/typing", channel_id);
    char *endpoint = sc_strbuf_finish(&ep);

    /* Typing endpoint expects empty POST */
    cJSON *empty = cJSON_CreateObject();
    cJSON *resp = discord_post(dd, endpoint, empty);
    cJSON_Delete(empty);
    cJSON_Delete(resp);
    free(endpoint);
}

/* Typing indicator vtable wrapper */
static int discord_send_typing_vtable(sc_channel_t *self, const char *chat_id)
{
    if (!self->running) return -1;
    discord_send_typing(self->data, chat_id);
    return 0;
}

/* Send a gateway payload */
static int gw_send(sc_ws_t *ws, int opcode, cJSON *data)
{
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddNumberToObject(msg, "op", opcode);
    if (data) {
        cJSON_AddItemToObject(msg, "d", cJSON_Duplicate(data, 1));
    } else {
        cJSON_AddNullToObject(msg, "d");
    }

    char *text = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);

    int ret = sc_ws_send_text(ws, text, strlen(text));
    free(text);
    return ret;
}

/* Send IDENTIFY */
static int gw_identify(sc_ws_t *ws, const char *token)
{
    cJSON *d = cJSON_CreateObject();
    cJSON_AddStringToObject(d, "token", token);
    cJSON_AddNumberToObject(d, "intents", DISCORD_INTENTS);

    cJSON *props = cJSON_CreateObject();
    cJSON_AddStringToObject(props, "os", "linux");
    cJSON_AddStringToObject(props, "browser", "smolclaw");
    cJSON_AddStringToObject(props, "device", "smolclaw");
    cJSON_AddItemToObject(d, "properties", props);

    int ret = gw_send(ws, GW_IDENTIFY, d);
    cJSON_Delete(d);
    return ret;
}

/* Send heartbeat */
static int gw_heartbeat(sc_ws_t *ws, int sequence)
{
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddNumberToObject(msg, "op", GW_HEARTBEAT);
    if (sequence >= 0) {
        cJSON_AddNumberToObject(msg, "d", sequence);
    } else {
        cJSON_AddNullToObject(msg, "d");
    }

    char *text = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);

    int ret = sc_ws_send_text(ws, text, strlen(text));
    free(text);
    return ret;
}

/* Heartbeat thread */
static void *heartbeat_thread(void *arg)
{
    sc_channel_t *ch = arg;
    discord_data_t *dd = ch->data;

    SC_LOG_DEBUG(DISCORD_TAG, "Heartbeat thread started (interval=%dms)",
                 dd->heartbeat_interval_ms);

    while (ch->running && sc_ws_is_connected(dd->ws)) {
        /* Sleep for heartbeat interval (in 100ms increments to check running flag) */
        int remaining = dd->heartbeat_interval_ms;
        while (remaining > 0 && ch->running) {
            int sleep_ms = remaining > 100 ? 100 : remaining;
            usleep((unsigned int)sleep_ms * 1000);
            remaining -= sleep_ms;
        }

        if (!ch->running || !sc_ws_is_connected(dd->ws)) break;

        if (!atomic_exchange(&dd->heartbeat_acked, 0)) {
            SC_LOG_WARN(DISCORD_TAG, "Heartbeat ACK not received, connection may be dead");
        }
        if (gw_heartbeat(dd->ws, dd->sequence) != 0) {
            SC_LOG_ERROR(DISCORD_TAG, "Failed to send heartbeat");
            break;
        }
        SC_LOG_DEBUG(DISCORD_TAG, "Sent heartbeat (seq=%d)", dd->sequence);
    }

    SC_LOG_DEBUG(DISCORD_TAG, "Heartbeat thread stopped");
    return NULL;
}

/* Check if a message should be ignored (own bot, other bots).
 * Returns the author cJSON node for further use, or NULL to ignore. */
static cJSON *should_process_message(cJSON *d, const discord_data_t *dd)
{
    cJSON *author = cJSON_GetObjectItem(d, "author");
    if (!author) return NULL;

    cJSON *author_id = cJSON_GetObjectItem(author, "id");
    if (author_id && cJSON_IsString(author_id) && dd->bot_user_id &&
        strcmp(author_id->valuestring, dd->bot_user_id) == 0)
        return NULL;

    cJSON *is_bot = cJSON_GetObjectItem(author, "bot");
    if (is_bot && cJSON_IsTrue(is_bot)) return NULL;

    return author;
}

/* Process audio attachments: transcribe or append filename */
static void process_audio_attachments(sc_strbuf_t *content_buf,
                                       cJSON *attachments,
                                       sc_channel_t *ch)
{
    if (!attachments || !cJSON_IsArray(attachments)) return;

    cJSON *att = NULL;
    cJSON_ArrayForEach(att, attachments) {
        cJSON *ct = cJSON_GetObjectItem(att, "content_type");
        cJSON *fname = cJSON_GetObjectItem(att, "filename");
        const char *ct_str = (ct && cJSON_IsString(ct)) ? ct->valuestring : "";
        const char *fn_str = (fname && cJSON_IsString(fname)) ? fname->valuestring : "";

        /* Check if audio by content_type or extension */
        int is_audio = (strncmp(ct_str, "audio/", 6) == 0 ||
                       strcmp(ct_str, "application/ogg") == 0);
        if (!is_audio) {
            const char *dot = strrchr(fn_str, '.');
            if (dot && (strcmp(dot, ".mp3") == 0 || strcmp(dot, ".wav") == 0 ||
                       strcmp(dot, ".ogg") == 0 || strcmp(dot, ".m4a") == 0 ||
                       strcmp(dot, ".flac") == 0 || strcmp(dot, ".aac") == 0 ||
                       strcmp(dot, ".opus") == 0)) {
                is_audio = 1;
            }
        }

        if (!is_audio) continue;

        cJSON *att_url = cJSON_GetObjectItem(att, "url");
        if (!att_url || !cJSON_IsString(att_url)) continue;

#if SC_ENABLE_VOICE
        if (ch->transcriber && sc_transcriber_is_available(ch->transcriber)) {
            char *tmp = sc_download_to_temp(att_url->valuestring, NULL);
            if (tmp) {
                char *transcript = sc_transcribe(ch->transcriber, tmp);
                if (transcript) {
                    if (content_buf->len > 0)
                        sc_strbuf_append(content_buf, "\n");
                    sc_strbuf_appendf(content_buf,
                        "[audio transcription: %s]", transcript);
                    free(transcript);
                } else {
                    if (content_buf->len > 0)
                        sc_strbuf_append(content_buf, "\n");
                    sc_strbuf_appendf(content_buf,
                        "[audio: %s (transcription failed)]", fn_str);
                }
                remove(tmp);
                free(tmp);
            }
        } else
#endif
        {
            (void)ch;
            if (content_buf->len > 0)
                sc_strbuf_append(content_buf, "\n");
            sc_strbuf_appendf(content_buf, "[audio: %s]", fn_str);
        }
    }
}

/* Process a MESSAGE_CREATE dispatch event */
static void process_message_create(sc_channel_t *ch, cJSON *d)
{
    discord_data_t *dd = ch->data;

    cJSON *author = should_process_message(d, dd);
    if (!author) return;

    /* Extract text content */
    sc_strbuf_t content_buf;
    sc_strbuf_init(&content_buf);

    cJSON *content = cJSON_GetObjectItem(d, "content");
    if (content && cJSON_IsString(content) && content->valuestring[0] != '\0') {
        sc_strbuf_append(&content_buf, content->valuestring);
    }

    /* Handle audio attachments */
    process_audio_attachments(&content_buf,
                               cJSON_GetObjectItem(d, "attachments"), ch);

    char *msg_content = sc_strbuf_finish(&content_buf);
    if (!msg_content || msg_content[0] == '\0') {
        free(msg_content);
        msg_content = sc_strdup("[empty message]");
    }

    /* Extract sender ID: "user_id|username" */
    cJSON *author_id = cJSON_GetObjectItem(author, "id");
    cJSON *username = cJSON_GetObjectItem(author, "username");
    char sender_id[256];
    if (username && cJSON_IsString(username)) {
        snprintf(sender_id, sizeof(sender_id), "%s|%s",
                 author_id->valuestring, username->valuestring);
    } else {
        snprintf(sender_id, sizeof(sender_id), "%s", author_id->valuestring);
    }

    /* Extract channel ID */
    cJSON *channel_id = cJSON_GetObjectItem(d, "channel_id");
    const char *chat_id = (channel_id && cJSON_IsString(channel_id))
                          ? channel_id->valuestring : "0";

    SC_LOG_DEBUG(DISCORD_TAG, "Message from %s in channel %s: %.80s",
                 sender_id, chat_id, msg_content);

    discord_send_typing(dd, chat_id);
    sc_channel_handle_message(ch, sender_id, chat_id, msg_content);
    free(msg_content);
}

/* Get Gateway URL from Discord REST API */
static char *get_gateway_url(const discord_data_t *dd)
{
    sc_strbuf_t url_buf;
    sc_strbuf_init(&url_buf);
    sc_strbuf_appendf(&url_buf, "%s/gateway/bot", dd->api_base);
    char *url = sc_strbuf_finish(&url_buf);

    CURL *curl = sc_curl_init();
    if (!curl) { free(url); return NULL; }

    sc_strbuf_t resp;
    sc_strbuf_init(&resp);

    sc_strbuf_t auth_buf;
    sc_strbuf_init(&auth_buf);
    sc_strbuf_appendf(&auth_buf, "Authorization: Bot %s", dd->token);
    char *auth_header = sc_strbuf_finish(&auth_buf);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(url);
    free(auth_header);

    if (res != CURLE_OK) {
        SC_LOG_ERROR(DISCORD_TAG, "Failed to get gateway URL: %s", curl_easy_strerror(res));
        sc_strbuf_free(&resp);
        return NULL;
    }

    char *response = sc_strbuf_finish(&resp);
    cJSON *json = cJSON_Parse(response);
    free(response);

    if (!json) return NULL;

    const char *gw_url = NULL;
    cJSON *url_field = cJSON_GetObjectItem(json, "url");
    if (url_field && cJSON_IsString(url_field)) {
        gw_url = url_field->valuestring;
    }

    char *result = NULL;
    if (gw_url) {
        /* Append query params for v10 + JSON encoding */
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "%s/?v=10&encoding=json", gw_url);
        result = sc_strbuf_finish(&sb);
    }

    cJSON_Delete(json);
    return result;
}

/* Handle a DISPATCH event (opcode 0) */
static void handle_dispatch_event(sc_channel_t *ch, discord_data_t *dd,
                                   cJSON *d, const char *event_name)
{
    if (strcmp(event_name, "READY") == 0) {
        cJSON *user = d ? cJSON_GetObjectItem(d, "user") : NULL;
        cJSON *id = user ? cJSON_GetObjectItem(user, "id") : NULL;
        if (id && cJSON_IsString(id)) {
            free(dd->bot_user_id);
            dd->bot_user_id = sc_strdup(id->valuestring);
            SC_LOG_INFO(DISCORD_TAG, "Bot ready (user_id=%s)", dd->bot_user_id);
        }
    } else if (strcmp(event_name, "MESSAGE_CREATE") == 0 && d) {
        process_message_create(ch, d);
    }
}

/*
 * Process a single gateway opcode.
 * Returns: 0 = continue, 1 = reconnect (ws closed).
 */
static int process_gateway_opcode(sc_channel_t *ch, discord_data_t *dd,
                                   int opcode, cJSON *d, cJSON *msg)
{
    switch (opcode) {
    case GW_HELLO: {
        cJSON *interval = d ? cJSON_GetObjectItem(d, "heartbeat_interval") : NULL;
        dd->heartbeat_interval_ms = (interval && cJSON_IsNumber(interval))
                                    ? interval->valueint : 41250;
        dd->heartbeat_acked = 1;
        dd->sequence = -1;

        SC_LOG_INFO(DISCORD_TAG, "Received HELLO (heartbeat_interval=%dms)",
                    dd->heartbeat_interval_ms);

        dd->heartbeat_started = 0;
        if (pthread_create(&dd->heartbeat_thread, NULL, heartbeat_thread, ch) == 0) {
            dd->heartbeat_started = 1;
        }

        gw_identify(dd->ws, dd->token);
        break;
    }

    case GW_HEARTBEAT_ACK:
        dd->heartbeat_acked = 1;
        SC_LOG_DEBUG(DISCORD_TAG, "Heartbeat ACKed");
        break;

    case GW_HEARTBEAT:
        gw_heartbeat(dd->ws, dd->sequence);
        break;

    case GW_RECONNECT:
        SC_LOG_INFO(DISCORD_TAG, "Server requested reconnect");
        sc_ws_close(dd->ws);
        dd->ws = NULL;
        return 1;

    case GW_INVALID_SESSION:
        SC_LOG_WARN(DISCORD_TAG, "Invalid session, will re-identify");
        sleep(3);
        sc_ws_close(dd->ws);
        dd->ws = NULL;
        return 1;

    case GW_DISPATCH: {
        cJSON *t = cJSON_GetObjectItem(msg, "t");
        const char *event = (t && cJSON_IsString(t)) ? t->valuestring : "";
        handle_dispatch_event(ch, dd, d, event);
        break;
    }

    default:
        SC_LOG_DEBUG(DISCORD_TAG, "Unhandled gateway opcode %d", opcode);
        break;
    }

    return 0;
}

/* Gateway thread - connects and processes events */
static void *gateway_thread(void *arg)
{
    sc_channel_t *ch = arg;
    discord_data_t *dd = ch->data;

    SC_LOG_INFO(DISCORD_TAG, "Gateway thread started");

    while (ch->running) {
        char *gw_url = get_gateway_url(dd);
        if (!gw_url) {
            SC_LOG_ERROR(DISCORD_TAG, "Failed to get gateway URL, retrying in 5s");
            sc_channel_sleep(&ch->running, 5);
            continue;
        }

        SC_LOG_INFO(DISCORD_TAG, "Connecting to gateway: %s", gw_url);
        dd->ws = sc_ws_connect(gw_url);
        free(gw_url);

        if (!dd->ws) {
            SC_LOG_ERROR(DISCORD_TAG, "WebSocket connect failed, retrying in 5s");
            sc_channel_sleep(&ch->running, 5);
            continue;
        }

        /* Event loop */
        while (ch->running && sc_ws_is_connected(dd->ws)) {
            char *frame = sc_ws_recv(dd->ws);
            if (!frame) break;

            cJSON *msg = cJSON_Parse(frame);
            free(frame);
            if (!msg) continue;

            cJSON *op = cJSON_GetObjectItem(msg, "op");
            int opcode = (op && cJSON_IsNumber(op)) ? op->valueint : -1;
            cJSON *d = cJSON_GetObjectItem(msg, "d");

            cJSON *s = cJSON_GetObjectItem(msg, "s");
            if (s && cJSON_IsNumber(s)) {
                dd->sequence = s->valueint;
            }

            process_gateway_opcode(ch, dd, opcode, d, msg);
            cJSON_Delete(msg);
        }

        if (dd->ws) {
            sc_ws_close(dd->ws);
            dd->ws = NULL;
        }

        /* Join heartbeat thread from this WSocket session */
        if (dd->heartbeat_started) {
            pthread_join(dd->heartbeat_thread, NULL);
            dd->heartbeat_started = 0;
        }

        if (ch->running) {
            SC_LOG_INFO(DISCORD_TAG, "Disconnected from gateway, reconnecting in 5s");
            sc_channel_sleep(&ch->running, 5);
        }
    }

    SC_LOG_INFO(DISCORD_TAG, "Gateway thread stopped");
    return NULL;
}

static int discord_start(sc_channel_t *self)
{
    discord_data_t *dd = self->data;

    self->running = 1;
    dd->thread_started = 1;

    int ret = pthread_create(&dd->gateway_thread, NULL, gateway_thread, self);
    if (ret != 0) {
        SC_LOG_ERROR(DISCORD_TAG, "Failed to create gateway thread");
        self->running = 0;
        dd->thread_started = 0;
        return -1;
    }

    SC_LOG_INFO(DISCORD_TAG, "Discord channel started (Gateway WebSocket)");
    return 0;
}

static int discord_stop(sc_channel_t *self)
{
    discord_data_t *dd = self->data;
    self->running = 0;

    /* Close WebSocket to unblock the gateway thread, but keep the pointer
     * alive until after join — other threads may still dereference dd->ws. */
    if (dd->ws)
        sc_ws_close(dd->ws);

    if (dd->thread_started)
        pthread_join(dd->gateway_thread, NULL);

    /* Safe to NULL now — all threads have exited */
    dd->ws = NULL;

    SC_LOG_INFO(DISCORD_TAG, "Discord channel stopped");
    return 0;
}

/* Find the largest chunk size <= max that doesn't split a UTF-8 character */
static size_t utf8_safe_chunk(const char *text, size_t len, size_t max)
{
    if (len <= max) return len;
    size_t pos = max;
    /* Walk back past continuation bytes (10xxxxxx) */
    while (pos > 0 && ((unsigned char)text[pos] & 0xC0) == 0x80)
        pos--;
    return pos > 0 ? pos : max;
}

static int discord_send(sc_channel_t *self, sc_outbound_msg_t *msg)
{
    if (!self->running) return -1;
    if (!is_numeric_id(msg->chat_id)) {
        SC_LOG_ERROR(DISCORD_TAG, "Invalid channel ID: %s", msg->chat_id);
        return -1;
    }
    discord_data_t *dd = self->data;

    const char *text = msg->content;
    size_t text_len = strlen(text);
    int success = 1;

    while (text_len > 0) {
        size_t chunk = utf8_safe_chunk(text, text_len, DISCORD_MAX_MSG_LEN);

        sc_strbuf_t ep;
        sc_strbuf_init(&ep);
        sc_strbuf_appendf(&ep, "/channels/%s/messages", msg->chat_id);
        char *endpoint = sc_strbuf_finish(&ep);

        char *chunk_str = malloc(chunk + 1);
        if (!chunk_str) { free(endpoint); return -1; }
        memcpy(chunk_str, text, chunk);
        chunk_str[chunk] = '\0';

        cJSON *payload = cJSON_CreateObject();
        cJSON_AddStringToObject(payload, "content", chunk_str);
        free(chunk_str);

        cJSON *resp = discord_post(dd, endpoint, payload);
        cJSON_Delete(payload);
        free(endpoint);

        if (resp) {
            cJSON *id = cJSON_GetObjectItem(resp, "id");
            if (!id || !cJSON_IsString(id)) {
                cJSON *err_msg = cJSON_GetObjectItem(resp, "message");
                SC_LOG_ERROR(DISCORD_TAG, "sendMessage failed: %s",
                             (err_msg && cJSON_IsString(err_msg))
                             ? err_msg->valuestring : "unknown error");
                success = 0;
            }
            cJSON_Delete(resp);
        } else {
            success = 0;
        }

        text += chunk;
        text_len -= chunk;
    }

    return success ? 0 : -1;
}

static int discord_is_running(sc_channel_t *self)
{
    return self ? self->running : 0;
}

static void discord_destroy(sc_channel_t *self)
{
    if (!self) return;
    discord_data_t *dd = self->data;
    if (dd) {
        if (dd->ws) {
            sc_ws_close(dd->ws);
        }
        free(dd->token);
        free(dd->api_base);
        free(dd->bot_user_id);
        free(dd);
    }
    self->data = NULL;
    sc_channel_base_free(self);
}

sc_channel_t *sc_channel_discord_new(sc_discord_config_t *cfg, sc_bus_t *bus)
{
    if (!cfg || !cfg->token) return NULL;

    sc_channel_t *ch = calloc(1, sizeof(*ch));
    if (!ch) return NULL;

    discord_data_t *dd = calloc(1, sizeof(*dd));
    if (!dd) { free(ch); return NULL; }

    dd->token = sc_strdup(cfg->token);
    dd->api_base = sc_strdup(cfg->api_base && cfg->api_base[0]
                             ? cfg->api_base : "https://discord.com/api/v10");
    dd->bot_user_id = NULL;
    dd->ws = NULL;
    dd->thread_started = 0;
    dd->sequence = -1;
    dd->heartbeat_acked = 1;

    ch->name = SC_CHANNEL_DISCORD;
    ch->start = discord_start;
    ch->stop = discord_stop;
    ch->send = discord_send;
    ch->send_typing = discord_send_typing_vtable;
    ch->is_running = discord_is_running;
    ch->destroy = discord_destroy;
    ch->bus = bus;
    ch->running = 0;
    ch->data = dd;

    sc_channel_init_security(ch, cfg->dm_policy, cfg->allow_from,
                              cfg->allow_from_count, "discord");

    return ch;
}
