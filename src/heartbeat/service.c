/*
 * smolclaw - heartbeat service
 * Periodic heartbeat checks. Reads HEARTBEAT.md, calls handler, routes response.
 */

#include "heartbeat/service.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "constants.h"
#include "logger.h"
#include "util/str.h"

/* Minimum interval: 5 minutes */
#define MIN_INTERVAL_MIN 5
#define DEFAULT_INTERVAL_MIN 30

static void timer_callback(evutil_socket_t fd, short what, void *arg);
static void execute_heartbeat(sc_heartbeat_service_t *hs);
static char *build_prompt(sc_heartbeat_service_t *hs);
static void send_response(sc_heartbeat_service_t *hs, const char *response);
static void parse_last_channel(const char *last_channel, char **channel, char **chat_id);

sc_heartbeat_service_t *sc_heartbeat_service_new(const char *workspace,
                                                   int interval_min, int enabled,
                                                   struct event_base *base)
{
    sc_heartbeat_service_t *hs = calloc(1, sizeof(*hs));
    if (!hs) return NULL;

    /* Apply minimum interval */
    if (interval_min > 0 && interval_min < MIN_INTERVAL_MIN) {
        interval_min = MIN_INTERVAL_MIN;
    }
    if (interval_min == 0) {
        interval_min = DEFAULT_INTERVAL_MIN;
    }

    hs->workspace = sc_strdup(workspace);
    hs->interval_min = interval_min;
    hs->enabled = enabled;
    hs->base = base;
    hs->bus = NULL;
    hs->state = NULL;
    hs->handler = NULL;
    hs->handler_ctx = NULL;
    hs->running = 0;
    hs->timer_event = NULL;

    return hs;
}

void sc_heartbeat_service_free(sc_heartbeat_service_t *hs)
{
    if (!hs) return;
    sc_heartbeat_service_stop(hs);
    free(hs->workspace);
    /* state and bus are borrowed */
    free(hs);
}

void sc_heartbeat_service_set_bus(sc_heartbeat_service_t *hs, sc_bus_t *bus)
{
    if (hs) hs->bus = bus;
}

void sc_heartbeat_service_set_state(sc_heartbeat_service_t *hs, sc_state_t *state)
{
    if (hs) hs->state = state;
}

void sc_heartbeat_service_set_handler(sc_heartbeat_service_t *hs,
                                       sc_heartbeat_handler_t handler, void *ctx)
{
    if (!hs) return;
    hs->handler = handler;
    hs->handler_ctx = ctx;
}

int sc_heartbeat_service_start(sc_heartbeat_service_t *hs)
{
    if (!hs) return -1;

    if (hs->running) {
        SC_LOG_INFO("heartbeat", "Heartbeat service already running");
        return 0;
    }

    if (!hs->enabled) {
        SC_LOG_INFO("heartbeat", "Heartbeat service disabled");
        return 0;
    }

    hs->running = 1;

    /* Create periodic timer via libevent */
    if (hs->base) {
        struct timeval interval;
        interval.tv_sec = hs->interval_min * 60;
        interval.tv_usec = 0;

        hs->timer_event = event_new(hs->base, -1, EV_PERSIST, timer_callback, hs);
        if (hs->timer_event) {
            event_add(hs->timer_event, &interval);
        }
    }

    SC_LOG_INFO("heartbeat", "Heartbeat service started (interval=%d min)", hs->interval_min);
    return 0;
}

void sc_heartbeat_service_stop(sc_heartbeat_service_t *hs)
{
    if (!hs || !hs->running) return;

    hs->running = 0;

    if (hs->timer_event) {
        event_del(hs->timer_event);
        event_free(hs->timer_event);
        hs->timer_event = NULL;
    }

    SC_LOG_INFO("heartbeat", "Heartbeat service stopped");
}

/* --- Internal --- */

static void timer_callback(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    sc_heartbeat_service_t *hs = arg;
    if (hs->running) {
        execute_heartbeat(hs);
    }
}

static void execute_heartbeat(sc_heartbeat_service_t *hs)
{
    if (!hs->enabled || !hs->running) return;

    SC_LOG_DEBUG("heartbeat", "Executing heartbeat");

    char *prompt = build_prompt(hs);
    if (!prompt || prompt[0] == '\0') {
        SC_LOG_INFO("heartbeat", "No heartbeat prompt (HEARTBEAT.md empty or missing)");
        free(prompt);
        return;
    }

    if (!hs->handler) {
        SC_LOG_ERROR("heartbeat", "Heartbeat handler not configured");
        free(prompt);
        return;
    }

    /* Get last channel for context */
    const char *last_channel = hs->state ? sc_state_get_last_channel(hs->state) : NULL;
    char *channel = NULL;
    char *chat_id = NULL;
    parse_last_channel(last_channel, &channel, &chat_id);

    SC_LOG_INFO("heartbeat", "Resolved channel: %s, chatID: %s (from lastChannel: %s)",
                channel ? channel : "(null)",
                chat_id ? chat_id : "(null)",
                last_channel ? last_channel : "(null)");

    /* Call handler */
    char *response = hs->handler(prompt, channel, chat_id, hs->handler_ctx);
    free(prompt);

    if (!response) {
        SC_LOG_INFO("heartbeat", "Heartbeat handler returned NULL");
        free(channel);
        free(chat_id);
        return;
    }

    /* Check for HEARTBEAT_OK (silent) */
    if (strcmp(response, "HEARTBEAT_OK") == 0) {
        SC_LOG_INFO("heartbeat", "Heartbeat OK - silent");
        free(response);
        free(channel);
        free(chat_id);
        return;
    }

    /* Send response to last channel */
    send_response(hs, response);
    SC_LOG_INFO("heartbeat", "Heartbeat completed");

    free(response);
    free(channel);
    free(chat_id);
}

static char *build_prompt(sc_heartbeat_service_t *hs)
{
    sc_strbuf_t path;
    sc_strbuf_init(&path);
    sc_strbuf_appendf(&path, "%s/HEARTBEAT.md", hs->workspace);
    char *hb_path = sc_strbuf_finish(&path);

    FILE *f = fopen(hb_path, "r");
    free(hb_path);

    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (len <= 0) { fclose(f); return NULL; }
    if (len > 256 * 1024) len = 256 * 1024;  /* cap at 256 KB */

    char *data = malloc(len + 1);
    if (!data) { fclose(f); return NULL; }

    size_t nread = fread(data, 1, len, f);
    data[nread] = '\0';
    fclose(f);

    if (data[0] == '\0') { free(data); return NULL; }

    /* Build prompt with timestamp */
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_append(&sb, "# Heartbeat Check\n\n");
    sc_strbuf_appendf(&sb, "Current time: %s\n\n", timebuf);
    sc_strbuf_append(&sb, "You are a proactive AI assistant. This is a scheduled heartbeat check.\n");
    sc_strbuf_append(&sb, "Review the following tasks and execute any necessary actions using available tools.\n");
    sc_strbuf_append(&sb, "If there is nothing that requires attention, respond ONLY with: HEARTBEAT_OK\n\n");
    sc_strbuf_append(&sb, data);

    free(data);
    return sc_strbuf_finish(&sb);
}

static void send_response(sc_heartbeat_service_t *hs, const char *response)
{
    if (!hs->bus) {
        SC_LOG_INFO("heartbeat", "No message bus, heartbeat result not sent");
        return;
    }

    if (!hs->state) return;

    const char *last_channel = sc_state_get_last_channel(hs->state);
    if (!last_channel || last_channel[0] == '\0') {
        SC_LOG_INFO("heartbeat", "No last channel recorded, heartbeat result not sent");
        return;
    }

    char *platform = NULL;
    char *user_id = NULL;
    parse_last_channel(last_channel, &platform, &user_id);

    if (!platform || !user_id || platform[0] == '\0' || user_id[0] == '\0') {
        free(platform);
        free(user_id);
        return;
    }

    /* Skip internal channels */
    if (sc_is_internal_channel(platform)) {
        SC_LOG_INFO("heartbeat", "Skipping internal channel: %s", platform);
        free(platform);
        free(user_id);
        return;
    }

    sc_outbound_msg_t *msg = sc_outbound_msg_new(platform, user_id, response);
    if (msg) {
        sc_bus_publish_outbound(hs->bus, msg);
        SC_LOG_INFO("heartbeat", "Heartbeat result sent to %s", platform);
    }

    free(platform);
    free(user_id);
}

static void parse_last_channel(const char *last_channel, char **channel, char **chat_id)
{
    *channel = NULL;
    *chat_id = NULL;

    if (!last_channel || last_channel[0] == '\0') return;

    /* Format: "platform:user_id" */
    const char *colon = strchr(last_channel, ':');
    if (!colon) return;

    size_t platform_len = colon - last_channel;
    if (platform_len == 0) return;

    *channel = malloc(platform_len + 1);
    if (!*channel) return;
    memcpy(*channel, last_channel, platform_len);
    (*channel)[platform_len] = '\0';

    const char *uid = colon + 1;
    if (uid[0] == '\0') {
        free(*channel);
        *channel = NULL;
        return;
    }

    *chat_id = sc_strdup(uid);
}
