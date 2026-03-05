/*
 * smolclaw - Web channel
 * HTTP REST API for agent interaction + embedded chat UI.
 *
 * Runs its own event_base in a dedicated thread.
 * POST /api/message — send a message, get agent response
 * GET /api/health   — health check
 * GET /             — embedded chat UI
 *
 * Async response delivery: inbound messages are published to the bus.
 * When the agent responds, the main thread writes to a pipe which
 * the web thread reads to fulfill the pending HTTP request.
 */

#include "channels/web.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>

#include "cJSON.h"
#include "constants.h"
#include "logger.h"
#include "util/str.h"
#include "util/uuid.h"
#include "util/json_helpers.h"

#define WEB_TAG "web"
#define WEB_REQUEST_TIMEOUT 120  /* seconds */

/* Pending request entry */
typedef struct web_pending {
    char *request_id;
    struct evhttp_request *req;
    struct event *timeout_ev;
    struct web_pending *next;
} web_pending_t;

/* Response message passed through pipe */
typedef struct {
    char request_id[64];
    char *text;
} web_response_t;

typedef struct {
    char *bearer_token;
    char *bind_addr;
    int port;
    struct event_base *base;
    struct evhttp *http;
    pthread_t thread;
    int thread_started;

    /* Pending request map (linked list, protected by mutex) */
    pthread_mutex_t pending_lock;
    web_pending_t *pending_head;

    /* Pipe for thread-safe response delivery */
    int response_pipe[2];
    struct event *pipe_event;
} web_data_t;

/* Embedded chat UI (minimal HTML/JS) */
static const char *CHAT_HTML =
    "<!DOCTYPE html><html><head>"
    "<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>smolclaw</title>"
    "<style>"
    "body{margin:0;background:#1a1a2e;color:#eee;font-family:monospace;display:flex;"
    "flex-direction:column;height:100vh}"
    "#chat{flex:1;overflow-y:auto;padding:1em}"
    ".msg{margin:.5em 0;padding:.5em;border-radius:4px}"
    ".user{background:#16213e;text-align:right}"
    ".bot{background:#0f3460}"
    "#input-area{display:flex;padding:.5em;background:#0a0a1a}"
    "#msg{flex:1;padding:.5em;background:#16213e;color:#eee;border:1px solid #333;"
    "border-radius:4px;font-family:monospace}"
    "#send{padding:.5em 1em;background:#e94560;color:#fff;border:none;border-radius:4px;"
    "cursor:pointer;margin-left:.5em}"
    "</style></head><body>"
    "<div id='chat'></div>"
    "<div id='input-area'>"
    "<input id='msg' placeholder='Type a message...' autocomplete='off'>"
    "<button id='send'>Send</button>"
    "</div>"
    "<script>"
    "let token=localStorage.getItem('sc_token');"
    "if(!token){token=prompt('Bearer token:');if(token)localStorage.setItem('sc_token',token)}"
    "const chat=document.getElementById('chat');"
    "const inp=document.getElementById('msg');"
    "function add(text,cls){const d=document.createElement('div');"
    "d.className='msg '+cls;d.textContent=text;chat.appendChild(d);"
    "chat.scrollTop=chat.scrollHeight}"
    "async function send(){"
    "const t=inp.value.trim();if(!t)return;inp.value='';"
    "add(t,'user');add('...','bot');"
    "try{const r=await fetch('/api/message',{method:'POST',"
    "headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},"
    "body:JSON.stringify({message:t})});"
    "const j=await r.json();"
    "chat.lastChild.textContent=j.response||j.error||'No response'}"
    "catch(e){chat.lastChild.textContent='Error: '+e.message}}"
    "document.getElementById('send').onclick=send;"
    "inp.onkeydown=e=>{if(e.key==='Enter')send()};"
    "</script></body></html>";

/* Check bearer token */
static int check_auth(struct evhttp_request *req, const web_data_t *wd)
{
    if (!wd->bearer_token || !wd->bearer_token[0])
        return 1; /* No token configured = open */

    const char *auth = evhttp_find_header(evhttp_request_get_input_headers(req),
                                           "Authorization");
    if (!auth) return 0;

    /* Expect "Bearer <token>" */
    if (strncmp(auth, "Bearer ", 7) != 0) return 0;
    return strcmp(auth + 7, wd->bearer_token) == 0;
}

static void send_json_error(struct evhttp_request *req, int code,
                             const char *msg)
{
    struct evbuffer *buf = evbuffer_new();
    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "error", msg);
    char *str = cJSON_PrintUnformatted(j);
    evbuffer_add(buf, str, strlen(str));
    free(str);
    cJSON_Delete(j);
    evhttp_add_header(evhttp_request_get_output_headers(req),
                       "Content-Type", "application/json");
    evhttp_send_reply(req, code, NULL, buf);
    evbuffer_free(buf);
}

/* Timeout callback for pending requests */
static void request_timeout_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    web_pending_t *wp = arg;

    /* Send 504 and let cleanup happen */
    if (wp->req)
        send_json_error(wp->req, 504, "Request timed out");
    wp->req = NULL; /* Mark as handled */
}

/* Add a pending request */
static void add_pending(web_data_t *wd, const char *request_id,
                          struct evhttp_request *req)
{
    web_pending_t *wp = calloc(1, sizeof(*wp));
    if (!wp) return;

    wp->request_id = sc_strdup(request_id);
    wp->req = req;
    wp->next = NULL;

    /* Set timeout */
    struct timeval tv = { .tv_sec = WEB_REQUEST_TIMEOUT, .tv_usec = 0 };
    wp->timeout_ev = event_new(wd->base, -1, 0, request_timeout_cb, wp);
    if (wp->timeout_ev)
        event_add(wp->timeout_ev, &tv);

    pthread_mutex_lock(&wd->pending_lock);
    wp->next = wd->pending_head;
    wd->pending_head = wp;
    pthread_mutex_unlock(&wd->pending_lock);
}

/* Find and remove a pending request by ID */
static web_pending_t *take_pending(web_data_t *wd, const char *request_id)
{
    pthread_mutex_lock(&wd->pending_lock);

    web_pending_t *prev = NULL;
    web_pending_t *cur = wd->pending_head;
    while (cur) {
        if (strcmp(cur->request_id, request_id) == 0) {
            if (prev)
                prev->next = cur->next;
            else
                wd->pending_head = cur->next;
            cur->next = NULL;
            pthread_mutex_unlock(&wd->pending_lock);
            return cur;
        }
        prev = cur;
        cur = cur->next;
    }

    pthread_mutex_unlock(&wd->pending_lock);
    return NULL;
}

static void free_pending(web_pending_t *wp)
{
    if (!wp) return;
    if (wp->timeout_ev) {
        event_del(wp->timeout_ev);
        event_free(wp->timeout_ev);
    }
    free(wp->request_id);
    free(wp);
}

/* Handle POST /api/message */
static void handle_message(struct evhttp_request *req, void *arg)
{
    sc_channel_t *ch = arg;
    web_data_t *wd = ch->data;

    if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
        send_json_error(req, 405, "Method not allowed");
        return;
    }

    if (!check_auth(req, wd)) {
        send_json_error(req, 401, "Unauthorized");
        return;
    }

    /* Parse body */
    struct evbuffer *input = evhttp_request_get_input_buffer(req);
    size_t len = evbuffer_get_length(input);
    if (len == 0 || len > 64 * 1024) {
        send_json_error(req, 400, "Invalid request body");
        return;
    }

    char *body = malloc(len + 1);
    if (!body) {
        send_json_error(req, 500, "Out of memory");
        return;
    }
    evbuffer_copyout(input, body, len);
    body[len] = '\0';

    cJSON *json = cJSON_Parse(body);
    free(body);
    if (!json) {
        send_json_error(req, 400, "Invalid JSON");
        return;
    }

    const char *message = sc_json_get_string(json, "message", NULL);
    const char *session = sc_json_get_string(json, "session", NULL);
    if (!message || !message[0]) {
        cJSON_Delete(json);
        send_json_error(req, 400, "Missing 'message' field");
        return;
    }

    /* Generate request ID */
    char request_id[64];
    char *rid = sc_generate_id();
    snprintf(request_id, sizeof(request_id), "%s", rid ? rid : "unknown");
    free(rid);

    /* Store pending request */
    add_pending(wd, request_id, req);

    /* Build session key */
    sc_strbuf_t sk;
    sc_strbuf_init(&sk);
    sc_strbuf_appendf(&sk, "web:%s", session && session[0] ? session : request_id);
    char *session_key = sc_strbuf_finish(&sk);

    /* Publish inbound message to bus.
     * sender_id = "web" (no user auth), chat_id = request_id for response routing */
    sc_inbound_msg_t *inbound = sc_inbound_msg_new(
        SC_CHANNEL_WEB, "web", request_id, message, session_key);
    free(session_key);
    cJSON_Delete(json);

    if (inbound) {
        sc_bus_publish_inbound(ch->bus, inbound);
    } else {
        web_pending_t *wp = take_pending(wd, request_id);
        if (wp) {
            send_json_error(wp->req, 500, "Failed to create message");
            free_pending(wp);
        }
    }
}

/* Handle GET /api/health */
static void handle_health(struct evhttp_request *req, void *arg)
{
    (void)arg;
    struct evbuffer *buf = evbuffer_new();
    evbuffer_add_printf(buf, "{\"status\":\"ok\"}");
    evhttp_add_header(evhttp_request_get_output_headers(req),
                       "Content-Type", "application/json");
    evhttp_send_reply(req, 200, "OK", buf);
    evbuffer_free(buf);
}

/* Handle GET / (chat UI) */
static void handle_root(struct evhttp_request *req, void *arg)
{
    (void)arg;
    struct evbuffer *buf = evbuffer_new();
    evbuffer_add(buf, CHAT_HTML, strlen(CHAT_HTML));
    evhttp_add_header(evhttp_request_get_output_headers(req),
                       "Content-Type", "text/html; charset=utf-8");
    evhttp_send_reply(req, 200, "OK", buf);
    evbuffer_free(buf);
}

/* Default handler for unmatched routes */
static void handle_notfound(struct evhttp_request *req, void *arg)
{
    (void)arg;
    send_json_error(req, 404, "Not found");
}

/* Pipe callback: reads responses from main thread */
static void pipe_read_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    sc_channel_t *ch = arg;
    web_data_t *wd = ch->data;

    web_response_t resp;
    ssize_t n = read(fd, &resp, sizeof(resp));
    if (n != sizeof(resp)) return;

    web_pending_t *wp = take_pending(wd, resp.request_id);
    if (wp && wp->req) {
        struct evbuffer *buf = evbuffer_new();
        cJSON *j = cJSON_CreateObject();
        cJSON_AddStringToObject(j, "response", resp.text ? resp.text : "");
        char *str = cJSON_PrintUnformatted(j);
        evbuffer_add(buf, str, strlen(str));
        free(str);
        cJSON_Delete(j);

        evhttp_add_header(evhttp_request_get_output_headers(wp->req),
                           "Content-Type", "application/json");
        evhttp_send_reply(wp->req, 200, "OK", buf);
        evbuffer_free(buf);
    }
    free_pending(wp);
    free(resp.text);
}

/* Web thread main function */
static void *web_thread_fn(void *arg)
{
    sc_channel_t *ch = arg;
    web_data_t *wd = ch->data;

    event_base_dispatch(wd->base);
    return NULL;
}

/* Channel vtable: send (called from main thread) */
static int web_send(sc_channel_t *self, sc_outbound_msg_t *msg)
{
    web_data_t *wd = self->data;
    if (!msg || !msg->chat_id || !msg->content) return -1;

    web_response_t resp;
    memset(&resp, 0, sizeof(resp));
    snprintf(resp.request_id, sizeof(resp.request_id), "%s", msg->chat_id);
    resp.text = sc_strdup(msg->content);

    ssize_t written = write(wd->response_pipe[1], &resp, sizeof(resp));
    if (written != sizeof(resp)) {
        free(resp.text);
        SC_LOG_ERROR(WEB_TAG, "Failed to write response to pipe");
        return -1;
    }

    return 0;
}

static int web_start(sc_channel_t *self)
{
    web_data_t *wd = self->data;

    /* Create event base */
    wd->base = event_base_new();
    if (!wd->base) {
        SC_LOG_ERROR(WEB_TAG, "Failed to create event base");
        return -1;
    }

    /* Create HTTP server */
    wd->http = evhttp_new(wd->base);
    if (!wd->http) {
        SC_LOG_ERROR(WEB_TAG, "Failed to create HTTP server");
        event_base_free(wd->base);
        wd->base = NULL;
        return -1;
    }

    /* Set up routes */
    evhttp_set_cb(wd->http, "/api/message", handle_message, self);
    evhttp_set_cb(wd->http, "/api/health", handle_health, self);
    evhttp_set_cb(wd->http, "/", handle_root, self);
    evhttp_set_gencb(wd->http, handle_notfound, self);

    /* Bind */
    if (evhttp_bind_socket(wd->http, wd->bind_addr, (uint16_t)wd->port) != 0) {
        SC_LOG_ERROR(WEB_TAG, "Failed to bind to %s:%d",
                     wd->bind_addr, wd->port);
        evhttp_free(wd->http);
        event_base_free(wd->base);
        wd->http = NULL;
        wd->base = NULL;
        return -1;
    }

    /* Set up response pipe */
    if (pipe(wd->response_pipe) != 0) {
        SC_LOG_ERROR(WEB_TAG, "Failed to create response pipe");
        evhttp_free(wd->http);
        event_base_free(wd->base);
        wd->http = NULL;
        wd->base = NULL;
        return -1;
    }

    wd->pipe_event = event_new(wd->base, wd->response_pipe[0],
                                EV_READ | EV_PERSIST, pipe_read_cb, self);
    event_add(wd->pipe_event, NULL);

    self->running = 1;
    wd->thread_started = 1;

    int ret = pthread_create(&wd->thread, NULL, web_thread_fn, self);
    if (ret != 0) {
        SC_LOG_ERROR(WEB_TAG, "Failed to create web thread");
        self->running = 0;
        wd->thread_started = 0;
        close(wd->response_pipe[0]);
        close(wd->response_pipe[1]);
        event_free(wd->pipe_event);
        evhttp_free(wd->http);
        event_base_free(wd->base);
        wd->http = NULL;
        wd->base = NULL;
        return -1;
    }

    SC_LOG_INFO(WEB_TAG, "Web channel started on %s:%d",
                wd->bind_addr, wd->port);
    return 0;
}

static int web_stop(sc_channel_t *self)
{
    web_data_t *wd = self->data;
    self->running = 0;

    if (wd->base)
        event_base_loopbreak(wd->base);

    if (wd->thread_started)
        pthread_join(wd->thread, NULL);

    SC_LOG_INFO(WEB_TAG, "Web channel stopped");
    return 0;
}

static int web_is_running(sc_channel_t *self)
{
    return self->running;
}

static void web_destroy(sc_channel_t *self)
{
    if (!self) return;
    web_data_t *wd = self->data;
    if (wd) {
        /* Clean up pending requests */
        web_pending_t *cur = wd->pending_head;
        while (cur) {
            web_pending_t *next = cur->next;
            free_pending(cur);
            cur = next;
        }

        if (wd->pipe_event) {
            event_del(wd->pipe_event);
            event_free(wd->pipe_event);
        }
        if (wd->response_pipe[0]) close(wd->response_pipe[0]);
        if (wd->response_pipe[1]) close(wd->response_pipe[1]);
        if (wd->http) evhttp_free(wd->http);
        if (wd->base) event_base_free(wd->base);

        free(wd->bearer_token);
        free(wd->bind_addr);
        pthread_mutex_destroy(&wd->pending_lock);
        free(wd);
    }
    self->data = NULL;
    sc_channel_base_free(self);
}

sc_channel_t *sc_channel_web_new(sc_web_config_t *cfg, sc_bus_t *bus)
{
    if (!cfg) return NULL;

    sc_channel_t *ch = calloc(1, sizeof(*ch));
    if (!ch) return NULL;

    web_data_t *wd = calloc(1, sizeof(*wd));
    if (!wd) { free(ch); return NULL; }

    wd->bearer_token = sc_strdup(cfg->bearer_token);
    wd->bind_addr = sc_strdup(cfg->bind_addr && cfg->bind_addr[0]
                               ? cfg->bind_addr : "127.0.0.1");
    wd->port = cfg->port > 0 ? cfg->port : SC_DEFAULT_WEB_PORT;
    wd->base = NULL;
    wd->http = NULL;
    wd->thread_started = 0;
    wd->pending_head = NULL;
    wd->response_pipe[0] = 0;
    wd->response_pipe[1] = 0;
    wd->pipe_event = NULL;
    pthread_mutex_init(&wd->pending_lock, NULL);

    ch->name = SC_CHANNEL_WEB;
    ch->start = web_start;
    ch->stop = web_stop;
    ch->send = web_send;
    ch->send_typing = NULL;
    ch->is_running = web_is_running;
    ch->destroy = web_destroy;
    ch->bus = bus;
    ch->running = 0;
    ch->data = wd;

    sc_channel_init_security(ch, cfg->dm_policy, cfg->allow_from,
                              cfg->allow_from_count, "web");

    return ch;
}
