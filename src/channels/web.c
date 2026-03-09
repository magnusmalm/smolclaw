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
#include <errno.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>

#if SC_HAVE_EVENT_OPENSSL
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "cJSON.h"
#include "constants.h"
#include "logger.h"
#include "util/str.h"
#include "util/uuid.h"
#include "util/json_helpers.h"
#include "util/sha256.h"

#define WEB_TAG "web"
#define WEB_REQUEST_TIMEOUT 120  /* seconds */
#define WEB_MAX_PENDING     100

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
    int auto_port;
    char *tls_cert;
    char *tls_key;
    struct event_base *base;
    struct evhttp *http;
    pthread_t thread;
    int thread_started;

    /* Pending request map (linked list, protected by mutex) */
    pthread_mutex_t pending_lock;
    web_pending_t *pending_head;
    int pending_count;

    /* Pipe for thread-safe response delivery */
    int response_pipe[2];
    struct event *pipe_event;

#if SC_HAVE_EVENT_OPENSSL
    SSL_CTX *ssl_ctx;
#endif
} web_data_t;

/* Check if address is loopback (safe for plaintext HTTP) */
static int is_loopback_addr(const char *addr)
{
    if (!addr) return 1;
    return strcmp(addr, "127.0.0.1") == 0 ||
           strcmp(addr, "::1") == 0 ||
           strcmp(addr, "localhost") == 0;
}

#if SC_HAVE_EVENT_OPENSSL
/* Bufferevent callback: creates an SSL-wrapped bufferevent for each connection */
static struct bufferevent *ssl_bevcb(struct event_base *base, void *arg)
{
    SSL_CTX *ctx = arg;
    SSL *ssl = SSL_new(ctx);
    if (!ssl) return NULL;
    return bufferevent_openssl_socket_new(base, -1, ssl,
                                          BUFFEREVENT_SSL_ACCEPTING,
                                          BEV_OPT_CLOSE_ON_FREE);
}

/* Initialize SSL_CTX from cert + key files. Returns NULL on failure. */
static SSL_CTX *web_ssl_ctx_new(const char *cert_path, const char *key_path)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        SC_LOG_ERROR(WEB_TAG, "Failed to create SSL context");
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1) {
        SC_LOG_ERROR(WEB_TAG, "Failed to load TLS certificate: %s", cert_path);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1) {
        SC_LOG_ERROR(WEB_TAG, "Failed to load TLS private key: %s", key_path);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        SC_LOG_ERROR(WEB_TAG, "TLS private key does not match certificate");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}
#endif

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
    return sc_timing_safe_cmp(auth + 7, wd->bearer_token) == 0;
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

/* Add a pending request. Returns 0 on success, -1 if at capacity. */
static int add_pending(web_data_t *wd, const char *request_id,
                         struct evhttp_request *req)
{
    pthread_mutex_lock(&wd->pending_lock);
    if (wd->pending_count >= WEB_MAX_PENDING) {
        pthread_mutex_unlock(&wd->pending_lock);
        return -1;
    }
    pthread_mutex_unlock(&wd->pending_lock);

    web_pending_t *wp = calloc(1, sizeof(*wp));
    if (!wp) return -1;

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
    wd->pending_count++;
    pthread_mutex_unlock(&wd->pending_lock);
    return 0;
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
            wd->pending_count--;
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
    if (add_pending(wd, request_id, req) != 0) {
        cJSON_Delete(json);
        send_json_error(req, 503, "Too many pending requests");
        return;
    }

    /* Build session key — namespace by bearer token so different clients
     * cannot access each other's sessions by guessing the session name. */
    sc_strbuf_t sk;
    sc_strbuf_init(&sk);
    const char *sess_name = session && session[0] ? session : request_id;
    if (wd->bearer_token) {
        /* Hash the token so it doesn't appear in session filenames */
        sc_sha256_ctx_t ctx;
        sc_sha256_init(&ctx);
        sc_sha256_update(&ctx, (const uint8_t *)wd->bearer_token,
                         strlen(wd->bearer_token));
        uint8_t hash[32];
        sc_sha256_final(&ctx, hash);
        char token_hash[17];
        for (int i = 0; i < 8; i++)
            snprintf(token_hash + i * 2, 3, "%02x", hash[i]);
        sc_strbuf_appendf(&sk, "web:%s:%s", token_hash, sess_name);
    } else
        sc_strbuf_appendf(&sk, "web:%s", sess_name);
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
    ssize_t n;
    do {
        n = read(fd, &resp, sizeof(resp));
    } while (n < 0 && errno == EINTR);
    if (n != (ssize_t)sizeof(resp)) {
        /* Partial/failed read — can't recover the text pointer safely */
        if (n > 0)
            SC_LOG_ERROR(WEB_TAG, "Partial pipe read (%zd/%zu bytes), response lost",
                         n, sizeof(resp));
        return;
    }

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

    ssize_t written;
    do {
        written = write(wd->response_pipe[1], &resp, sizeof(resp));
    } while (written < 0 && errno == EINTR);
    if (written != (ssize_t)sizeof(resp)) {
        free(resp.text);
        SC_LOG_ERROR(WEB_TAG, "Failed to write response to pipe");
        return -1;
    }

    return 0;
}

static int web_start(sc_channel_t *self)
{
    web_data_t *wd = self->data;

    if (!wd->bearer_token || !wd->bearer_token[0])
        SC_LOG_WARN(WEB_TAG, "No bearer token configured — web API is unauthenticated");

    int has_tls = 0;
#if SC_HAVE_EVENT_OPENSSL
    if (wd->tls_cert && wd->tls_cert[0] && wd->tls_key && wd->tls_key[0]) {
        has_tls = 1;
    } else if (wd->tls_cert || wd->tls_key) {
        SC_LOG_ERROR(WEB_TAG, "Both tls_cert and tls_key must be set for HTTPS");
        return -1;
    }
#else
    if (wd->tls_cert && wd->tls_cert[0]) {
        SC_LOG_WARN(WEB_TAG, "TLS cert configured but built without OpenSSL support — "
                    "running plain HTTP");
    }
#endif

    if (!has_tls && !is_loopback_addr(wd->bind_addr))
        SC_LOG_WARN(WEB_TAG, "Binding to %s without TLS — exposed to network. "
                    "Configure tls_cert/tls_key or use a reverse proxy for HTTPS.",
                    wd->bind_addr);

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

#if SC_HAVE_EVENT_OPENSSL
    /* Set up TLS if cert+key configured */
    if (has_tls) {
        wd->ssl_ctx = web_ssl_ctx_new(wd->tls_cert, wd->tls_key);
        if (!wd->ssl_ctx) {
            evhttp_free(wd->http);
            event_base_free(wd->base);
            wd->http = NULL;
            wd->base = NULL;
            return -1;
        }
        evhttp_set_bevcb(wd->http, ssl_bevcb, wd->ssl_ctx);
    }
#endif

    /* Set up routes */
    evhttp_set_cb(wd->http, "/api/message", handle_message, self);
    evhttp_set_cb(wd->http, "/api/health", handle_health, self);
    evhttp_set_cb(wd->http, "/", handle_root, self);
    evhttp_set_gencb(wd->http, handle_notfound, self);

    /* Bind — try configured port, then auto-increment up to +10 */
    int bound = 0;
    int try_port = wd->port;
    int max_port = wd->auto_port ? try_port + 10 : try_port;
    for (; try_port <= max_port; try_port++) {
        if (evhttp_bind_socket(wd->http, wd->bind_addr, (uint16_t)try_port) == 0) {
            bound = 1;
            if (try_port != wd->port)
                SC_LOG_INFO(WEB_TAG, "Port %d in use, bound to %d instead",
                            wd->port, try_port);
            wd->port = try_port;
            break;
        }
    }
    if (!bound) {
        SC_LOG_ERROR(WEB_TAG, "Failed to bind to %s:%d%s",
                     wd->bind_addr, wd->port,
                     wd->auto_port ? " (tried +10)" : "");
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

    SC_LOG_INFO(WEB_TAG, "Web channel started on %s://%s:%d",
                has_tls ? "https" : "http", wd->bind_addr, wd->port);
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
        if (wd->response_pipe[0] >= 0) close(wd->response_pipe[0]);
        if (wd->response_pipe[1] >= 0) close(wd->response_pipe[1]);
        if (wd->http) evhttp_free(wd->http);
        if (wd->base) event_base_free(wd->base);

#if SC_HAVE_EVENT_OPENSSL
        if (wd->ssl_ctx) SSL_CTX_free(wd->ssl_ctx);
#endif
        free(wd->bearer_token);
        free(wd->bind_addr);
        free(wd->tls_cert);
        free(wd->tls_key);
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
    wd->auto_port = cfg->auto_port;
    wd->tls_cert = sc_strdup(cfg->tls_cert);
    wd->tls_key = sc_strdup(cfg->tls_key);
    wd->base = NULL;
    wd->http = NULL;
    wd->thread_started = 0;
    wd->pending_head = NULL;
    wd->response_pipe[0] = -1;
    wd->response_pipe[1] = -1;
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
