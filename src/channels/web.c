/*
 * smolclaw - Web channel
 * HTTP REST API for agent interaction + embedded chat UI.
 *
 * Runs its own event_base in a dedicated thread.
 * POST /api/message       — send a message, get agent response
 * POST /api/memory/log    — append to agent's daily notes (bearer auth)
 * POST /api/memory/search — query agent's FTS5 memory index (bearer auth)
 * GET /api/health         — health check
 * GET /                   — embedded chat UI
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
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>

#include <time.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>

#if SC_HAVE_EVENT_OPENSSL
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "sc_features.h"
#include "cJSON.h"
#include "constants.h"
#include "logger.h"
#include "memory.h"
#if SC_ENABLE_MEMORY_SEARCH
#include "memory_index.h"
#endif
#include "util/glob.h"
#include "util/port_diag.h"
#include "util/str.h"
#include "util/uuid.h"
#include "util/json_helpers.h"
#include "util/sha256.h"
#include "rate_limit.h"
#include "audit.h"

#define WEB_TAG "web"
#define WEB_REQUEST_TIMEOUT_DEFAULT 600  /* seconds — fallback when config and
                                          * max_turn_secs are both unset. Must
                                          * cover multi-step delegation chains. */
#define WEB_MAX_PENDING     100

#define WEB_PROGRESS_MAX_LINES 200
#define WEB_ATTACH_MAX 6

/* Pending request entry */
typedef struct web_pending {
    char *request_id;
    struct evhttp_request *req;
    struct event *timeout_ev;
    int structured_response;
    /* Live-progress feed: client-chosen id polled via /api/progress
     * while the turn runs; lines come from is_progress outbound
     * messages (agent verbose mode). Protected by pending_lock. */
    char *progress_id;
    char **progress;
    int progress_count;
    time_t turn_start;
    struct web_pending *next;
} web_pending_t;

/* Response message passed through pipe */
typedef struct {
    char request_id[64];
    char *text;
} web_response_t;

/* Audit M-2: the response struct is shuttled main-thread -> web-thread as a
 * single write()/read() of sizeof(web_response_t). POSIX guarantees a pipe
 * write of <= PIPE_BUF bytes is atomic, so the reader never observes a partial
 * message and can never lose (leak) the `text` pointer to a torn read. This
 * assertion enforces that invariant at compile time — if the struct ever grows
 * past PIPE_BUF, switch to a length-prefixed framing instead. */
_Static_assert(sizeof(web_response_t) <= PIPE_BUF,
               "web_response_t must fit in PIPE_BUF for atomic pipe writes (audit M-2)");

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

    /* Workspace path for memory access */
    char *workspace;

    /* Optional live-stream URL surfaced to the UI (see config.h) */
    char *embed_stream_url;

    /* Per-request server-side timeout (seconds). Source priority:
     *   1. channels.web.request_timeout_secs if explicitly set
     *   2. agents.defaults.max_turn_secs + 30s grace
     *   3. WEB_REQUEST_TIMEOUT_DEFAULT (600s)
     * Resolved once at channel construction; rebind the agent to pick
     * up a config change. */
    int request_timeout_secs;

    /* Session-isolation glob (Phase 4). If non-NULL/non-empty and a
     * request's `session` field matches, the inbound message is marked
     * isolated. See docs/design/session-isolation-plan.md. */
    char *isolation_pattern;

    /* Uptime tracking */
    time_t start_time;

#if SC_HAVE_EVENT_OPENSSL
    SSL_CTX *ssl_ctx;
#endif
} web_data_t;

int sc_web_compute_isolation(const char *pattern,
                              const char *session_name,
                              const char *session_key,
                              char out_ns_id[17])
{
    if (out_ns_id) out_ns_id[0] = '\0';
    if (!pattern || !pattern[0]) return 0;
    if (!session_name || !session_key || !out_ns_id) return 0;
    if (!sc_glob_match(pattern, session_name)) return 0;

    sc_sha256_ctx_t ctx;
    sc_sha256_init(&ctx);
    sc_sha256_update(&ctx, (const uint8_t *)session_key, strlen(session_key));
    uint8_t hash[32];
    sc_sha256_final(&ctx, hash);
    for (int i = 0; i < 8; i++)
        snprintf(out_ns_id + i * 2, 3, "%02x", hash[i]);
    out_ns_id[16] = '\0';
    return 1;
}

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
    /* Lazy TLS: only reached from web channel start, not agent init
     * (docs/design/deferred-initialization.md item 3). */
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
    ".msg img{max-width:100%;border-radius:4px;display:block;margin:.5em 0}"
    ".log{background:#0a0a1a;color:#8a8aa8;font-size:.8em;white-space:pre-wrap;"
    "margin:.3em 0;padding:.4em;border-radius:4px;border-left:2px solid #e94560}"
    "#input-area{display:flex;align-items:center;padding:.5em;background:#0a0a1a}"
    "#msg{flex:1;padding:.5em;background:#16213e;color:#eee;border:1px solid #333;"
    "border-radius:4px;font-family:monospace}"
    "#send{padding:.5em 1em;background:#e94560;color:#fff;border:none;border-radius:4px;"
    "cursor:pointer;margin-left:.5em}"
    "#vwrap{font-size:.75em;color:#8a8aa8;margin-left:.6em;white-space:nowrap;"
    "user-select:none;cursor:pointer}"
    "#live{display:none;background:#000;text-align:center}"
    "#live img{max-width:100%;max-height:45vh}"
    "#livebtn{display:none;padding:.5em .8em;background:#16213e;color:#8a8aa8;"
    "border:1px solid #333;border-radius:4px;cursor:pointer;margin-left:.5em}"
    "#livebtn.on{background:#0f3460;color:#eee}"
    "</style></head><body>"
    "<div id='live'></div>"
    "<div id='chat'></div>"
    "<div id='input-area'>"
    "<input id='msg' placeholder='Type a message...' autocomplete='off'>"
    "<button id='send'>Send</button>"
    "<button id='livebtn'>&#9679; Live</button>"
    "<label id='vwrap'><input type='checkbox' id='vlog'> live log</label>"
    "</div>"
    "<script>"
    "let token=sessionStorage.getItem('sc_token');"
    "if(!token){token=prompt('Bearer token:');if(token)sessionStorage.setItem('sc_token',token)}"
    "const chat=document.getElementById('chat');"
    "const inp=document.getElementById('msg');"
    "const vlog=document.getElementById('vlog');"
    "vlog.checked=localStorage.getItem('sc_vlog')==='1';"
    "vlog.onchange=()=>localStorage.setItem('sc_vlog',vlog.checked?'1':'0');"
    "const H=()=>({'Content-Type':'application/json','Authorization':'Bearer '+token});"
    "const live=document.getElementById('live');"
    "const livebtn=document.getElementById('livebtn');"
    "let streamUrl=null;"
    "fetch('/api/ui-config',{headers:{'Authorization':'Bearer '+token}})"
    ".then(r=>r.json()).then(j=>{if(j.stream_url){streamUrl=j.stream_url;"
    "livebtn.style.display='inline-block'}}).catch(e=>{});"
    "livebtn.onclick=()=>{"
    "if(live.style.display==='block'){live.style.display='none';"
    "live.innerHTML='';livebtn.classList.remove('on')}"
    "else{live.innerHTML='<img src=\"'+streamUrl+'\">';"
    "live.style.display='block';livebtn.classList.add('on')}};"
    "function add(text,cls){const d=document.createElement('div');"
    "d.className='msg '+cls;d.textContent=text;chat.appendChild(d);"
    "chat.scrollTop=chat.scrollHeight;return d}"
    "async function addImg(parent,path){"
    "try{const r=await fetch('/api/media?path='+encodeURIComponent(path),"
    "{headers:{'Authorization':'Bearer '+token}});"
    "if(!r.ok)return;const b=await r.blob();"
    "const img=document.createElement('img');img.src=URL.createObjectURL(b);"
    "img.title=path;parent.appendChild(img);chat.scrollTop=chat.scrollHeight}"
    "catch(e){}}"
    "function pollProgress(pid,logEl,state){"
    "const tick=async()=>{if(state.stop)return;"
    "try{const r=await fetch('/api/progress?id='+pid+'&after='+state.next,"
    "{headers:{'Authorization':'Bearer '+token}});"
    "const j=await r.json();"
    "if(j.lines&&j.lines.length){state.next=j.next;"
    "logEl.textContent+=(logEl.textContent?'\\n':'')+j.lines.join('\\n');"
    "chat.scrollTop=chat.scrollHeight}"
    "if(!state.stop&&!j.done)setTimeout(tick,1000)}"
    "catch(e){}};"
    "setTimeout(tick,600)}"
    "async function send(){"
    "const t=inp.value.trim();if(!t)return;inp.value='';"
    "add(t,'user');const bot=add('...','bot');"
    "const body={message:t};let logEl=null;const state={next:0,stop:false};"
    "if(vlog.checked){"
    "body.progress_id=([...crypto.getRandomValues(new Uint8Array(8))]"
    ".map(b=>b.toString(16).padStart(2,'0')).join(''));"
    "logEl=document.createElement('div');logEl.className='log';"
    "chat.insertBefore(logEl,bot);"
    "pollProgress(body.progress_id,logEl,state)}"
    "try{const r=await fetch('/api/message',{method:'POST',headers:H(),"
    "body:JSON.stringify(body)});"
    "const j=await r.json();state.stop=true;"
    "bot.textContent=j.response||j.error||'No response';"
    "if(j.attachments)for(const a of j.attachments)addImg(bot,a)}"
    "catch(e){state.stop=true;bot.textContent='Error: '+e.message}}"
    "document.getElementById('send').onclick=send;"
    "inp.onkeydown=e=>{if(e.key==='Enter')send()};"
    "</script></body></html>";

/* Fail-closed bearer auth (audit 4298ba13 / PR-1). The web channel must not
 * start without a configured token; this path denies anyway if misconfigured. */
int sc_web_check_bearer_auth(const char *configured_token,
                              const char *authorization_header)
{
    if (!configured_token || !configured_token[0])
        return 0;

    if (!authorization_header)
        return 0;

    if (strncmp(authorization_header, "Bearer ", 7) != 0)
        return 0;

    return sc_timing_safe_cmp(authorization_header + 7, configured_token) == 0;
}

static int check_auth(struct evhttp_request *req, const web_data_t *wd)
{
    const char *auth = evhttp_find_header(evhttp_request_get_input_headers(req),
                                           "Authorization");
    return sc_web_check_bearer_auth(wd->bearer_token, auth);
}

/* Per-IP rate limiting for /api/message (audit 4298ba13 / P1-4). HTTP bypasses
 * sc_channel_handle_message, so we apply agents.defaults rate_limiter here,
 * keyed by client IP and bearer-token hash to limit credential sharing abuse. */
int sc_web_build_message_rate_key(const char *client_ip,
                                   const char *authorization_header,
                                   char *out, size_t out_len)
{
    if (!out || out_len == 0) return -1;

    const char *ip = (client_ip && client_ip[0]) ? client_ip : "unknown";
    char token_hash[17] = "anon";

    if (authorization_header &&
        strncmp(authorization_header, "Bearer ", 7) == 0 &&
        authorization_header[7]) {
        sc_sha256_ctx_t ctx;
        sc_sha256_init(&ctx);
        sc_sha256_update(&ctx, (const uint8_t *)(authorization_header + 7),
                         strlen(authorization_header + 7));
        uint8_t hash[32];
        sc_sha256_final(&ctx, hash);
        for (int i = 0; i < 8; i++)
            snprintf(token_hash + i * 2, 3, "%02x", hash[i]);
    }

    snprintf(out, out_len, "web:msg:%s:%s", ip, token_hash);
    return 0;
}

int sc_web_check_message_rate_limit(sc_rate_limiter_t *rl,
                                     const char *client_ip,
                                     const char *authorization_header)
{
    if (!rl) return 1;

    char key[128];
    if (sc_web_build_message_rate_key(client_ip, authorization_header,
                                      key, sizeof(key)) != 0)
        return 1;

    return sc_rate_limiter_check(rl, key);
}

static void web_client_ip(struct evhttp_request *req, char *buf, size_t buflen)
{
    if (!buf || buflen == 0) return;
    buf[0] = '\0';

    struct evhttp_connection *con = evhttp_request_get_connection(req);
    if (!con) {
        snprintf(buf, buflen, "unknown");
        return;
    }

    char *addr = NULL;
    ev_uint16_t port = 0;
    evhttp_connection_get_peer(con, &addr, &port);
    if (addr && addr[0])
        snprintf(buf, buflen, "%s", addr);
    else
        snprintf(buf, buflen, "unknown");
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
                         struct evhttp_request *req,
                         int structured_response,
                         const char *progress_id)
{
    /* Allocate outside lock, then re-check count under lock to close
     * the TOCTOU window between capacity check and insertion. */
    web_pending_t *wp = calloc(1, sizeof(*wp));
    if (!wp) return -1;

    wp->request_id = sc_strdup(request_id);
    wp->req = req;
    wp->structured_response = structured_response;
    if (progress_id && progress_id[0])
        wp->progress_id = sc_strdup(progress_id);
    wp->turn_start = time(NULL);
    wp->next = NULL;

    /* Set timeout */
    int t = wd->request_timeout_secs > 0
            ? wd->request_timeout_secs
            : WEB_REQUEST_TIMEOUT_DEFAULT;
    struct timeval tv = { .tv_sec = t, .tv_usec = 0 };
    wp->timeout_ev = event_new(wd->base, -1, 0, request_timeout_cb, wp);
    if (wp->timeout_ev)
        event_add(wp->timeout_ev, &tv);

    pthread_mutex_lock(&wd->pending_lock);
    if (wd->pending_count >= WEB_MAX_PENDING) {
        pthread_mutex_unlock(&wd->pending_lock);
        if (wp->timeout_ev) event_free(wp->timeout_ev);
        free(wp->request_id);
        free(wp->progress_id);
        free(wp);
        return -1;
    }
    wp->next = wd->pending_head;
    wd->pending_head = wp;
    wd->pending_count++;
    pthread_mutex_unlock(&wd->pending_lock);
    return 0;
}

/* Find and remove a pending request by ID */
static int pending_requires_final_response(web_data_t *wd,
                                          const char *request_id)
{
    int structured = 0;

    pthread_mutex_lock(&wd->pending_lock);
    for (web_pending_t *cur = wd->pending_head; cur; cur = cur->next) {
        if (strcmp(cur->request_id, request_id) == 0) {
            structured = cur->structured_response;
            break;
        }
    }
    pthread_mutex_unlock(&wd->pending_lock);
    return structured;
}

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
    free(wp->progress_id);
    for (int i = 0; i < wp->progress_count; i++)
        free(wp->progress[i]);
    free(wp->progress);
    free(wp);
}

/* Append a progress line to the pending request it belongs to.
 * Called from the agent thread (web_send); readers hold pending_lock. */
static void append_progress(web_data_t *wd, const char *request_id,
                             const char *line)
{
    pthread_mutex_lock(&wd->pending_lock);
    for (web_pending_t *cur = wd->pending_head; cur; cur = cur->next) {
        if (strcmp(cur->request_id, request_id) != 0) continue;
        if (!cur->progress_id) break;             /* client not listening */
        if (cur->progress_count >= WEB_PROGRESS_MAX_LINES) break;
        char **tmp = realloc(cur->progress,
            (size_t)(cur->progress_count + 1) * sizeof(char *));
        if (!tmp) break;
        cur->progress = tmp;
        cur->progress[cur->progress_count] = sc_strdup(line);
        if (cur->progress[cur->progress_count])
            cur->progress_count++;
        break;
    }
    pthread_mutex_unlock(&wd->pending_lock);
}

/* GET /api/progress?id=<progress_id>&after=<n> — poll live progress
 * lines for an in-flight /api/message turn. Returns done:true once the
 * turn has completed (pending entry gone). */
static void handle_progress(struct evhttp_request *req, void *arg)
{
    sc_channel_t *ch = arg;
    web_data_t *wd = ch->data;

    if (!check_auth(req, wd)) {
        send_json_error(req, 401, "Unauthorized");
        return;
    }

    struct evkeyvalq params;
    const char *uri = evhttp_request_get_uri(req);
    evhttp_parse_query(uri, &params);
    const char *pid = evhttp_find_header(&params, "id");
    const char *after_s = evhttp_find_header(&params, "after");
    int after = after_s ? atoi(after_s) : 0;
    if (after < 0) after = 0;

    cJSON *j = cJSON_CreateObject();
    cJSON *lines = cJSON_AddArrayToObject(j, "lines");
    int found = 0, next = after;

    if (pid && pid[0]) {
        pthread_mutex_lock(&wd->pending_lock);
        for (web_pending_t *cur = wd->pending_head; cur; cur = cur->next) {
            if (!cur->progress_id || strcmp(cur->progress_id, pid) != 0)
                continue;
            found = 1;
            for (int i = after; i < cur->progress_count; i++)
                cJSON_AddItemToArray(lines,
                                     cJSON_CreateString(cur->progress[i]));
            next = cur->progress_count;
            break;
        }
        pthread_mutex_unlock(&wd->pending_lock);
    }
    cJSON_AddNumberToObject(j, "next", next);
    cJSON_AddBoolToObject(j, "done", !found);
    evhttp_clear_headers(&params);

    char *str = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    struct evbuffer *buf = evbuffer_new();
    evbuffer_add(buf, str, strlen(str));
    free(str);
    evhttp_add_header(evhttp_request_get_output_headers(req),
                       "Content-Type", "application/json");
    evhttp_send_reply(req, 200, "OK", buf);
    evbuffer_free(buf);
}

/* GET /api/ui-config — UI bootstrap info (authed). Currently just the
 * optional live-stream URL; the UI hides the Live toggle when unset. */
static void handle_ui_config(struct evhttp_request *req, void *arg)
{
    sc_channel_t *ch = arg;
    web_data_t *wd = ch->data;

    if (!check_auth(req, wd)) {
        send_json_error(req, 401, "Unauthorized");
        return;
    }

    cJSON *j = cJSON_CreateObject();
    if (wd->embed_stream_url && wd->embed_stream_url[0])
        cJSON_AddStringToObject(j, "stream_url", wd->embed_stream_url);
    char *str = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);

    struct evbuffer *buf = evbuffer_new();
    evbuffer_add(buf, str, strlen(str));
    free(str);
    evhttp_add_header(evhttp_request_get_output_headers(req),
                       "Content-Type", "application/json");
    evhttp_send_reply(req, 200, "OK", buf);
    evbuffer_free(buf);
}

/* ---- Image attachments ---------------------------------------------- */

static int web_is_image_ext(const char *name)
{
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;
    return strcasecmp(dot, ".jpg") == 0 || strcasecmp(dot, ".jpeg") == 0 ||
           strcasecmp(dot, ".png") == 0;
}

/* Resolve a path (absolute or workspace-relative) and confine it to the
 * workspace. Returns malloc'd workspace-RELATIVE path, or NULL. */
static char *web_confine_image(const char *workspace, const char *path)
{
    if (!workspace || !path || !path[0]) return NULL;
    if (!web_is_image_ext(path)) return NULL;

    char joined[PATH_MAX];
    if (path[0] == '/')
        snprintf(joined, sizeof(joined), "%s", path);
    else
        snprintf(joined, sizeof(joined), "%s/%s", workspace, path);

    char *resolved = realpath(joined, NULL);
    if (!resolved) return NULL;
    char *ws = realpath(workspace, NULL);
    if (!ws) { free(resolved); return NULL; }

    size_t wlen = strlen(ws);
    char *rel = NULL;
    if (strncmp(resolved, ws, wlen) == 0 && resolved[wlen] == '/') {
        struct stat st;
        if (stat(resolved, &st) == 0 && S_ISREG(st.st_mode))
            rel = sc_strdup(resolved + wlen + 1);
    }
    free(ws);
    free(resolved);
    return rel;
}

static void attach_add(cJSON *arr, const char *rel)
{
    if (!rel || cJSON_GetArraySize(arr) >= WEB_ATTACH_MAX) return;
    for (cJSON *it = arr->child; it; it = it->next)
        if (cJSON_IsString(it) && strcmp(it->valuestring, rel) == 0)
            return;
    cJSON_AddItemToArray(arr, cJSON_CreateString(rel));
}

/* Scan one workspace subdir for images newer than `since`. */
static void attach_scan_dir(cJSON *arr, const char *workspace,
                             const char *sub, time_t since)
{
    char dir_path[PATH_MAX];
    snprintf(dir_path, sizeof(dir_path), "%s/%s", workspace, sub);
    DIR *d = opendir(dir_path);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.' || !web_is_image_ext(de->d_name)) continue;
        char fpath[PATH_MAX];
        snprintf(fpath, sizeof(fpath), "%s/%s", dir_path, de->d_name);
        struct stat st;
        if (stat(fpath, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (st.st_mtime < since) continue;
        char rel[PATH_MAX];
        snprintf(rel, sizeof(rel), "%s/%s", sub, de->d_name);
        attach_add(arr, rel);
    }
    closedir(d);
}

/* Collect image attachments for a finished turn: images mentioned in
 * the response text (resolved + confined to the workspace) plus any
 * image written under camera/ or camera/motion since the turn began. */
static cJSON *collect_attachments(web_data_t *wd, web_pending_t *wp,
                                   const char *text)
{
    cJSON *arr = cJSON_CreateArray();
    if (!wd->workspace) return arr;

    /* Paths mentioned in the response text */
    if (text) {
        const char *p = text;
        while (*p && cJSON_GetArraySize(arr) < WEB_ATTACH_MAX) {
            const char *dot = strstr(p, ".");
            if (!dot) break;
            if (strncasecmp(dot, ".jpg", 4) == 0 ||
                strncasecmp(dot, ".jpeg", 5) == 0 ||
                strncasecmp(dot, ".png", 4) == 0) {
                const char *end = dot;
                while (*end && *end != ' ' && *end != '\n' && *end != ')' &&
                       *end != ']' && *end != '"' && *end != '\'' &&
                       *end != ',')
                    end++;
                const char *start = dot;
                while (start > text) {
                    char c = *(start - 1);
                    if (c == ' ' || c == '\n' || c == '(' || c == '[' ||
                        c == '"' || c == '\'' || c == '`' || c == ',')
                        break;
                    start--;
                }
                if (end > start && end - start < PATH_MAX - 1) {
                    char cand[PATH_MAX];
                    snprintf(cand, sizeof(cand), "%.*s",
                             (int)(end - start), start);
                    char *rel = web_confine_image(wd->workspace, cand);
                    if (rel) { attach_add(arr, rel); free(rel); }
                }
                p = end;
            } else {
                p = dot + 1;
            }
        }
    }

    /* Fresh captures from this turn */
    if (wp) {
        attach_scan_dir(arr, wd->workspace, "camera", wp->turn_start);
        attach_scan_dir(arr, wd->workspace, "camera/motion", wp->turn_start);
    }
    return arr;
}

/* GET /api/media?path=<workspace-relative image> — serve a captured
 * image. Same bearer auth as the rest of the API; path is confined to
 * the workspace and must have an image extension. */
static void handle_media(struct evhttp_request *req, void *arg)
{
    sc_channel_t *ch = arg;
    web_data_t *wd = ch->data;

    if (!check_auth(req, wd)) {
        send_json_error(req, 401, "Unauthorized");
        return;
    }

    struct evkeyvalq params;
    const char *uri = evhttp_request_get_uri(req);
    evhttp_parse_query(uri, &params);
    const char *path = evhttp_find_header(&params, "path");

    char *rel = path ? web_confine_image(wd->workspace, path) : NULL;
    if (!rel) {
        evhttp_clear_headers(&params);
        send_json_error(req, 404, "Image not found");
        return;
    }

    char full[PATH_MAX];
    snprintf(full, sizeof(full), "%s/%s", wd->workspace, rel);
    struct stat st;
    FILE *f = NULL;
    if (stat(full, &st) != 0 || st.st_size > 10 * 1024 * 1024 ||
        !(f = fopen(full, "rb"))) {
        free(rel);
        evhttp_clear_headers(&params);
        send_json_error(req, 404, "Image not readable");
        return;
    }

    struct evbuffer *buf = evbuffer_new();
    char chunk[8192];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0)
        evbuffer_add(buf, chunk, n);
    fclose(f);

    const char *dot = strrchr(rel, '.');
    const char *ctype = (dot && strcasecmp(dot, ".png") == 0)
                        ? "image/png" : "image/jpeg";
    evhttp_add_header(evhttp_request_get_output_headers(req),
                       "Content-Type", ctype);
    evhttp_send_reply(req, 200, "OK", buf);
    evbuffer_free(buf);
    free(rel);
    evhttp_clear_headers(&params);
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

    pthread_mutex_lock(&ch->security_mutex);
    sc_rate_limiter_t *rl = ch->rate_limiter;
    pthread_mutex_unlock(&ch->security_mutex);
    if (rl) {
        char ip[64];
        web_client_ip(req, ip, sizeof(ip));
        const char *auth = evhttp_find_header(
            evhttp_request_get_input_headers(req), "Authorization");
        if (!sc_web_check_message_rate_limit(rl, ip, auth)) {
            SC_LOG_WARN(WEB_TAG, "Rate limited /api/message from %s", ip);
            send_json_error(req, 429, "Rate limit exceeded");
            return;
        }
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
    cJSON *response_format = cJSON_GetObjectItem(json, "response_format");
    if (!message || !message[0]) {
        cJSON_Delete(json);
        send_json_error(req, 400, "Missing 'message' field");
        return;
    }
    if (response_format && !cJSON_IsObject(response_format)) {
        cJSON_Delete(json);
        send_json_error(req, 400, "'response_format' must be an object");
        return;
    }

    /* Generate request ID */
    char request_id[64];
    char *rid = sc_generate_id();
    snprintf(request_id, sizeof(request_id), "%s", rid ? rid : "unknown");
    free(rid);

    /* Store pending request */
    const char *progress_id = sc_json_get_string(json, "progress_id", NULL);
    if (add_pending(wd, request_id, req, response_format != NULL,
                    progress_id) != 0) {
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

    /* If context was provided (from delegate tool), prepend it */
    const char *delegate_ctx = sc_json_get_string(json, "context", NULL);
    char *full_message = NULL;
    if (delegate_ctx && delegate_ctx[0]) {
        sc_strbuf_t cm;
        sc_strbuf_init(&cm);
        sc_strbuf_appendf(&cm, "[Context from dispatcher]\n%s\n\n%s",
                          delegate_ctx, message);
        full_message = sc_strbuf_finish(&cm);
    }

    /* Publish inbound message to bus.
     * sender_id = "web" (no user auth), chat_id = request_id for response routing */
    /* Session-isolation routing (see sc_web_compute_isolation in web.h). */
    char ns_id[17];
    int isolated = sc_web_compute_isolation(wd->isolation_pattern, sess_name,
                                             session_key, ns_id);
    if (isolated)
        SC_LOG_DEBUG("web", "isolated session='%s' ns='%s'",
                     sess_name ? sess_name : "(null)", ns_id);

    /* Per-turn tool-workspace override (Phase 5). An orchestration layer
     * sends this when materialize succeeded for a run, so delegate tools
     * (read_file, list_dir, exec, git) get scoped to the run-specific
     * repo checkout for the duration of this turn. Gateway validates the
     * path before swapping; an invalid value silently falls through to
     * the agent's full workspace (caller's bug, not ours to enforce). */
    const char *run_repo_dir = sc_json_get_string(json, "run_repo_dir", NULL);

    sc_inbound_msg_t *inbound = sc_inbound_msg_new(
        SC_CHANNEL_WEB, "web", request_id,
        full_message ? full_message : message, session_key,
        response_format, isolated, isolated ? ns_id : NULL,
        run_repo_dir);
    free(full_message);
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

/* Handle GET /api/audit — return recent audit log entries as JSON array */
static void handle_audit(struct evhttp_request *req, void *arg)
{
    sc_channel_t *ch = arg;
    web_data_t *wd = ch->data;

    if (!check_auth(req, wd)) {
        send_json_error(req, 401, "Unauthorized");
        return;
    }

    /* Parse query params */
    struct evkeyvalq params;
    const char *uri = evhttp_request_get_uri(req);
    evhttp_parse_query(uri, &params);
    const char *limit_str = evhttp_find_header(&params, "limit");
    const char *since_str = evhttp_find_header(&params, "since");
    int limit = limit_str ? atoi(limit_str) : 50;
    double since_ts = since_str ? strtod(since_str, NULL) : 0;
    evhttp_clear_headers(&params);

    char *json = sc_audit_read_recent(limit, since_ts);
    if (!json) json = sc_strdup("[]");

    struct evbuffer *buf = evbuffer_new();
    evbuffer_add(buf, json, strlen(json));
    free(json);

    evhttp_add_header(evhttp_request_get_output_headers(req),
                       "Content-Type", "application/json");
    evhttp_send_reply(req, 200, "OK", buf);
    evbuffer_free(buf);
}

/* Handle GET /api/health */
static void handle_health(struct evhttp_request *req, void *arg)
{
    sc_channel_t *ch = arg;
    web_data_t *wd = ch->data;

    /* Require bearer auth (audit 4298ba13 / P2-5): health exposed version,
     * uptime, and pending count — same sensitivity as other API routes. */
    if (!check_auth(req, wd)) {
        send_json_error(req, 401, "Unauthorized");
        return;
    }

    time_t now = time(NULL);
    long uptime_secs = (long)(now - wd->start_time);

    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "status", "ok");
    cJSON_AddStringToObject(j, "version", SC_VERSION);
    cJSON_AddNumberToObject(j, "uptime_secs", uptime_secs);
    cJSON_AddNumberToObject(j, "pending_requests", wd->pending_count);

    char *str = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);

    struct evbuffer *buf = evbuffer_new();
    evbuffer_add(buf, str, strlen(str));
    free(str);

    evhttp_add_header(evhttp_request_get_output_headers(req),
                       "Content-Type", "application/json");
    evhttp_send_reply(req, 200, "OK", buf);
    evbuffer_free(buf);
}

/* Handle POST /api/memory/log — append to daily notes from external caller */
static void handle_memory_log(struct evhttp_request *req, void *arg)
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

    if (!wd->workspace) {
        send_json_error(req, 500, "Workspace not configured");
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

    const char *content = sc_json_get_string(json, "content", NULL);
    if (!content || !content[0]) {
        cJSON_Delete(json);
        send_json_error(req, 400, "Missing 'content' field");
        return;
    }

    /* Append to daily notes */
    sc_memory_t *mem = sc_memory_new(wd->workspace);
    if (!mem) {
        cJSON_Delete(json);
        send_json_error(req, 500, "Failed to open memory store");
        return;
    }

    int rc = sc_memory_append_today(mem, content);
    sc_memory_free(mem);
    cJSON_Delete(json);

    if (rc != 0) {
        send_json_error(req, 500, "Failed to write to daily notes");
        return;
    }

    SC_LOG_INFO(WEB_TAG, "Memory log entry appended via API");

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "ok");
    char *str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);

    struct evbuffer *buf = evbuffer_new();
    evbuffer_add(buf, str, strlen(str));
    free(str);

    evhttp_add_header(evhttp_request_get_output_headers(req),
                       "Content-Type", "application/json");
    evhttp_send_reply(req, 200, "OK", buf);
    evbuffer_free(buf);
}

#if SC_ENABLE_MEMORY_SEARCH
/* Handle POST /api/memory/search — query agent's FTS5 memory index */
static void handle_memory_search(struct evhttp_request *req, void *arg)
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

    if (!wd->workspace) {
        send_json_error(req, 500, "Workspace not configured");
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

    const char *query = sc_json_get_string(json, "query", NULL);
    if (!query || !query[0]) {
        cJSON_Delete(json);
        send_json_error(req, 400, "Missing 'query' field");
        return;
    }
    int max_results = sc_json_get_int(json, "max_results", 10);
    if (max_results < 1) max_results = 1;
    if (max_results > 50) max_results = 50;

    /* Open index from workspace */
    sc_strbuf_t db_path;
    sc_strbuf_init(&db_path);
    sc_strbuf_appendf(&db_path, "%s/memory/search.db", wd->workspace);
    char *db = sc_strbuf_finish(&db_path);

    sc_memory_index_t *idx = sc_memory_index_new(db);
    free(db);
    if (!idx) {
        cJSON_Delete(json);
        send_json_error(req, 500, "Memory search index not available");
        return;
    }

    {
        sc_strbuf_t mem_sb;
        sc_strbuf_init(&mem_sb);
        sc_strbuf_appendf(&mem_sb, "%s/memory", wd->workspace);
        char *mem_dir = sc_strbuf_finish(&mem_sb);
        sc_memory_index_defer_rebuild(idx, mem_dir);
        free(mem_dir);

        sc_strbuf_t ctx_sb;
        sc_strbuf_init(&ctx_sb);
        sc_strbuf_appendf(&ctx_sb, "%s/context", wd->workspace);
        char *ctx_dir = sc_strbuf_finish(&ctx_sb);
        struct stat ctx_st;
        if (stat(ctx_dir, &ctx_st) == 0 && S_ISDIR(ctx_st.st_mode))
            sc_memory_index_defer_ctx_rebuild(idx, ctx_dir);
        free(ctx_dir);
    }

    int count = 0;
    sc_memory_search_result_t *results =
        sc_memory_index_search(idx, query, max_results, &count);
    sc_memory_index_free(idx);
    cJSON_Delete(json);

    /* Build JSON response */
    cJSON *resp = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(resp, "results");
    for (int i = 0; i < count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "source", results[i].source);
        cJSON_AddStringToObject(item, "snippet", results[i].snippet);
        cJSON_AddNumberToObject(item, "rank", results[i].rank);
        cJSON_AddItemToArray(arr, item);
    }
    cJSON_AddNumberToObject(resp, "count", count);
    sc_memory_search_results_free(results, count);

    char *str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);

    struct evbuffer *buf = evbuffer_new();
    evbuffer_add(buf, str, strlen(str));
    free(str);

    evhttp_add_header(evhttp_request_get_output_headers(req),
                       "Content-Type", "application/json");
    evhttp_send_reply(req, 200, "OK", buf);
    evbuffer_free(buf);
}
#endif /* SC_ENABLE_MEMORY_SEARCH */

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
        cJSON_AddItemToObject(j, "attachments",
                              collect_attachments(wd, wp, resp.text));
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

    /* Verbose progress messages feed the /api/progress poll buffer of
     * the in-flight request instead of completing it. */
    if (msg->is_progress) {
        append_progress(wd, msg->chat_id, msg->content);
        return 0;
    }
    if (pending_requires_final_response(wd, msg->chat_id) && !msg->is_final_response)
        return 0;

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

    if (!wd->bearer_token || !wd->bearer_token[0]) {
        SC_LOG_ERROR(WEB_TAG, "bearer_token is required — refusing to start "
                    "unauthenticated web API (audit 4298ba13)");
        return -1;
    }

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
    evhttp_set_cb(wd->http, "/api/memory/log", handle_memory_log, self);
#if SC_ENABLE_MEMORY_SEARCH
    evhttp_set_cb(wd->http, "/api/memory/search", handle_memory_search, self);
#endif
    evhttp_set_cb(wd->http, "/api/audit", handle_audit, self);
    evhttp_set_cb(wd->http, "/api/progress", handle_progress, self);
    evhttp_set_cb(wd->http, "/api/media", handle_media, self);
    evhttp_set_cb(wd->http, "/api/ui-config", handle_ui_config, self);
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
        char *holder = sc_port_holder(wd->port);
        SC_LOG_ERROR(WEB_TAG, "Failed to bind to %s:%d%s%s%s",
                     wd->bind_addr, wd->port,
                     wd->auto_port ? " (tried +10)" : "",
                     holder ? " — port held by " : "",
                     holder ? holder : "");
        if (!holder)
            SC_LOG_INFO(WEB_TAG, "Run 'ss -ltnp' to see what holds port %d; "
                        "set web.auto_port=true to bind the next free port",
                        wd->port);
        free(holder);
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
    wd->start_time = time(NULL);

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
        free(wd->isolation_pattern);
        free(wd->bind_addr);
        free(wd->tls_cert);
        free(wd->tls_key);
        free(wd->workspace);
        free(wd->embed_stream_url);
        pthread_mutex_destroy(&wd->pending_lock);
        free(wd);
    }
    self->data = NULL;
    sc_channel_base_free(self);
}

sc_channel_t *sc_channel_web_new(sc_web_config_t *cfg, sc_bus_t *bus,
                                  const char *workspace)
{
    if (!cfg) return NULL;

    sc_channel_t *ch = calloc(1, sizeof(*ch));
    if (!ch) return NULL;

    web_data_t *wd = calloc(1, sizeof(*wd));
    if (!wd) { free(ch); return NULL; }

    wd->bearer_token = sc_strdup(cfg->bearer_token);
    wd->isolation_pattern = (cfg->isolation_pattern && cfg->isolation_pattern[0])
        ? sc_strdup(cfg->isolation_pattern) : NULL;
    wd->bind_addr = sc_strdup(cfg->bind_addr && cfg->bind_addr[0]
                               ? cfg->bind_addr : "127.0.0.1");
    wd->port = cfg->port > 0 ? cfg->port : SC_DEFAULT_WEB_PORT;
    wd->auto_port = cfg->auto_port;
    wd->request_timeout_secs = cfg->request_timeout_secs;
    wd->tls_cert = sc_strdup(cfg->tls_cert);
    wd->tls_key = sc_strdup(cfg->tls_key);
    /* Expand ~ once here: the media/attachment paths (opendir/realpath)
     * need an absolute path, unlike the memory helpers which expand
     * internally. */
    wd->workspace = workspace ? sc_expand_home(workspace) : NULL;
    wd->embed_stream_url = sc_strdup(cfg->embed_stream_url);
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
