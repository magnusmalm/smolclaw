/*
 * util/xai_oauth.c - xAI Grok OAuth (SuperGrok subscription) provider.
 * See util/xai_oauth.h and docs/design/xai-grok-oauth.md.
 *
 * Compiled only when SC_ENABLE_XAI_OAUTH is set (default n).
 */

#include "sc_features.h"

#if SC_ENABLE_XAI_OAUTH

#include "util/xai_oauth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <curl/curl.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>

#include "cJSON.h"
#include "constants.h"
#include "logger.h"
#include "util/str.h"
#include "util/base64.h"
#include "util/sha256.h"
#include "util/curl_common.h"

#define TAG "xai-oauth"

/* --- Constants. Re-verified 2026-06-29 against xAI's official CLI installer
 *     (x.ai/cli/install.sh) and the reference PKCE impl
 *     ysnock404/opencode-grok-auth (src/constants.ts + src/oauth.ts): client_id,
 *     issuer, scope, plan=generic and the 120s refresh skew all match. referrer
 *     is a free-form per-client identifier (reference uses "hermes-agent"). The
 *     authorize/token endpoints are resolved via OIDC discovery, not hardcoded,
 *     so they self-correct if xAI moves them. Live SuperGrok login still gates
 *     the end-to-end flow. --- */
#define XAI_CLIENT_ID  "b1a00492-073a-47ea-816f-4c329264a828"
#define XAI_ISSUER     "https://auth.x.ai"
#define XAI_SCOPE      "openid profile email offline_access grok-cli:access api:access"
#define XAI_REFRESH_SKEW 120          /* refresh within 2 min of expiry */
#define XAI_LOGIN_TIMEOUT_DEFAULT 180 /* seconds to wait for the callback */

/* ====================================================================== *
 *  Small local helpers                                                    *
 * ====================================================================== */

static int rand_bytes(unsigned char *buf, size_t n)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t got = fread(buf, 1, n, f);
    fclose(f);
    return got == n;
}

static char *iso_now(void)
{
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return sc_strdup(ts);
}

static char *hex_random(size_t nbytes)
{
    unsigned char *raw = malloc(nbytes);
    if (!raw) return NULL;
    if (!rand_bytes(raw, nbytes)) { free(raw); return NULL; }
    char *hex = malloc(nbytes * 2 + 1);
    if (!hex) { free(raw); return NULL; }
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < nbytes; i++) {
        hex[i * 2] = d[raw[i] >> 4];
        hex[i * 2 + 1] = d[raw[i] & 0xF];
    }
    hex[nbytes * 2] = '\0';
    free(raw);
    return hex;
}

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *ud)
{
    sc_strbuf_t *sb = ud;
    size_t total = size * nmemb;
    char *tmp = malloc(total + 1);
    if (!tmp) return 0;
    memcpy(tmp, ptr, total);
    tmp[total] = '\0';
    sc_strbuf_append(sb, tmp);
    free(tmp);
    return total;
}

/* HTTP GET → body (caller frees) or NULL; *status set to HTTP code. */
static char *http_get(const char *url, long *status)
{
    CURL *curl = sc_curl_init();
    if (!curl) return NULL;
    sc_strbuf_t sb; sc_strbuf_init(&sb);
    /* https in production (issuer is https); http permitted for loopback mock
     * servers in tests. The production issuer constant is always https. */
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https,http");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sb);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);
    if (status) *status = code;
    if (res != CURLE_OK) { sc_strbuf_free(&sb); return NULL; }
    return sc_strbuf_finish(&sb);
}

/* HTTP POST (form-encoded) → body (caller frees) or NULL; *status set. */
static char *http_post_form(const char *url, const char *body, long *status)
{
    CURL *curl = sc_curl_init();
    if (!curl) return NULL;
    sc_strbuf_t sb; sc_strbuf_init(&sb);
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs,
                             "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https,http");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sb);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if (status) *status = code;
    if (res != CURLE_OK) { sc_strbuf_free(&sb); return NULL; }
    return sc_strbuf_finish(&sb);
}

/* URL-escape via a throwaway curl handle. Caller frees. */
static char *url_escape(const char *s)
{
    CURL *curl = sc_curl_init();
    if (!curl) return NULL;
    char *enc = curl_easy_escape(curl, s ? s : "", 0);
    char *out = enc ? sc_strdup(enc) : NULL;
    if (enc) curl_free(enc);
    curl_easy_cleanup(curl);
    return out;
}

/* ====================================================================== *
 *  Pure helpers                                                           *
 * ====================================================================== */

int sc_xai_pkce_generate(char **verifier, char **challenge)
{
    if (!verifier || !challenge) return 0;
    *verifier = NULL; *challenge = NULL;

    unsigned char raw[32];
    if (!rand_bytes(raw, sizeof(raw))) return 0;
    char *v = sc_base64url_encode(raw, sizeof(raw)); /* 43-char verifier */
    if (!v) return 0;

    uint8_t hash[32];
    sc_sha256_ctx_t ctx;
    sc_sha256_init(&ctx);
    sc_sha256_update(&ctx, (const uint8_t *)v, strlen(v));
    sc_sha256_final(&ctx, hash);
    char *c = sc_base64url_encode(hash, sizeof(hash));
    if (!c) { free(v); return 0; }

    *verifier = v;
    *challenge = c;
    return 1;
}

long sc_xai_jwt_get_exp(const char *jwt)
{
    if (!jwt) return -1;
    const char *dot1 = strchr(jwt, '.');
    if (!dot1) return -1;
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return -1;

    size_t plen = (size_t)(dot2 - (dot1 + 1));
    char *payload = malloc(plen + 1);
    if (!payload) return -1;
    memcpy(payload, dot1 + 1, plen);
    payload[plen] = '\0';

    size_t dlen = 0;
    unsigned char *decoded = sc_base64url_decode(payload, &dlen);
    free(payload);
    if (!decoded) return -1;

    cJSON *o = cJSON_Parse((const char *)decoded);
    free(decoded);
    if (!o) return -1;

    long exp = -1;
    cJSON *e = cJSON_GetObjectItemCaseSensitive(o, "exp");
    if (e && cJSON_IsNumber(e)) exp = (long)e->valuedouble;
    cJSON_Delete(o);
    return exp;
}

int sc_xai_oauth_should_refresh(long exp, long now, int skew)
{
    if (exp <= 0) return 0;           /* unknown → don't refresh-loop */
    return exp <= now + skew;
}

char *sc_xai_oauth_build_authorize_url(const char *auth_endpoint,
                                       const char *redirect_uri,
                                       const char *challenge,
                                       const char *state)
{
    if (!auth_endpoint || !redirect_uri || !challenge || !state) return NULL;

    char *e_redirect = url_escape(redirect_uri);
    char *e_challenge = url_escape(challenge);
    char *e_state = url_escape(state);
    char *e_scope = url_escape(XAI_SCOPE);
    char *e_client = url_escape(XAI_CLIENT_ID);
    if (!e_redirect || !e_challenge || !e_state || !e_scope || !e_client) {
        free(e_redirect); free(e_challenge); free(e_state);
        free(e_scope); free(e_client);
        return NULL;
    }

    sc_strbuf_t sb; sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb,
        "%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s"
        "&state=%s&code_challenge=%s&code_challenge_method=S256"
        "&plan=generic&referrer=smolclaw",
        auth_endpoint, e_client, e_redirect, e_scope, e_state, e_challenge);

    free(e_redirect); free(e_challenge); free(e_state);
    free(e_scope); free(e_client);
    return sc_strbuf_finish(&sb);
}

int sc_xai_oauth_validate_endpoint(const char *url)
{
    if (!url) return 0;
    if (strncmp(url, "https://", 8) != 0) return 0;
    const char *host = url + 8;
    /* Host runs until '/', ':', '?' or end. */
    size_t hlen = 0;
    while (host[hlen] && host[hlen] != '/' && host[hlen] != ':' &&
           host[hlen] != '?')
        hlen++;
    if (hlen == 0) return 0;

    static const char *root = "x.ai";
    size_t rlen = 4;
    if (hlen == rlen && strncasecmp(host, root, rlen) == 0) return 1; /* x.ai */
    if (hlen > rlen + 1) {
        /* must end with ".x.ai" */
        const char *suffix = host + hlen - (rlen + 1);
        if (suffix[0] == '.' && strncasecmp(suffix + 1, root, rlen) == 0)
            return 1;
    }
    return 0;
}

/* ====================================================================== *
 *  Store (de)serialization + persistence                                 *
 * ====================================================================== */

void sc_xai_store_free(sc_xai_store_t *s)
{
    if (!s) return;
    free(s->access_token);
    free(s->refresh_token);
    free(s->id_token);
    free(s->token_type);
    free(s->authorization_endpoint);
    free(s->token_endpoint);
    free(s->redirect_uri);
    free(s->last_refresh);
    memset(s, 0, sizeof(*s));
}

char *sc_xai_oauth_store_path(void)
{
    char *home = sc_get_home_dir();
    if (!home) return NULL;
    sc_strbuf_t sb; sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/auth.json", home);
    free(home);
    return sc_strbuf_finish(&sb);
}

char *sc_xai_oauth_to_json(const sc_xai_store_t *s)
{
    if (!s) return NULL;
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    cJSON_AddNumberToObject(root, "version", 1);
    cJSON *providers = cJSON_AddObjectToObject(root, "providers");
    cJSON *x = cJSON_AddObjectToObject(providers, "xai-oauth");
    cJSON_AddStringToObject(x, "auth_mode", "oauth_pkce");

    cJSON *t = cJSON_AddObjectToObject(x, "tokens");
    if (s->access_token)  cJSON_AddStringToObject(t, "access_token", s->access_token);
    if (s->refresh_token) cJSON_AddStringToObject(t, "refresh_token", s->refresh_token);
    if (s->id_token)      cJSON_AddStringToObject(t, "id_token", s->id_token);
    cJSON_AddStringToObject(t, "token_type", s->token_type ? s->token_type : "Bearer");
    cJSON_AddNumberToObject(t, "expires_in", (double)s->expires_in);

    cJSON *d = cJSON_AddObjectToObject(x, "discovery");
    if (s->authorization_endpoint)
        cJSON_AddStringToObject(d, "authorization_endpoint", s->authorization_endpoint);
    if (s->token_endpoint)
        cJSON_AddStringToObject(d, "token_endpoint", s->token_endpoint);

    if (s->redirect_uri) cJSON_AddStringToObject(x, "redirect_uri", s->redirect_uri);
    if (s->last_refresh) cJSON_AddStringToObject(x, "last_refresh", s->last_refresh);

    char *out = cJSON_Print(root);
    cJSON_Delete(root);
    return out;
}

static char *dup_str_field(const cJSON *o, const char *key)
{
    cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    return (v && cJSON_IsString(v)) ? sc_strdup(v->valuestring) : NULL;
}

int sc_xai_oauth_from_json(const char *json, sc_xai_store_t *out)
{
    if (!out) return 0;
    memset(out, 0, sizeof(*out)); /* zero up front so failure leaves it safe to free */
    if (!json) return 0;
    cJSON *root = cJSON_Parse(json);
    if (!root) return 0;

    cJSON *providers = cJSON_GetObjectItemCaseSensitive(root, "providers");
    cJSON *x = providers ? cJSON_GetObjectItemCaseSensitive(providers, "xai-oauth")
                         : NULL;
    if (!x || !cJSON_IsObject(x)) { cJSON_Delete(root); return 0; }

    cJSON *t = cJSON_GetObjectItemCaseSensitive(x, "tokens");
    if (t) {
        out->access_token  = dup_str_field(t, "access_token");
        out->refresh_token = dup_str_field(t, "refresh_token");
        out->id_token      = dup_str_field(t, "id_token");
        out->token_type    = dup_str_field(t, "token_type");
        cJSON *ei = cJSON_GetObjectItemCaseSensitive(t, "expires_in");
        if (ei && cJSON_IsNumber(ei)) out->expires_in = (long)ei->valuedouble;
    }
    cJSON *d = cJSON_GetObjectItemCaseSensitive(x, "discovery");
    if (d) {
        out->authorization_endpoint = dup_str_field(d, "authorization_endpoint");
        out->token_endpoint = dup_str_field(d, "token_endpoint");
    }
    out->redirect_uri = dup_str_field(x, "redirect_uri");
    out->last_refresh = dup_str_field(x, "last_refresh");

    cJSON_Delete(root);
    return 1;
}

int sc_xai_oauth_save(const sc_xai_store_t *s)
{
    char *path = sc_xai_oauth_store_path();
    if (!path) return -1;
    char *json = sc_xai_oauth_to_json(s);
    if (!json) { free(path); return -1; }

    sc_strbuf_t tb; sc_strbuf_init(&tb);
    sc_strbuf_appendf(&tb, "%s.tmp.%d", path, (int)getpid());
    char *tmp = sc_strbuf_finish(&tb);

    int rc = -1;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        size_t len = strlen(json);
        ssize_t w = write(fd, json, len);
        if (fchmod(fd, 0600) != 0) { /* best-effort */ }
        close(fd);
        if (w == (ssize_t)len && rename(tmp, path) == 0)
            rc = 0;
        else
            unlink(tmp);
    }
    if (rc == 0)
        SC_LOG_DEBUG(TAG, "saved auth.json (0600)");
    else
        SC_LOG_ERROR(TAG, "failed to write %s: %s", path, strerror(errno));

    free(tmp);
    free(json);
    free(path);
    return rc;
}

int sc_xai_oauth_load(sc_xai_store_t *out)
{
    if (!out) return 0;
    memset(out, 0, sizeof(*out)); /* safe to sc_xai_store_free even on failure */
    char *path = sc_xai_oauth_store_path();
    if (!path) return 0;
    FILE *f = fopen(path, "r");
    free(path);
    if (!f) return 0;

    sc_strbuf_t sb; sc_strbuf_init(&sb);
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf) - 1, f)) > 0) {
        buf[n] = '\0';
        sc_strbuf_append(&sb, buf);
    }
    fclose(f);
    char *json = sc_strbuf_finish(&sb);
    int rc = json ? sc_xai_oauth_from_json(json, out) : 0;
    free(json);
    return rc;
}

int sc_xai_oauth_logout(void)
{
    char *path = sc_xai_oauth_store_path();
    if (!path) return -1;
    int rc = unlink(path);
    free(path);
    if (rc != 0 && errno == ENOENT) rc = 0; /* already gone */
    return rc;
}

/* ====================================================================== *
 *  HTTP steps                                                             *
 * ====================================================================== */

int sc_xai_oauth_discover(const char *issuer, char **auth_ep, char **token_ep)
{
    if (!issuer || !auth_ep || !token_ep) return -1;
    *auth_ep = NULL; *token_ep = NULL;

    sc_strbuf_t sb; sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/.well-known/openid-configuration", issuer);
    char *url = sc_strbuf_finish(&sb);

    long status = 0;
    char *body = http_get(url, &status);
    free(url);
    if (!body || status < 200 || status >= 300) {
        free(body);
        return -1;
    }
    cJSON *o = cJSON_Parse(body);
    free(body);
    if (!o) return -1;
    *auth_ep = dup_str_field(o, "authorization_endpoint");
    *token_ep = dup_str_field(o, "token_endpoint");
    cJSON_Delete(o);
    return (*auth_ep && *token_ep) ? 0 : -1;
}

/* Parse a token-endpoint JSON response into *out (preserves any existing
 * refresh_token if the server omits one). */
static int parse_token_response(const char *body, sc_xai_store_t *out)
{
    cJSON *o = cJSON_Parse(body);
    if (!o) return -1;
    char *access = dup_str_field(o, "access_token");
    if (!access) { cJSON_Delete(o); return -1; }

    free(out->access_token);
    out->access_token = access;

    char *rt = dup_str_field(o, "refresh_token");
    if (rt) { free(out->refresh_token); out->refresh_token = rt; }

    char *idt = dup_str_field(o, "id_token");
    if (idt) { free(out->id_token); out->id_token = idt; }

    char *tt = dup_str_field(o, "token_type");
    if (tt) { free(out->token_type); out->token_type = tt; }

    cJSON *ei = cJSON_GetObjectItemCaseSensitive(o, "expires_in");
    if (ei && cJSON_IsNumber(ei)) out->expires_in = (long)ei->valuedouble;

    cJSON_Delete(o);
    return 0;
}

int sc_xai_oauth_exchange_code(const char *token_ep, const char *code,
                               const char *verifier, const char *redirect_uri,
                               sc_xai_store_t *out)
{
    if (!token_ep || !code || !verifier || !redirect_uri || !out) return -1;
    char *e_code = url_escape(code);
    char *e_verifier = url_escape(verifier);
    char *e_redirect = url_escape(redirect_uri);
    char *e_client = url_escape(XAI_CLIENT_ID);
    if (!e_code || !e_verifier || !e_redirect || !e_client) {
        free(e_code); free(e_verifier); free(e_redirect); free(e_client);
        return -1;
    }
    sc_strbuf_t sb; sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb,
        "grant_type=authorization_code&code=%s&redirect_uri=%s"
        "&client_id=%s&code_verifier=%s",
        e_code, e_redirect, e_client, e_verifier);
    char *body = sc_strbuf_finish(&sb);
    free(e_code); free(e_verifier); free(e_redirect); free(e_client);

    long status = 0;
    char *resp = http_post_form(token_ep, body, &status);
    free(body);
    if (!resp) return -1;
    int rc = (status >= 200 && status < 300) ? parse_token_response(resp, out) : -1;
    free(resp);
    return rc;
}

int sc_xai_oauth_refresh(const char *token_ep, const char *refresh_token,
                         sc_xai_store_t *out)
{
    if (!token_ep || !refresh_token || !out) return 1;
    char *e_rt = url_escape(refresh_token);
    char *e_client = url_escape(XAI_CLIENT_ID);
    if (!e_rt || !e_client) { free(e_rt); free(e_client); return 1; }
    sc_strbuf_t sb; sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb,
        "grant_type=refresh_token&refresh_token=%s&client_id=%s",
        e_rt, e_client);
    char *body = sc_strbuf_finish(&sb);
    free(e_rt); free(e_client);

    /* Preserve the supplied refresh token as the fallback. */
    if (!out->refresh_token) out->refresh_token = sc_strdup(refresh_token);

    long status = 0;
    char *resp = http_post_form(token_ep, body, &status);
    free(body);
    if (!resp) return 1;                              /* transport error */
    int rc;
    if (status == 400 || status == 401) rc = 2;       /* invalid_grant → relogin */
    else if (status >= 200 && status < 300)
        rc = parse_token_response(resp, out) == 0 ? 0 : 1;
    else rc = 1;
    free(resp);
    return rc;
}

/* ====================================================================== *
 *  Runtime resolver                                                       *
 * ====================================================================== */

char *sc_xai_oauth_ensure_fresh_token(void)
{
    sc_xai_store_t s;
    if (!sc_xai_oauth_load(&s)) {
        SC_LOG_ERROR(TAG, "no xAI OAuth credential — run `smolclaw auth login xai`");
        return NULL;
    }
    if (!s.access_token) { sc_xai_store_free(&s); return NULL; }

    long exp = sc_xai_jwt_get_exp(s.access_token);
    long now = (long)time(NULL);

    if (sc_xai_oauth_should_refresh(exp, now, XAI_REFRESH_SKEW)) {
        if (!s.token_endpoint ||
            !sc_xai_oauth_validate_endpoint(s.token_endpoint)) {
            SC_LOG_ERROR(TAG, "stored token endpoint failed origin validation");
            sc_xai_store_free(&s);
            return NULL;
        }
        if (!s.refresh_token) {
            SC_LOG_ERROR(TAG, "token expiring and no refresh_token — re-login");
            sc_xai_store_free(&s);
            return NULL;
        }
        int rc = sc_xai_oauth_refresh(s.token_endpoint, s.refresh_token, &s);
        if (rc == 0) {
            free(s.last_refresh);
            s.last_refresh = iso_now();
            sc_xai_oauth_save(&s);
            SC_LOG_INFO(TAG, "refreshed xAI OAuth token");
        } else if (exp > now) {
            /* Refresh failed but the current token is not hard-expired — let
             * xAI be the authority and use it anyway. */
            SC_LOG_WARN(TAG, "refresh failed (rc=%d); using current token", rc);
        } else {
            SC_LOG_ERROR(TAG, "refresh failed and token expired — re-login");
            sc_xai_store_free(&s);
            return NULL;
        }
    }

    char *token = sc_strdup(s.access_token);
    sc_xai_store_free(&s);
    return token;
}

/* ====================================================================== *
 *  Interactive login (loopback PKCE) — the human-gated path               *
 * ====================================================================== */

typedef struct {
    struct event_base *base;
    char *expected_state;
    char *code;     /* captured authorization code */
    int   got;      /* 1 = code received, -1 = error/mismatch */
} callback_ctx_t;

static void callback_handler(struct evhttp_request *req, void *arg)
{
    callback_ctx_t *cb = arg;
    const char *uri = evhttp_request_get_uri(req);
    const char *q = uri ? strchr(uri, '?') : NULL;

    struct evkeyvalq params;
    memset(&params, 0, sizeof(params));
    const char *code = NULL, *state = NULL;
    if (q && evhttp_parse_query_str(q + 1, &params) == 0) {
        code = evhttp_find_header(&params, "code");
        state = evhttp_find_header(&params, "state");
    }

    const char *msg;
    if (code && state && cb->expected_state &&
        strcmp(state, cb->expected_state) == 0) {
        cb->code = sc_strdup(code);
        cb->got = 1;
        msg = "<html><body><h2>smolclaw: login complete.</h2>"
              "You can close this tab.</body></html>";
    } else {
        cb->got = -1;
        msg = "<html><body><h2>smolclaw: login failed (state mismatch).</h2>"
              "</body></html>";
    }

    struct evbuffer *out = evhttp_request_get_output_buffer(req);
    if (out) {
        evbuffer_add_printf(out, "%s", msg);
        evhttp_add_header(evhttp_request_get_output_headers(req),
                          "Content-Type", "text/html");
        evhttp_send_reply(req, HTTP_OK, "OK", out);
    }
    evhttp_clear_headers(&params);
    if (cb->base) event_base_loopbreak(cb->base);
}

static int is_remote_session(void)
{
    if (getenv("SMOLCLAW_NO_BROWSER")) return 1;
    if (getenv("SSH_CONNECTION") || getenv("SSH_CLIENT")) return 1;
    const char *term = getenv("TERM");
    if (term && strcmp(term, "dumb") == 0) return 1;
    return 0;
}

static void open_browser(const char *url)
{
    /* Best-effort; never blocks. */
    sc_strbuf_t sb; sc_strbuf_init(&sb);
#if defined(__APPLE__)
    sc_strbuf_appendf(&sb, "open '%s' >/dev/null 2>&1 &", url);
#else
    sc_strbuf_appendf(&sb, "xdg-open '%s' >/dev/null 2>&1 &", url);
#endif
    char *cmd = sc_strbuf_finish(&sb);
    if (cmd) { int r = system(cmd); (void)r; free(cmd); }
}

static int do_login(int no_browser, int timeout_secs)
{
    int rc = 1;
    char *auth_ep = NULL, *token_ep = NULL;
    char *verifier = NULL, *challenge = NULL, *state = NULL, *url = NULL;
    char *redirect = NULL;
    struct event_base *base = NULL;
    struct evhttp *http = NULL;
    callback_ctx_t cb;
    memset(&cb, 0, sizeof(cb));

    if (sc_xai_oauth_discover(XAI_ISSUER, &auth_ep, &token_ep) != 0) {
        fprintf(stderr, "auth: OIDC discovery failed (%s)\n", XAI_ISSUER);
        goto done;
    }
    if (!sc_xai_oauth_validate_endpoint(auth_ep) ||
        !sc_xai_oauth_validate_endpoint(token_ep)) {
        fprintf(stderr, "auth: discovery returned non-x.ai endpoints\n");
        goto done;
    }
    if (!sc_xai_pkce_generate(&verifier, &challenge)) {
        fprintf(stderr, "auth: PKCE generation failed\n");
        goto done;
    }
    state = hex_random(16);
    if (!state) goto done;

    base = event_base_new();
    if (!base) goto done;
    http = evhttp_new(base);
    if (!http) goto done;

    struct evhttp_bound_socket *bound =
        evhttp_bind_socket_with_handle(http, "127.0.0.1", 0);
    if (!bound) {
        fprintf(stderr, "auth: could not bind loopback callback server\n");
        goto done;
    }
    evutil_socket_t fd = evhttp_bound_socket_get_fd(bound);
    struct sockaddr_in sin;
    socklen_t slen = sizeof(sin);
    getsockname(fd, (struct sockaddr *)&sin, &slen);
    int port = ntohs(sin.sin_port);

    sc_strbuf_t rb; sc_strbuf_init(&rb);
    sc_strbuf_appendf(&rb, "http://127.0.0.1:%d/callback", port);
    redirect = sc_strbuf_finish(&rb);

    cb.base = base;
    cb.expected_state = state;
    evhttp_set_cb(http, "/callback", callback_handler, &cb);

    url = sc_xai_oauth_build_authorize_url(auth_ep, redirect, challenge, state);
    if (!url) goto done;

    int remote = no_browser || is_remote_session();
    printf("\nOpen this URL in a browser to authorize smolclaw with your "
           "Grok subscription:\n\n  %s\n\n", url);
    if (!remote) {
        printf("(attempting to open your browser…)\n");
        open_browser(url);
    } else {
        printf("(remote session detected — open the URL on your workstation; "
               "the callback returns to this host)\n");
    }
    printf("Waiting for the callback (timeout %ds)…\n", timeout_secs);

    struct timeval tv = { timeout_secs, 0 };
    event_base_loopexit(base, &tv);
    event_base_dispatch(base);

    if (cb.got != 1 || !cb.code) {
        fprintf(stderr, "auth: no authorization code received "
                        "(timeout or state mismatch)\n");
        goto done;
    }

    sc_xai_store_t store;
    memset(&store, 0, sizeof(store));
    if (sc_xai_oauth_exchange_code(token_ep, cb.code, verifier, redirect,
                                   &store) != 0) {
        fprintf(stderr, "auth: token exchange failed\n");
        sc_xai_store_free(&store);
        goto done;
    }
    store.authorization_endpoint = sc_strdup(auth_ep);
    store.token_endpoint = sc_strdup(token_ep);
    store.redirect_uri = sc_strdup(redirect);
    store.last_refresh = iso_now();
    if (sc_xai_oauth_save(&store) != 0) {
        fprintf(stderr, "auth: could not save tokens\n");
        sc_xai_store_free(&store);
        goto done;
    }
    sc_xai_store_free(&store);
    printf("\nLogged in. xAI Grok OAuth credential stored.\n");
    rc = 0;

done:
    if (http) evhttp_free(http);
    if (base) event_base_free(base);
    free(cb.code);
    free(auth_ep); free(token_ep);
    free(verifier); free(challenge); free(state);
    free(redirect); free(url);
    return rc;
}

/* ====================================================================== *
 *  CLI: smolclaw auth ...                                                 *
 * ====================================================================== */

static int do_status(void)
{
    sc_xai_store_t s;
    if (!sc_xai_oauth_load(&s) || !s.access_token) {
        printf("xAI OAuth: not logged in (run `smolclaw auth login xai`)\n");
        sc_xai_store_free(&s);
        return 1;
    }
    long exp = sc_xai_jwt_get_exp(s.access_token);
    long now = (long)time(NULL);
    if (exp <= 0) {
        printf("xAI OAuth: logged in (token expiry unknown)\n");
    } else if (exp <= now) {
        printf("xAI OAuth: token EXPIRED %lds ago — will refresh on next use\n",
               now - exp);
    } else {
        printf("xAI OAuth: valid (expires in %ld min)\n", (exp - now) / 60);
    }
    if (s.last_refresh) printf("  last refresh: %s\n", s.last_refresh);
    sc_xai_store_free(&s);
    return 0;
}

static int do_refresh_cmd(void)
{
    sc_xai_store_t s;
    if (!sc_xai_oauth_load(&s) || !s.refresh_token) {
        fprintf(stderr, "auth: no stored refresh token — run login first\n");
        sc_xai_store_free(&s);
        return 1;
    }
    if (!s.token_endpoint || !sc_xai_oauth_validate_endpoint(s.token_endpoint)) {
        fprintf(stderr, "auth: stored token endpoint failed validation\n");
        sc_xai_store_free(&s);
        return 1;
    }
    int rc = sc_xai_oauth_refresh(s.token_endpoint, s.refresh_token, &s);
    if (rc == 0) {
        free(s.last_refresh);
        s.last_refresh = iso_now();
        sc_xai_oauth_save(&s);
        printf("auth: refreshed.\n");
    } else if (rc == 2) {
        fprintf(stderr, "auth: refresh rejected (invalid_grant) — re-login.\n");
    } else {
        fprintf(stderr, "auth: refresh failed.\n");
    }
    sc_xai_store_free(&s);
    return rc == 0 ? 0 : 1;
}

int sc_cmd_auth(int argc, char **argv)
{
    /* argv: [smolclaw, auth, <action>, [provider], [--no-browser] [--timeout N]] */
    if (argc < 3) {
        fprintf(stderr,
            "Usage: smolclaw auth <login|status|logout|refresh> [xai] "
            "[--no-browser] [--timeout N]\n");
        return 1;
    }
    const char *action = argv[2];

    int no_browser = 0;
    int timeout = XAI_LOGIN_TIMEOUT_DEFAULT;
    const char *provider = "xai";
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--no-browser") == 0) no_browser = 1;
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            timeout = atoi(argv[++i]);
            if (timeout <= 0) timeout = XAI_LOGIN_TIMEOUT_DEFAULT;
        } else if (argv[i][0] != '-') {
            provider = argv[i];
        }
    }
    if (strcmp(provider, "xai") != 0 && strcmp(provider, "grok") != 0 &&
        strcmp(provider, "xai-oauth") != 0 && strcmp(provider, "grok-oauth") != 0) {
        fprintf(stderr, "auth: only the 'xai' provider is supported\n");
        return 1;
    }

    if (strcmp(action, "login") == 0)   return do_login(no_browser, timeout);
    if (strcmp(action, "status") == 0)  return do_status();
    if (strcmp(action, "logout") == 0) {
        int rc = sc_xai_oauth_logout();
        printf(rc == 0 ? "auth: logged out.\n" : "auth: logout failed.\n");
        return rc == 0 ? 0 : 1;
    }
    if (strcmp(action, "refresh") == 0) return do_refresh_cmd();

    fprintf(stderr, "auth: unknown action '%s'\n", action);
    return 1;
}

#endif /* SC_ENABLE_XAI_OAUTH */
