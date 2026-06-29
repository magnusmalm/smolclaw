/*
 * test_xai_oauth.c — tasks 2.1/2.2 xAI Grok OAuth.
 *
 * Covers the pure helpers (base64url, PKCE, JWT exp, refresh decision,
 * authorize-URL build, endpoint validation), the auth.json store
 * (serialize/save/load + 0600 perms), and the HTTP steps (discovery, refresh)
 * against a mock OIDC/token server. The interactive loopback login + live
 * SuperGrok consent are a human gate.
 */

#include "test_main.h"

#include "util/xai_oauth.h"
#include "providers/factory.h"
#include "util/base64.h"
#include "util/sha256.h"
#include "util/str.h"
#include "cJSON.h"
#include "mock_http.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

/* ---- helpers ---- */

static char *jwt_with_exp(long exp)
{
    char payload[64];
    snprintf(payload, sizeof(payload), "{\"exp\":%ld}", exp);
    char *b64 = sc_base64url_encode((const unsigned char *)payload,
                                    strlen(payload));
    sc_strbuf_t sb; sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "header.%s.signature", b64);
    free(b64);
    return sc_strbuf_finish(&sb);
}

static char *make_home(void)
{
    static char tmpl[64];
    snprintf(tmpl, sizeof(tmpl), "/tmp/sc_test_xai_XXXXXX");
    return mkdtemp(tmpl);
}

/* ---- pure helpers ---- */

static void test_base64url(void)
{
    /* Bytes that produce '+' and '/' in standard base64. */
    unsigned char raw[] = { 0xfb, 0xef, 0xbe };
    char *enc = sc_base64url_encode(raw, sizeof(raw));
    ASSERT_NOT_NULL(enc);
    ASSERT(strchr(enc, '+') == NULL, "no '+' in base64url");
    ASSERT(strchr(enc, '/') == NULL, "no '/' in base64url");
    ASSERT(strchr(enc, '=') == NULL, "no padding in base64url");

    size_t out_len = 0;
    unsigned char *dec = sc_base64url_decode(enc, &out_len);
    ASSERT_NOT_NULL(dec);
    ASSERT_INT_EQ((int)out_len, (int)sizeof(raw));
    ASSERT(memcmp(dec, raw, sizeof(raw)) == 0, "base64url round-trips");
    free(enc);
    free(dec);
}

static void test_pkce(void)
{
    char *verifier = NULL, *challenge = NULL;
    ASSERT_INT_EQ(sc_xai_pkce_generate(&verifier, &challenge), 1);
    ASSERT_NOT_NULL(verifier);
    ASSERT_NOT_NULL(challenge);
    /* 32 random bytes → 43-char base64url verifier. */
    ASSERT_INT_EQ((int)strlen(verifier), 43);

    /* challenge must equal base64url(sha256(verifier)). */
    uint8_t hash[32];
    sc_sha256_ctx_t ctx;
    sc_sha256_init(&ctx);
    sc_sha256_update(&ctx, (const uint8_t *)verifier, strlen(verifier));
    sc_sha256_final(&ctx, hash);
    char *expect = sc_base64url_encode(hash, sizeof(hash));
    ASSERT_STR_EQ(challenge, expect);

    free(expect);
    free(verifier);
    free(challenge);
}

static void test_jwt_exp(void)
{
    char *jwt = jwt_with_exp(2000000000L);
    ASSERT(sc_xai_jwt_get_exp(jwt) == 2000000000L, "exp parsed from JWT");
    free(jwt);

    ASSERT(sc_xai_jwt_get_exp("notajwt") == -1, "missing dots → -1");
    ASSERT(sc_xai_jwt_get_exp("a.b.c") == -1, "non-JSON payload → -1");
    ASSERT(sc_xai_jwt_get_exp(NULL) == -1, "NULL → -1");
}

static void test_should_refresh(void)
{
    long now = 1000000;
    ASSERT_INT_EQ(sc_xai_oauth_should_refresh(now + 30, now, 120), 1);
    ASSERT_INT_EQ(sc_xai_oauth_should_refresh(now + 3600, now, 120), 0);
    ASSERT_INT_EQ(sc_xai_oauth_should_refresh(0, now, 120), 0);  /* unknown */
    ASSERT_INT_EQ(sc_xai_oauth_should_refresh(-1, now, 120), 0);
    ASSERT_INT_EQ(sc_xai_oauth_should_refresh(now - 10, now, 120), 1); /* expired */
}

static void test_authorize_url(void)
{
    char *url = sc_xai_oauth_build_authorize_url(
        "https://auth.x.ai/authorize",
        "http://127.0.0.1:56121/callback", "CHAL", "STATE123");
    ASSERT_NOT_NULL(url);
    ASSERT(strstr(url, "response_type=code") != NULL, "has response_type");
    ASSERT(strstr(url, "code_challenge=CHAL") != NULL, "has challenge");
    ASSERT(strstr(url, "code_challenge_method=S256") != NULL, "S256 method");
    ASSERT(strstr(url, "state=STATE123") != NULL, "has state");
    ASSERT(strstr(url, "plan=generic") != NULL, "has plan=generic");
    ASSERT(strstr(url, "referrer=smolclaw") != NULL, "has referrer");
    ASSERT(strstr(url, "redirect_uri=http%3A%2F%2F127.0.0.1") != NULL,
           "redirect_uri is URL-escaped");
    free(url);
}

static void test_validate_endpoint(void)
{
    ASSERT_INT_EQ(sc_xai_oauth_validate_endpoint("https://auth.x.ai/oauth/token"), 1);
    ASSERT_INT_EQ(sc_xai_oauth_validate_endpoint("https://x.ai/token"), 1);
    ASSERT_INT_EQ(sc_xai_oauth_validate_endpoint("https://a.b.x.ai/token"), 1);
    ASSERT_INT_EQ(sc_xai_oauth_validate_endpoint("http://auth.x.ai/token"), 0); /* not https */
    ASSERT_INT_EQ(sc_xai_oauth_validate_endpoint("https://evil.com/token"), 0);
    ASSERT_INT_EQ(sc_xai_oauth_validate_endpoint("https://x.ai.evil.com/t"), 0);
    ASSERT_INT_EQ(sc_xai_oauth_validate_endpoint("https://notx.ai/t"), 0);
    ASSERT_INT_EQ(sc_xai_oauth_validate_endpoint(NULL), 0);
}

/* ---- store ---- */

static void test_store_json_roundtrip(void)
{
    sc_xai_store_t s;
    memset(&s, 0, sizeof(s));
    s.access_token = sc_strdup("ACCESS");
    s.refresh_token = sc_strdup("REFRESH");
    s.token_type = sc_strdup("Bearer");
    s.expires_in = 3600;
    s.authorization_endpoint = sc_strdup("https://auth.x.ai/authorize");
    s.token_endpoint = sc_strdup("https://auth.x.ai/oauth/token");
    s.redirect_uri = sc_strdup("http://127.0.0.1:5/callback");

    char *json = sc_xai_oauth_to_json(&s);
    ASSERT_NOT_NULL(json);

    sc_xai_store_t back;
    ASSERT_INT_EQ(sc_xai_oauth_from_json(json, &back), 1);
    ASSERT_STR_EQ(back.access_token, "ACCESS");
    ASSERT_STR_EQ(back.refresh_token, "REFRESH");
    ASSERT_STR_EQ(back.token_endpoint, "https://auth.x.ai/oauth/token");
    ASSERT_INT_EQ((int)back.expires_in, 3600);

    free(json);
    sc_xai_store_free(&s);
    sc_xai_store_free(&back);

    /* Malformed / wrong shape rejected. */
    sc_xai_store_t junk;
    ASSERT_INT_EQ(sc_xai_oauth_from_json("{}", &junk), 0);
    ASSERT_INT_EQ(sc_xai_oauth_from_json("not json", &junk), 0);
}

static void test_store_save_load_perms(void)
{
    char *home = make_home();
    ASSERT_NOT_NULL(home);
    setenv("SMOLCLAW_HOME", home, 1);

    sc_xai_store_t s;
    memset(&s, 0, sizeof(s));
    s.access_token = sc_strdup("A");
    s.refresh_token = sc_strdup("R");
    s.token_endpoint = sc_strdup("https://auth.x.ai/oauth/token");
    ASSERT_INT_EQ(sc_xai_oauth_save(&s), 0);
    sc_xai_store_free(&s);

    /* 0600 perms. */
    char *path = sc_xai_oauth_store_path();
    ASSERT_NOT_NULL(path);
    struct stat st;
    ASSERT_INT_EQ(stat(path, &st), 0);
    ASSERT_INT_EQ((int)(st.st_mode & 0777), 0600);

    sc_xai_store_t back;
    ASSERT_INT_EQ(sc_xai_oauth_load(&back), 1);
    ASSERT_STR_EQ(back.access_token, "A");
    ASSERT_STR_EQ(back.refresh_token, "R");
    sc_xai_store_free(&back);

    /* logout removes the file. */
    ASSERT_INT_EQ(sc_xai_oauth_logout(), 0);
    ASSERT_INT_EQ(stat(path, &st), -1);

    free(path);
    unsetenv("SMOLCLAW_HOME");
}

/* ---- HTTP steps (mock OIDC/token server) ---- */

static void test_discover_mock(void)
{
    char disc[512];
    snprintf(disc, sizeof(disc),
        "{\"authorization_endpoint\":\"https://auth.x.ai/authorize\","
        "\"token_endpoint\":\"https://auth.x.ai/oauth/token\"}");
    sc_mock_route_t routes[] = {
        { "GET", "/.well-known/openid-configuration", 200, NULL, disc },
    };
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    char *auth_ep = NULL, *token_ep = NULL;
    int rc = sc_xai_oauth_discover(mock->url, &auth_ep, &token_ep);
    ASSERT_INT_EQ(rc, 0);
    ASSERT_STR_EQ(auth_ep, "https://auth.x.ai/authorize");
    ASSERT_STR_EQ(token_ep, "https://auth.x.ai/oauth/token");

    free(auth_ep);
    free(token_ep);
    sc_mock_http_stop(mock);
}

static void test_refresh_mock(void)
{
    sc_mock_route_t routes[] = {
        { "POST", "/token", 200, NULL,
          "{\"access_token\":\"NEW\",\"refresh_token\":\"R2\","
          "\"token_type\":\"Bearer\",\"expires_in\":3600}" },
    };
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    char token_ep[128];
    snprintf(token_ep, sizeof(token_ep), "%s/token", mock->url);

    sc_xai_store_t s;
    memset(&s, 0, sizeof(s));
    int rc = sc_xai_oauth_refresh(token_ep, "R1", &s);
    ASSERT_INT_EQ(rc, 0);
    ASSERT_STR_EQ(s.access_token, "NEW");
    ASSERT_STR_EQ(s.refresh_token, "R2");
    sc_xai_store_free(&s);
    sc_mock_http_stop(mock);
}

static void test_refresh_invalid_grant(void)
{
    sc_mock_route_t routes[] = {
        { "POST", "/token", 400, NULL, "{\"error\":\"invalid_grant\"}" },
    };
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    char token_ep[128];
    snprintf(token_ep, sizeof(token_ep), "%s/token", mock->url);

    sc_xai_store_t s;
    memset(&s, 0, sizeof(s));
    int rc = sc_xai_oauth_refresh(token_ep, "R1", &s);
    ASSERT_INT_EQ(rc, 2);  /* relogin_required */
    /* supplied refresh token preserved as fallback */
    ASSERT_STR_EQ(s.refresh_token, "R1");
    sc_xai_store_free(&s);
    sc_mock_http_stop(mock);
}

/* ---- runtime resolver (no-network happy path) ---- */

static void test_ensure_fresh_not_expiring(void)
{
    char *home = make_home();
    ASSERT_NOT_NULL(home);
    setenv("SMOLCLAW_HOME", home, 1);

    char *jwt = jwt_with_exp((long)time(NULL) + 3600); /* not near expiry */
    sc_xai_store_t s;
    memset(&s, 0, sizeof(s));
    s.access_token = sc_strdup(jwt);
    s.refresh_token = sc_strdup("R");
    s.token_endpoint = sc_strdup("https://auth.x.ai/oauth/token");
    ASSERT_INT_EQ(sc_xai_oauth_save(&s), 0);
    sc_xai_store_free(&s);
    free(jwt);

    char *token = sc_xai_oauth_ensure_fresh_token();
    ASSERT_NOT_NULL(token);
    ASSERT(sc_xai_jwt_get_exp(token) > (long)time(NULL),
           "returned token is the stored, still-valid one");
    free(token);

    sc_xai_oauth_logout();
    unsetenv("SMOLCLAW_HOME");
}

/* Regression: the OAuth-only prefixes route to the OAuth provider but must
 * also be stripped from the model name before it reaches api.x.ai — otherwise
 * the literal `grok-sub/<model>` 400s ("Model not found"). Caught on live
 * SuperGrok acceptance 2026-06-29. */
static void test_strip_oauth_prefix(void)
{
    ASSERT_STR_EQ(sc_model_strip_prefix("grok-sub/grok-4.3"), "grok-4.3");
    ASSERT_STR_EQ(sc_model_strip_prefix("xai-oauth/grok-4.3"), "grok-4.3");
    ASSERT_STR_EQ(sc_model_strip_prefix("grok-oauth/grok-4.3"), "grok-4.3");
    /* Table-driven prefixes still strip; bare names and unknowns pass through. */
    ASSERT_STR_EQ(sc_model_strip_prefix("grok/grok-4.3"), "grok-4.3");
    ASSERT_STR_EQ(sc_model_strip_prefix("grok-4.3"), "grok-4.3");
}

int main(void)
{
    printf("test_xai_oauth:\n");
    RUN_TEST(test_strip_oauth_prefix);
    RUN_TEST(test_base64url);
    RUN_TEST(test_pkce);
    RUN_TEST(test_jwt_exp);
    RUN_TEST(test_should_refresh);
    RUN_TEST(test_authorize_url);
    RUN_TEST(test_validate_endpoint);
    RUN_TEST(test_store_json_roundtrip);
    RUN_TEST(test_store_save_load_perms);
    RUN_TEST(test_discover_mock);
    RUN_TEST(test_refresh_mock);
    RUN_TEST(test_refresh_invalid_grant);
    RUN_TEST(test_ensure_fresh_not_expiring);
    TEST_REPORT();
}
