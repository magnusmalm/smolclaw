/*
 * Companion HTTP integration — Layer 0 + Layer 1 against a live web channel.
 */

#include "test_main.h"

#include "channels/web.h"
#include "bus.h"
#include "sc_version.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct curl_buf {
    char *data;
    size_t len;
};

static sc_channel_t *g_ch;
static char g_base[128];
static char g_auth[64];

static size_t curl_write(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct curl_buf *b = userdata;
    size_t n = size * nmemb;
    char *p = realloc(b->data, b->len + n + 1);
    if (!p) return 0;
    b->data = p;
    memcpy(b->data + b->len, ptr, n);
    b->len += n;
    b->data[b->len] = '\0';
    return n;
}

static long http_request(const char *method, const char *url,
                          const char *auth, const char *ctype,
                          const void *body, size_t body_len,
                          struct curl_buf *out)
{
    CURL *curl = curl_easy_init();
    ASSERT_NOT_NULL(curl);
    memset(out, 0, sizeof(*out));

    struct curl_slist *hdrs = NULL;
    if (auth) {
        char h[512];
        snprintf(h, sizeof(h), "Authorization: %s", auth);
        hdrs = curl_slist_append(hdrs, h);
    }
    if (ctype)
        hdrs = curl_slist_append(hdrs, ctype);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L);
    if (body && body_len > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body_len);
    }

    CURLcode rc = curl_easy_perform(curl);
    long code = 0;
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    ASSERT_INT_EQ((int)rc, (int)CURLE_OK);
    return code;
}

static void fixture_start(void)
{
    static char ws[] = "/tmp/sc_comp_test_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(ws));

    sc_bus_t *bus = sc_bus_create(NULL);
    ASSERT_NOT_NULL(bus);

    sc_web_config_t cfg = {0};
    cfg.bind_addr = "127.0.0.1";
    cfg.port = 37653;
    cfg.auto_port = 1;
    cfg.bearer_token = "test-bearer";

    g_ch = sc_channel_web_new(&cfg, bus, ws);
    ASSERT_NOT_NULL(g_ch);
    ASSERT_INT_EQ(g_ch->start(g_ch), 0);
    usleep(200000);

    snprintf(g_base, sizeof(g_base), "http://127.0.0.1:%d",
             sc_web_channel_port(g_ch));
    snprintf(g_auth, sizeof(g_auth), "Bearer %s", cfg.bearer_token);
}

static void fixture_stop(void)
{
    if (!g_ch) return;
    sc_bus_t *bus = g_ch->bus;
    if (g_ch->is_running(g_ch))
        g_ch->stop(g_ch);
    g_ch->destroy(g_ch);
    sc_bus_destroy(bus);
    g_ch = NULL;
}

static void test_health_authed(void)
{
    struct curl_buf out = {0};
    char url[256];
    snprintf(url, sizeof(url), "%s/api/health", g_base);
    long code = http_request("GET", url, g_auth, NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 200);
    ASSERT(strstr(out.data, "\"status\":\"ok\"") != NULL, "status ok");
    ASSERT(strstr(out.data, SC_VERSION) != NULL, "version field");
    free(out.data);
}

static void test_health_denied(void)
{
    struct curl_buf out = {0};
    char url[256];
    snprintf(url, sizeof(url), "%s/api/health", g_base);
    long code = http_request("GET", url, "Bearer wrong", NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 401);
    ASSERT(strstr(out.data, "\"error\"") != NULL, "error envelope");
    free(out.data);
}

static void test_capabilities(void)
{
    struct curl_buf out = {0};
    char url[256];
    snprintf(url, sizeof(url), "%s/api/companion/capabilities", g_base);
    long code = http_request("GET", url, g_auth, NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 200);
    ASSERT(strstr(out.data, "smolclaw-companion/1") != NULL, "protocol");
    ASSERT(strstr(out.data, "\"snap\":true") != NULL, "snap feature");
    ASSERT(strstr(out.data, "10485760") != NULL, "snap_max_bytes");
    free(out.data);
}

static void test_snap_upload_jpeg(void)
{
    static const unsigned char jpeg[] = {
        0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00,
        0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0xff, 0xd9
    };
    struct curl_buf out = {0};
    char url[256];
    snprintf(url, sizeof(url), "%s/api/companion/snap", g_base);
    long code = http_request("POST", url, g_auth,
        "Content-Type: image/jpeg",
        jpeg, sizeof(jpeg), &out);
    ASSERT_INT_EQ((int)code, 201);
    ASSERT(strstr(out.data, "companion/inbox/") != NULL, "inbox path");
    ASSERT(strstr(out.data, ".jpg") != NULL, "jpg extension");
    ASSERT(strstr(out.data, "\"bytes\":") != NULL, "bytes field");
    free(out.data);
}

static void test_snap_bad_content_type(void)
{
    struct curl_buf out = {0};
    char url[256];
    snprintf(url, sizeof(url), "%s/api/companion/snap", g_base);
    long code = http_request("POST", url, g_auth,
        "Content-Type: image/gif", "GIF89a", 6, &out);
    ASSERT_INT_EQ((int)code, 400);
    ASSERT(strstr(out.data, "unsupported content type") != NULL, "error msg");
    free(out.data);
}

static void test_audit_poll(void)
{
    struct curl_buf out = {0};
    char url[256];
    snprintf(url, sizeof(url), "%s/api/audit?limit=5&since=0", g_base);
    long code = http_request("GET", url, g_auth, NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 200);
    ASSERT(out.data && out.data[0] == '[', "audit returns JSON array");
    free(out.data);
}

static void test_memory_pending_list(void)
{
    struct curl_buf out = {0};
    char url[256];
    snprintf(url, sizeof(url), "%s/api/memory/pending", g_base);
    long code = http_request("GET", url, g_auth, NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 200);
    ASSERT(strstr(out.data, "\"pending\"") != NULL, "pending array");
    free(out.data);
}

static void test_progress_poll(void)
{
    struct curl_buf out = {0};
    char url[256];
    snprintf(url, sizeof(url), "%s/api/progress?id=abc&after=0", g_base);
    long code = http_request("GET", url, g_auth, NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 200);
    ASSERT(strstr(out.data, "\"done\"") != NULL, "done field");
    free(out.data);
}

int main(void)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);

    printf("test_companion_http:\n");
    fixture_start();

    RUN_TEST(test_health_authed);
    RUN_TEST(test_health_denied);
    RUN_TEST(test_capabilities);
    RUN_TEST(test_snap_upload_jpeg);
    RUN_TEST(test_snap_bad_content_type);
    RUN_TEST(test_audit_poll);
    RUN_TEST(test_memory_pending_list);
    RUN_TEST(test_progress_poll);

    fixture_stop();
    curl_global_cleanup();
    TEST_REPORT();
}