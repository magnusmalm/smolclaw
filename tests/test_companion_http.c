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
#include <time.h>
#include <unistd.h>
#include <utime.h>

struct curl_buf {
    char *data;
    size_t len;
};

static sc_channel_t *g_ch;
static char g_base[128];
static char g_auth[64];
static char g_ws[256];

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
    /* Honor $TMPDIR so the test runs under sandboxes that mount /tmp read-only. */
    const char *tmpdir = getenv("TMPDIR");
    snprintf(g_ws, sizeof(g_ws), "%s/sc_comp_test_XXXXXX",
             (tmpdir && tmpdir[0]) ? tmpdir : "/tmp");
    ASSERT_NOT_NULL(mkdtemp(g_ws));
    char *ws = g_ws;

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

/* ---------------- P2.2 library endpoints ---------------- */

#define ID_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define ID_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define TRIAGE_LINE "- reminder | tag1,tag2 | water the plants"

static void today_str(char *month, char *date)
{
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(month, 8, "%Y%m", &tmv);
    strftime(date, 10, "%Y%m%d", &tmv);
}

static void library_fixture(void)
{
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/companion/inbox", g_ws);
    char cmd[600];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", dir);
    ASSERT_INT_EQ(system(cmd), 0);

    char path[600];
    snprintf(path, sizeof(path), "%s/%s.jpg", dir, ID_A);
    FILE *f = fopen(path, "wb");
    ASSERT_NOT_NULL(f);
    fputs("JPEGDATA-A", f);
    fclose(f);
    /* Make A clearly older so B sorts first (newest-first list). */
    struct utimbuf older = { time(NULL) - 3600, time(NULL) - 3600 };
    utime(path, &older);

    snprintf(path, sizeof(path), "%s/%s.jpg", dir, ID_B);
    f = fopen(path, "wb");
    ASSERT_NOT_NULL(f);
    fputs("JPEGDATA-B", f);
    fclose(f);

    char month[8], date[10];
    today_str(month, date);
    snprintf(dir, sizeof(dir), "%s/memory/%s", g_ws, month);
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", dir);
    ASSERT_INT_EQ(system(cmd), 0);
    snprintf(path, sizeof(path), "%s/%s.md", dir, date);
    f = fopen(path, "w");
    ASSERT_NOT_NULL(f);
    fprintf(f, "snap companion/inbox/%s.jpg: test description A\n", ID_A);
    fprintf(f, "- snap-note companion/inbox/%s.jpg | note about A\n", ID_A);
    fprintf(f, "%s\n", TRIAGE_LINE);
    fprintf(f, "unrelated freeform line\n");
    fclose(f);
}

static void test_library_snaps_list(void)
{
    library_fixture();

    struct curl_buf out = {0};
    char url[300];
    snprintf(url, sizeof(url), "%s/api/companion/snaps", g_base);
    long code = http_request("GET", url, g_auth, NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 200);
    char *pa = strstr(out.data, ID_A);
    char *pb = strstr(out.data, ID_B);
    ASSERT(pa != NULL && pb != NULL, "both snaps listed");
    ASSERT(pb < pa, "newest (B) listed first");
    /* The upload test's snap is also present: total >= 3 */
    ASSERT(strstr(out.data, "\"total\":") != NULL, "total field");
    free(out.data);

    /* Unauthorized */
    code = http_request("GET", url, "Bearer wrong", NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 401);
    free(out.data);
}

static void test_library_snaps_image(void)
{
    struct curl_buf out = {0};
    char url[300];
    snprintf(url, sizeof(url), "%s/api/companion/snaps?image=%s",
             g_base, ID_A);
    long code = http_request("GET", url, g_auth, NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 200);
    ASSERT(out.len == 10 && memcmp(out.data, "JPEGDATA-A", 10) == 0,
           "image bytes round-trip");
    free(out.data);

    /* Traversal / malformed ids are rejected before any path is built */
    snprintf(url, sizeof(url),
             "%s/api/companion/snaps?image=..%%2F..%%2Fetc%%2Fpasswd", g_base);
    code = http_request("GET", url, g_auth, NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 400);
    free(out.data);

    snprintf(url, sizeof(url), "%s/api/companion/snaps?image=%s", g_base,
             "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
    code = http_request("GET", url, g_auth, NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 400);
    free(out.data);

    /* Valid id, no such photo */
    snprintf(url, sizeof(url), "%s/api/companion/snaps?image=%s", g_base,
             "0123456789abcdef0123456789abcdef");
    code = http_request("GET", url, g_auth, NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 404);
    free(out.data);
}

static void test_library_notes_list(void)
{
    struct curl_buf out = {0};
    char url[300];
    snprintf(url, sizeof(url), "%s/api/companion/notes?days=2", g_base);
    long code = http_request("GET", url, g_auth, NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 200);
    ASSERT(strstr(out.data, "\"kind\":\"snap\"") != NULL, "snap kind");
    ASSERT(strstr(out.data, "\"kind\":\"snap-note\"") != NULL,
           "snap-note kind");
    ASSERT(strstr(out.data, "\"kind\":\"triage\"") != NULL, "triage kind");
    ASSERT(strstr(out.data, "\"kind\":\"other\"") != NULL, "other kind");
    ASSERT(strstr(out.data, "note about A") != NULL, "note text present");
    free(out.data);
}

static void test_library_snap_delete_purges_notes(void)
{
    struct curl_buf out = {0};
    char url[300];
    snprintf(url, sizeof(url),
             "%s/api/companion/snaps?id=%s&purge_notes=1", g_base, ID_A);
    long code = http_request("DELETE", url, g_auth, NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 200);
    ASSERT(strstr(out.data, "\"deleted\":true") != NULL, "deleted flag");
    ASSERT(strstr(out.data, "\"notes_removed\":2") != NULL,
           "both A lines purged");
    free(out.data);

    /* Photo gone from disk */
    char path[600];
    snprintf(path, sizeof(path), "%s/companion/inbox/%s.jpg", g_ws, ID_A);
    ASSERT(access(path, F_OK) != 0, "photo unlinked");

    /* Note lines gone, unrelated lines intact */
    char month[8], date[10];
    today_str(month, date);
    snprintf(path, sizeof(path), "%s/memory/%s/%s.md", g_ws, month, date);
    FILE *f = fopen(path, "r");
    ASSERT_NOT_NULL(f);
    char buf[4096] = {0};
    fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    ASSERT(strstr(buf, ID_A) == NULL, "A lines purged from daily note");
    ASSERT(strstr(buf, TRIAGE_LINE) != NULL, "triage line intact");
    ASSERT(strstr(buf, "unrelated freeform line") != NULL, "other intact");

    /* Second delete: 404, nothing left to purge */
    code = http_request("DELETE", url, g_auth, NULL, NULL, 0, &out);
    ASSERT_INT_EQ((int)code, 404);
    ASSERT(strstr(out.data, "\"notes_removed\":0") != NULL, "idempotent");
    free(out.data);
}

static void test_library_note_delete_exact_line(void)
{
    char month[8], date[10];
    today_str(month, date);

    char body[512];
    snprintf(body, sizeof(body), "{\"date\":\"%s\",\"line\":\"%s\"}",
             date, TRIAGE_LINE);
    struct curl_buf out = {0};
    char url[300];
    snprintf(url, sizeof(url), "%s/api/companion/notes", g_base);
    long code = http_request("DELETE", url, g_auth,
        "Content-Type: application/json", body, strlen(body), &out);
    ASSERT_INT_EQ((int)code, 200);
    ASSERT(strstr(out.data, "\"deleted\":true") != NULL, "note deleted");
    free(out.data);

    /* Same line again: exact-match-or-nothing → 404 */
    code = http_request("DELETE", url, g_auth,
        "Content-Type: application/json", body, strlen(body), &out);
    ASSERT_INT_EQ((int)code, 404);
    free(out.data);

    /* Malformed date rejected */
    snprintf(body, sizeof(body), "{\"date\":\"20xx0101\",\"line\":\"x\"}");
    code = http_request("DELETE", url, g_auth,
        "Content-Type: application/json", body, strlen(body), &out);
    ASSERT_INT_EQ((int)code, 400);
    free(out.data);

    /* Unrelated line survived the exact-line delete */
    char path[600];
    snprintf(path, sizeof(path), "%s/memory/%s/%s.md", g_ws, month, date);
    FILE *f = fopen(path, "r");
    ASSERT_NOT_NULL(f);
    char buf[4096] = {0};
    fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    ASSERT(strstr(buf, "unrelated freeform line") != NULL, "other intact");
    ASSERT(strstr(buf, TRIAGE_LINE) == NULL, "triage line gone");
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
    RUN_TEST(test_library_snaps_list);
    RUN_TEST(test_library_snaps_image);
    RUN_TEST(test_library_notes_list);
    RUN_TEST(test_library_snap_delete_purges_notes);
    RUN_TEST(test_library_note_delete_exact_line);

    fixture_stop();
    curl_global_cleanup();
    TEST_REPORT();
}