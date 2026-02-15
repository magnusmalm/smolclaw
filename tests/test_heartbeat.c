/*
 * smolclaw - heartbeat service tests
 * Tests service lifecycle, interval clamping, HEARTBEAT.md prompt building,
 * and handler invocation.
 */

#include "test_main.h"
#include "heartbeat/service.h"
#include "state.h"
#include "util/str.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <event2/event.h>

/* --- Mock handler --- */

static int hb_handler_called;
static char *hb_handler_prompt;
static char *hb_handler_response;

static char *test_hb_handler(const char *prompt, const char *channel,
                              const char *chat_id, void *ctx)
{
    (void)ctx;
    hb_handler_called++;
    free(hb_handler_prompt);
    hb_handler_prompt = sc_strdup(prompt);
    return sc_strdup(hb_handler_response ? hb_handler_response : "HEARTBEAT_OK");
}

static void cleanup_dir(const char *dir)
{
    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", dir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

/* --- Tests --- */

static void test_heartbeat_create(void)
{
    struct event_base *base = event_base_new();

    /* Normal creation */
    sc_heartbeat_service_t *hs = sc_heartbeat_service_new("/tmp/test-ws", 15, 1, base);
    ASSERT_NOT_NULL(hs);
    ASSERT_INT_EQ(hs->interval_min, 15);
    ASSERT_INT_EQ(hs->enabled, 1);
    ASSERT_INT_EQ(hs->running, 0);
    sc_heartbeat_service_free(hs);

    /* Interval below minimum (5) gets clamped */
    hs = sc_heartbeat_service_new("/tmp/test-ws", 2, 1, base);
    ASSERT_NOT_NULL(hs);
    ASSERT_INT_EQ(hs->interval_min, 5);
    sc_heartbeat_service_free(hs);

    /* Interval = 0 gets default (30) */
    hs = sc_heartbeat_service_new("/tmp/test-ws", 0, 1, base);
    ASSERT_NOT_NULL(hs);
    ASSERT_INT_EQ(hs->interval_min, 30);
    sc_heartbeat_service_free(hs);

    event_base_free(base);
}

static void test_heartbeat_start_disabled(void)
{
    struct event_base *base = event_base_new();
    sc_heartbeat_service_t *hs = sc_heartbeat_service_new("/tmp/test-ws", 10, 0, base);
    ASSERT_NOT_NULL(hs);
    ASSERT_INT_EQ(hs->enabled, 0);

    int ret = sc_heartbeat_service_start(hs);
    ASSERT_INT_EQ(ret, 0);
    ASSERT_INT_EQ(hs->running, 0); /* Should not start when disabled */

    sc_heartbeat_service_free(hs);
    event_base_free(base);
}

static void test_heartbeat_start_stop(void)
{
    struct event_base *base = event_base_new();
    sc_heartbeat_service_t *hs = sc_heartbeat_service_new("/tmp/test-ws", 5, 1, base);
    ASSERT_NOT_NULL(hs);

    sc_heartbeat_service_start(hs);
    ASSERT_INT_EQ(hs->running, 1);
    ASSERT_NOT_NULL(hs->timer_event);

    /* Double start should be idempotent */
    sc_heartbeat_service_start(hs);
    ASSERT_INT_EQ(hs->running, 1);

    sc_heartbeat_service_stop(hs);
    ASSERT_INT_EQ(hs->running, 0);
    ASSERT_NULL(hs->timer_event);

    /* Double stop should not crash */
    sc_heartbeat_service_stop(hs);

    sc_heartbeat_service_free(hs);
    event_base_free(base);
}

static void test_heartbeat_handler_fires(void)
{
    char tmpdir[] = "/tmp/sc_test_hb_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    /* Create HEARTBEAT.md in workspace */
    sc_strbuf_t hb_path;
    sc_strbuf_init(&hb_path);
    sc_strbuf_appendf(&hb_path, "%s/HEARTBEAT.md", tmpdir);
    char *hb_file = sc_strbuf_finish(&hb_path);

    FILE *f = fopen(hb_file, "w");
    ASSERT_NOT_NULL(f);
    fprintf(f, "Check server status and report.\n");
    fclose(f);
    free(hb_file);

    struct event_base *base = event_base_new();
    sc_heartbeat_service_t *hs = sc_heartbeat_service_new(tmpdir, 5, 1, base);
    ASSERT_NOT_NULL(hs);

    /* Set up handler */
    hb_handler_called = 0;
    free(hb_handler_prompt);
    hb_handler_prompt = NULL;
    hb_handler_response = "HEARTBEAT_OK";
    sc_heartbeat_service_set_handler(hs, test_hb_handler, NULL);

    /* Start the service (creates 5-min timer) */
    sc_heartbeat_service_start(hs);
    ASSERT_INT_EQ(hs->running, 1);

    /* Hack timer to fire in 50ms instead of 5 minutes */
    if (hs->timer_event) {
        event_del(hs->timer_event);
        struct timeval short_tv = { .tv_sec = 0, .tv_usec = 50000 };
        event_add(hs->timer_event, &short_tv);
    }

    /* Run event loop briefly */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 }; /* 200ms */
    event_base_loopexit(base, &tv);
    event_base_dispatch(base);

    ASSERT(hb_handler_called > 0, "Heartbeat handler should have been called");
    ASSERT_NOT_NULL(hb_handler_prompt);

    /* Prompt should contain HEARTBEAT.md content */
    ASSERT(strstr(hb_handler_prompt, "Check server status") != NULL,
           "Prompt should contain HEARTBEAT.md content");
    ASSERT(strstr(hb_handler_prompt, "Heartbeat Check") != NULL,
           "Prompt should contain heartbeat header");

    sc_heartbeat_service_free(hs);
    event_base_free(base);
    free(hb_handler_prompt);
    hb_handler_prompt = NULL;
    cleanup_dir(tmpdir);
}

static void test_heartbeat_no_file(void)
{
    char tmpdir[] = "/tmp/sc_test_hb_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    /* No HEARTBEAT.md — handler should NOT be called */
    struct event_base *base = event_base_new();
    sc_heartbeat_service_t *hs = sc_heartbeat_service_new(tmpdir, 5, 1, base);
    ASSERT_NOT_NULL(hs);

    hb_handler_called = 0;
    sc_heartbeat_service_set_handler(hs, test_hb_handler, NULL);

    sc_heartbeat_service_start(hs);

    /* Hack timer */
    if (hs->timer_event) {
        event_del(hs->timer_event);
        struct timeval short_tv = { .tv_sec = 0, .tv_usec = 50000 };
        event_add(hs->timer_event, &short_tv);
    }

    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
    event_base_loopexit(base, &tv);
    event_base_dispatch(base);

    /* Handler should NOT be called (no HEARTBEAT.md) */
    ASSERT_INT_EQ(hb_handler_called, 0);

    sc_heartbeat_service_free(hs);
    event_base_free(base);
    cleanup_dir(tmpdir);
}

static void test_heartbeat_null_safety(void)
{
    /* NULL should not crash */
    sc_heartbeat_service_free(NULL);
    sc_heartbeat_service_stop(NULL);
    sc_heartbeat_service_set_bus(NULL, NULL);
    sc_heartbeat_service_set_state(NULL, NULL);
    sc_heartbeat_service_set_handler(NULL, NULL, NULL);

    int ret = sc_heartbeat_service_start(NULL);
    ASSERT_INT_EQ(ret, -1);
}

int main(void)
{
    printf("test_heartbeat\n");

    RUN_TEST(test_heartbeat_create);
    RUN_TEST(test_heartbeat_start_disabled);
    RUN_TEST(test_heartbeat_start_stop);
    RUN_TEST(test_heartbeat_handler_fires);
    RUN_TEST(test_heartbeat_no_file);
    RUN_TEST(test_heartbeat_null_safety);

    TEST_REPORT();
}
