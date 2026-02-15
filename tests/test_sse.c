/*
 * smolclaw - SSE parser tests
 */

#include "test_main.h"
#include "util/sse.h"
#include "util/str.h"

#include <string.h>

/* Test context: collects all events into a buffer */
typedef struct {
    sc_strbuf_t events;
    int count;
} test_ctx_t;

static void test_event_cb(const char *data, void *ctx)
{
    test_ctx_t *tc = ctx;
    sc_strbuf_append(&tc->events, data);
    sc_strbuf_append(&tc->events, "|");
    tc->count++;
}

static void test_sse_basic(void)
{
    test_ctx_t ctx = {0};
    sc_strbuf_init(&ctx.events);

    sc_sse_parser_t p;
    sc_sse_init(&p, test_event_cb, &ctx);

    const char *input = "data: hello\n\ndata: world\n\n";
    sc_sse_feed(&p, input, strlen(input));

    char *result = sc_strbuf_finish(&ctx.events);
    ASSERT_STR_EQ(result, "hello|world|");
    ASSERT_INT_EQ(ctx.count, 2);

    free(result);
    sc_sse_free(&p);
}

static void test_sse_no_space_after_colon(void)
{
    test_ctx_t ctx = {0};
    sc_strbuf_init(&ctx.events);

    sc_sse_parser_t p;
    sc_sse_init(&p, test_event_cb, &ctx);

    const char *input = "data:nospace\n\n";
    sc_sse_feed(&p, input, strlen(input));

    char *result = sc_strbuf_finish(&ctx.events);
    ASSERT_STR_EQ(result, "nospace|");

    free(result);
    sc_sse_free(&p);
}

static void test_sse_done_marker(void)
{
    test_ctx_t ctx = {0};
    sc_strbuf_init(&ctx.events);

    sc_sse_parser_t p;
    sc_sse_init(&p, test_event_cb, &ctx);

    const char *input = "data: {\"text\":\"hi\"}\n\ndata: [DONE]\n\n";
    sc_sse_feed(&p, input, strlen(input));

    char *result = sc_strbuf_finish(&ctx.events);
    ASSERT_STR_EQ(result, "{\"text\":\"hi\"}|[DONE]|");
    ASSERT_INT_EQ(ctx.count, 2);

    free(result);
    sc_sse_free(&p);
}

static void test_sse_chunked_feed(void)
{
    /* Simulate chunked delivery: data split across multiple feed calls */
    test_ctx_t ctx = {0};
    sc_strbuf_init(&ctx.events);

    sc_sse_parser_t p;
    sc_sse_init(&p, test_event_cb, &ctx);

    sc_sse_feed(&p, "dat", 3);
    sc_sse_feed(&p, "a: ch", 5);
    sc_sse_feed(&p, "unked\n\n", 7);

    char *result = sc_strbuf_finish(&ctx.events);
    ASSERT_STR_EQ(result, "chunked|");
    ASSERT_INT_EQ(ctx.count, 1);

    free(result);
    sc_sse_free(&p);
}

static void test_sse_crlf(void)
{
    /* Test \r\n line endings */
    test_ctx_t ctx = {0};
    sc_strbuf_init(&ctx.events);

    sc_sse_parser_t p;
    sc_sse_init(&p, test_event_cb, &ctx);

    const char *input = "data: crlf\r\n\r\n";
    sc_sse_feed(&p, input, strlen(input));

    char *result = sc_strbuf_finish(&ctx.events);
    ASSERT_STR_EQ(result, "crlf|");

    free(result);
    sc_sse_free(&p);
}

static void test_sse_ignores_non_data(void)
{
    /* event: and id: lines should be ignored */
    test_ctx_t ctx = {0};
    sc_strbuf_init(&ctx.events);

    sc_sse_parser_t p;
    sc_sse_init(&p, test_event_cb, &ctx);

    const char *input = "event: message\nid: 123\nretry: 5000\ndata: actual\n\n";
    sc_sse_feed(&p, input, strlen(input));

    char *result = sc_strbuf_finish(&ctx.events);
    ASSERT_STR_EQ(result, "actual|");
    ASSERT_INT_EQ(ctx.count, 1);

    free(result);
    sc_sse_free(&p);
}

static void test_sse_json_payload(void)
{
    test_ctx_t ctx = {0};
    sc_strbuf_init(&ctx.events);

    sc_sse_parser_t p;
    sc_sse_init(&p, test_event_cb, &ctx);

    const char *input =
        "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n"
        "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n\n";
    sc_sse_feed(&p, input, strlen(input));

    ASSERT_INT_EQ(ctx.count, 2);

    char *result = sc_strbuf_finish(&ctx.events);
    ASSERT(strstr(result, "Hello") != NULL, "Should contain Hello");
    ASSERT(strstr(result, "world") != NULL, "Should contain world");

    free(result);
    sc_sse_free(&p);
}

int main(void)
{
    printf("test_sse\n");

    RUN_TEST(test_sse_basic);
    RUN_TEST(test_sse_no_space_after_colon);
    RUN_TEST(test_sse_done_marker);
    RUN_TEST(test_sse_chunked_feed);
    RUN_TEST(test_sse_crlf);
    RUN_TEST(test_sse_ignores_non_data);
    RUN_TEST(test_sse_json_payload);

    TEST_REPORT();
}
