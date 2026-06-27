/*
 * smolclaw - streaming inline tool-call buffer tests (Phase 1.6)
 */
#include "test_main.h"
#include "providers/stream_buffer.h"
#include "providers/types.h"
#include "util/str.h"

#include <string.h>

typedef struct {
    sc_strbuf_t text;
    int ends;
} recorder_t;

static void rec_cb(const sc_stream_event_t *ev, void *ctx)
{
    recorder_t *r = ctx;
    if (!ev) { r->ends++; return; }
    if (ev->type == SC_STREAM_TEXT && ev->data)
        sc_strbuf_append(&r->text, ev->data);
}

static void feed(sc_stream_buffer_t *sb, const char *s)
{
    sc_stream_event_t ev = {0};
    ev.type = SC_STREAM_TEXT;
    ev.data = s;
    sc_stream_buffer_cb(&ev, sb);
}

static void test_looks_like_tool_call(void)
{
    ASSERT(sc_stream_looks_like_tool_call("{\"name\":\"x\",\"arguments\":{}}"),
           "name+arguments is a tool call");
    ASSERT(sc_stream_looks_like_tool_call("  {\"name\":\"x\",\"args\":[]}"),
           "leading ws + args alias");
    ASSERT(sc_stream_looks_like_tool_call("{\"name\":\"x\",\"parameters\":{}}"),
           "parameters alias");
    ASSERT_INT_EQ(sc_stream_looks_like_tool_call("hello"), 0);
    ASSERT_INT_EQ(sc_stream_looks_like_tool_call("{\"foo\":1}"), 0);
    ASSERT_INT_EQ(sc_stream_looks_like_tool_call(NULL), 0);
}

static void test_buffer_suppresses_tool_call(void)
{
    recorder_t r = {0}; sc_strbuf_init(&r.text);
    sc_stream_buffer_t *sb = sc_stream_buffer_new(rec_cb, &r);
    ASSERT_NOT_NULL(sb);

    feed(sb, "{\"name\":");
    feed(sb, "\"read_file\",\"arguments\":{}}");
    sc_stream_buffer_cb(NULL, sb);   /* end of stream */

    ASSERT_INT_EQ((int)r.text.len, 0);   /* raw JSON not emitted to channel */
    ASSERT_INT_EQ(r.ends, 1);

    sc_stream_buffer_free(sb);
    sc_strbuf_free(&r.text);
}

static void test_buffer_passes_prose(void)
{
    recorder_t r = {0}; sc_strbuf_init(&r.text);
    sc_stream_buffer_t *sb = sc_stream_buffer_new(rec_cb, &r);

    feed(sb, "Hello ");
    feed(sb, "world");
    sc_stream_buffer_cb(NULL, sb);

    ASSERT_STR_EQ(r.text.data ? r.text.data : "", "Hello world");
    ASSERT_INT_EQ(r.ends, 1);

    sc_stream_buffer_free(sb);
    sc_strbuf_free(&r.text);
}

static void test_buffer_flushes_non_tool_json(void)
{
    recorder_t r = {0}; sc_strbuf_init(&r.text);
    sc_stream_buffer_t *sb = sc_stream_buffer_new(rec_cb, &r);

    feed(sb, "{not a tool call");
    sc_stream_buffer_cb(NULL, sb);

    ASSERT_STR_EQ(r.text.data ? r.text.data : "", "{not a tool call");
    ASSERT_INT_EQ(r.ends, 1);

    sc_stream_buffer_free(sb);
    sc_strbuf_free(&r.text);
}

static void test_buffer_finish_idempotent(void)
{
    recorder_t r = {0}; sc_strbuf_init(&r.text);
    sc_stream_buffer_t *sb = sc_stream_buffer_new(rec_cb, &r);

    feed(sb, "hi");
    sc_stream_buffer_cb(NULL, sb);   /* end via NULL event */
    sc_stream_buffer_finish(sb);     /* explicit finish — must be a no-op */

    ASSERT_INT_EQ(r.ends, 1);        /* end forwarded exactly once */

    sc_stream_buffer_free(sb);
    sc_strbuf_free(&r.text);
}

int main(void)
{
    printf("test_stream_buffer\n");

    RUN_TEST(test_looks_like_tool_call);
    RUN_TEST(test_buffer_suppresses_tool_call);
    RUN_TEST(test_buffer_passes_prose);
    RUN_TEST(test_buffer_flushes_non_tool_json);
    RUN_TEST(test_buffer_finish_idempotent);

    TEST_REPORT();
}
