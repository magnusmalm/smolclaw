/*
 * test_doctor_local.c — task 4.6 `doctor --local` capability probing.
 *
 * Covers the pure helpers (report (de)serialization, cache path sanitization,
 * inline-JSON detection) and the provider-driven probe against a mock provider
 * (no network). Live acceptance against a real provider is a human gate.
 */

#include "test_main.h"

#include "doctor_local.h"
#include "providers/types.h"
#include "util/str.h"
#include "cJSON.h"
#include "sc_features.h"

#include <stdlib.h>
#include <string.h>

/* ---- mock provider ---- */

static sc_llm_response_t *mk_resp(const char *content)
{
    sc_llm_response_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->content = sc_strdup(content ? content : "");
    r->finish_reason = sc_strdup("stop");
    r->http_status = 200;
    r->usage.cost_usd = -1.0;
    return r;
}

static sc_llm_response_t *mock_chat(sc_provider_t *self,
                                    sc_llm_message_t *msgs, int msg_count,
                                    sc_tool_definition_t *tools, int tool_count,
                                    const char *model, cJSON *options)
{
    (void)self; (void)model; (void)options;
    (void)tools;
    const char *content = (msg_count > 0 && msgs[0].content) ? msgs[0].content : "";

    /* Tool probe: a tool was offered → respond with one tool call. */
    if (tool_count > 0) {
        sc_llm_response_t *r = mk_resp("");
        if (!r) return NULL;
        r->tool_calls = calloc(1, sizeof(sc_tool_call_t));
        if (r->tool_calls) {
            r->tool_call_count = 1;
            r->tool_calls[0].id = sc_strdup("call_1");
            r->tool_calls[0].name = sc_strdup("ping");
            r->tool_calls[0].arguments = cJSON_CreateObject();
        }
        return r;
    }

    /* JSON probe: prompt mentions JSON → return a JSON object. */
    if (strstr(content, "JSON"))
        return mk_resp("{\"ok\": true}");

    /* Default chat probe. */
    return mk_resp("OK");
}

#if SC_ENABLE_STREAMING
static sc_llm_response_t *mock_chat_stream(sc_provider_t *self,
                                           sc_llm_message_t *msgs, int msg_count,
                                           sc_tool_definition_t *tools, int tool_count,
                                           const char *model, cJSON *options,
                                           sc_stream_cb cb, void *ctx)
{
    (void)self; (void)msgs; (void)msg_count; (void)tools; (void)tool_count;
    (void)model; (void)options;
    if (cb) {
        sc_stream_event_t ev = { .type = SC_STREAM_TEXT, .data = "hi",
                                 .tool_name = NULL, .tool_id = NULL };
        cb(&ev, ctx);
        cb(NULL, ctx); /* end of stream */
    }
    return mk_resp("hi");
}
#endif

static sc_provider_t make_mock_provider(void)
{
    sc_provider_t p;
    memset(&p, 0, sizeof(p));
    p.name = "mock";
    p.chat = mock_chat;
#if SC_ENABLE_STREAMING
    p.chat_stream = mock_chat_stream;
#endif
    return p;
}

/* ---- tests ---- */

static void test_response_is_json(void)
{
    ASSERT(sc_capabilities_response_is_json("{\"ok\": true}") == 1,
           "plain JSON object is detected");
    ASSERT(sc_capabilities_response_is_json("[1, 2, 3]") == 1,
           "plain JSON array is detected");
    ASSERT(sc_capabilities_response_is_json("  \n {\"a\":1}\n ") == 1,
           "surrounding whitespace is tolerated");
    ASSERT(sc_capabilities_response_is_json("```json\n{\"a\":1}\n```") == 1,
           "fenced JSON is detected");
    ASSERT(sc_capabilities_response_is_json("```\n{\"a\":1}\n```") == 1,
           "fenced JSON without a language tag is detected");
    ASSERT(sc_capabilities_response_is_json("Sure! Here is the data.") == 0,
           "prose is not JSON");
    ASSERT(sc_capabilities_response_is_json("") == 0, "empty is not JSON");
    ASSERT(sc_capabilities_response_is_json(NULL) == 0, "NULL is not JSON");
}

static void test_report_json_roundtrip(void)
{
    sc_capability_report_t r;
    memset(&r, 0, sizeof(r));
    r.model = sc_strdup("openrouter/foo");
    r.chat_ok = SC_CAP_YES;
    r.stream_ok = SC_CAP_SKIPPED;
    r.tool_calls_ok = SC_CAP_NO;
    r.json_ok = SC_CAP_YES;
    r.checked_at = 1234567;

    char *json = sc_capabilities_to_json(&r);
    ASSERT_NOT_NULL(json);

    sc_capability_report_t back;
    int ok = sc_capabilities_from_json(json, &back);
    ASSERT_INT_EQ(ok, 1);
    ASSERT_STR_EQ(back.model, "openrouter/foo");
    ASSERT_INT_EQ(back.chat_ok, SC_CAP_YES);
    ASSERT_INT_EQ(back.stream_ok, SC_CAP_SKIPPED);
    ASSERT_INT_EQ(back.tool_calls_ok, SC_CAP_NO);
    ASSERT_INT_EQ(back.json_ok, SC_CAP_YES);
    ASSERT_INT_EQ((int)back.checked_at, 1234567);

    /* Malformed input rejected. */
    sc_capability_report_t junk;
    ASSERT_INT_EQ(sc_capabilities_from_json("not json", &junk), 0);

    free(json);
    sc_capability_report_free(&r);
    sc_capability_report_free(&back);
}

static void test_cache_path_sanitizes(void)
{
    char *p = sc_capabilities_cache_path("/home/x/.smolclaw", "openrouter/a/b:c");
    ASSERT_NOT_NULL(p);
    ASSERT_STR_EQ(p, "/home/x/.smolclaw/capabilities/openrouter_a_b_c.json");
    free(p);

    /* Safe characters are preserved. */
    char *p2 = sc_capabilities_cache_path("/h", "claude-opus-4.8");
    ASSERT_NOT_NULL(p2);
    ASSERT_STR_EQ(p2, "/h/capabilities/claude-opus-4.8.json");
    free(p2);

    ASSERT_NULL(sc_capabilities_cache_path(NULL, "m"));
    ASSERT_NULL(sc_capabilities_cache_path("/h", ""));
}

static void test_probe_provider(void)
{
    sc_provider_t mock = make_mock_provider();
    sc_capability_report_t rep;
    int basic = sc_doctor_probe_provider(&mock, "mock-model", &rep);

    ASSERT_INT_EQ(basic, 1);
    ASSERT_STR_EQ(rep.model, "mock-model");
    ASSERT_INT_EQ(rep.chat_ok, SC_CAP_YES);
    ASSERT_INT_EQ(rep.tool_calls_ok, SC_CAP_YES);
    ASSERT_INT_EQ(rep.json_ok, SC_CAP_YES);
#if SC_ENABLE_STREAMING
    ASSERT_INT_EQ(rep.stream_ok, SC_CAP_YES);
#else
    ASSERT_INT_EQ(rep.stream_ok, SC_CAP_SKIPPED);
#endif

    sc_capability_report_free(&rep);
}

static void test_probe_null_provider(void)
{
    sc_capability_report_t rep;
    memset(&rep, 0, sizeof(rep));
    ASSERT_INT_EQ(sc_doctor_probe_provider(NULL, "m", &rep), 0);
}

int main(void)
{
    printf("test_doctor_local:\n");
    RUN_TEST(test_response_is_json);
    RUN_TEST(test_report_json_roundtrip);
    RUN_TEST(test_cache_path_sanitizes);
    RUN_TEST(test_probe_provider);
    RUN_TEST(test_probe_null_provider);
    TEST_REPORT();
}
