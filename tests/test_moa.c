/*
 * smolclaw - Mixture of Agents (MoA-lite) tests (task 2.13)
 *
 * Pure message-helper tests + sc_moa_run with mock providers (no live HTTP),
 * plus config-load rejection paths (local_only, recursive).
 */

#include "test_main.h"
#include "providers/moa.h"
#include "providers/types.h"
#include "config.h"
#include "util/str.h"

#include <stdlib.h>
#include <string.h>

/* ---- mock provider ---- */

typedef struct {
    const char *reply;     /* content to return; NULL → HTTP 500 */
    int call_count;
    char captured[8192];   /* concatenated message contents of the last call */
} mock_t;

static sc_llm_response_t *mock_chat(sc_provider_t *self,
                                    sc_llm_message_t *msgs, int count,
                                    sc_tool_definition_t *tools, int tool_count,
                                    const char *model, cJSON *options)
{
    (void)tools; (void)tool_count; (void)model; (void)options;
    mock_t *m = self->data;
    m->call_count++;
    m->captured[0] = '\0';
    for (int i = 0; i < count; i++) {
        if (msgs[i].content) {
            strncat(m->captured, msgs[i].content,
                    sizeof(m->captured) - strlen(m->captured) - 1);
            strncat(m->captured, "\n", sizeof(m->captured) - strlen(m->captured) - 1);
        }
    }
    sc_llm_response_t *r = calloc(1, sizeof(*r));
    if (m->reply) {
        r->content = sc_strdup(m->reply);
        r->http_status = 200;
    } else {
        r->http_status = 500;
    }
    return r;
}

static sc_provider_t make_mock(mock_t *m, const char *reply)
{
    m->reply = reply;
    m->call_count = 0;
    sc_provider_t p = {0};
    p.name = "mock";
    p.chat = mock_chat;
    p.data = m;
    return p;
}

static sc_moa_slot_t make_slot(sc_provider_t *p, const char *model, const char *label)
{
    sc_moa_slot_t s = {0};
    s.provider = p;
    s.model = sc_strdup(model);
    s.label = sc_strdup(label);
    return s;
}

static void free_slot(sc_moa_slot_t *s) { free(s->model); free(s->label); }

/* Free fields of a STACK-allocated message array (sc_llm_message_array_free
 * would free() the array pointer itself, which is illegal for stack arrays). */
static void free_stack_msgs(sc_llm_message_t *m, int n)
{
    for (int i = 0; i < n; i++) sc_llm_message_free_fields(&m[i]);
}

/* ---- message helpers ---- */

static void test_reference_view_excludes_system_and_tools(void)
{
    sc_llm_message_t msgs[5] = {0};
    msgs[0] = sc_msg_system("you are helpful");
    msgs[1] = sc_msg_user("hello");
    msgs[2] = sc_msg_assistant("hi there");
    msgs[3] = sc_msg_tool_result("call_1", "tool output");
    msgs[4] = sc_msg_assistant("");            /* tool-only assistant turn */

    int n = 0;
    sc_llm_message_t *view = sc_msgs_reference_view(msgs, 5, &n);
    ASSERT_INT_EQ(n, 2);
    ASSERT_STR_EQ(view[0].role, "user");
    ASSERT_STR_EQ(view[1].role, "assistant");
    ASSERT_STR_EQ(view[1].content, "hi there");

    sc_llm_message_array_free(view, n);
    free_stack_msgs(msgs, 5);
}

static void test_injection_appends_without_mutating(void)
{
    sc_llm_message_t msgs[1] = {0};
    msgs[0] = sc_msg_user("solve this");

    char *labels[2] = { (char *)"ollama/a", (char *)"openrouter/b" };
    char *texts[2]  = { (char *)"idea one", (char *)"idea two" };

    int n = 0;
    sc_llm_message_t *out = sc_msgs_inject_moa_refs(msgs, 1, labels, texts, 2, &n);
    ASSERT_INT_EQ(n, 1);
    ASSERT(strstr(out[0].content, "solve this") != NULL, "keeps original text");
    ASSERT(strstr(out[0].content, "idea one") != NULL, "includes ref 1");
    ASSERT(strstr(out[0].content, "idea two") != NULL, "includes ref 2");
    ASSERT(strstr(out[0].content, "MoA reference: ollama/a") != NULL, "ref label");

    /* Source array unchanged. */
    ASSERT_STR_EQ(msgs[0].content, "solve this");

    sc_llm_message_array_free(out, n);
    free_stack_msgs(msgs, 1);
}

static void test_injection_synthetic_user_when_tail_not_user(void)
{
    sc_llm_message_t msgs[1] = {0};
    msgs[0] = sc_msg_tool_result("c1", "result");  /* tail is not a user turn */

    char *labels[1] = { (char *)"ollama/a" };
    char *texts[1]  = { (char *)"guidance" };

    int n = 0;
    sc_llm_message_t *out = sc_msgs_inject_moa_refs(msgs, 1, labels, texts, 1, &n);
    ASSERT_INT_EQ(n, 2);                  /* synthetic user appended */
    ASSERT_STR_EQ(out[1].role, "user");
    ASSERT(strstr(out[1].content, "guidance") != NULL, "synthetic carries refs");

    sc_llm_message_array_free(out, n);
    free_stack_msgs(msgs, 1);
}

/* ---- local_only validation ---- */

static void test_provider_is_local(void)
{
    ASSERT_INT_EQ(sc_moa_provider_is_local("ollama", NULL), 1);
    ASSERT_INT_EQ(sc_moa_provider_is_local("vllm", NULL), 1);
    ASSERT_INT_EQ(sc_moa_provider_is_local("anthropic", NULL), 0);
    ASSERT_INT_EQ(sc_moa_provider_is_local("openrouter", NULL), 0);
    ASSERT_INT_EQ(sc_moa_provider_is_local("custom", "http://127.0.0.1:8000/v1"), 1);
    ASSERT_INT_EQ(sc_moa_provider_is_local("custom", "http://192.168.1.5:8000"), 1);
    ASSERT_INT_EQ(sc_moa_provider_is_local("custom", "https://api.openai.com/v1"), 0);
}

/* ---- sc_moa_run ---- */

static void test_run_injects_two_references(void)
{
    mock_t r1m, r2m, aggm;
    sc_provider_t r1 = make_mock(&r1m, "REF_ALPHA");
    sc_provider_t r2 = make_mock(&r2m, "REF_BETA");
    sc_provider_t agg = make_mock(&aggm, "FINAL_ANSWER");

    sc_moa_preset_t preset = {0};
    preset.enabled = 1;
    preset.refs[0] = make_slot(&r1, "a", "ollama/a");
    preset.refs[1] = make_slot(&r2, "b", "openrouter/b");
    preset.ref_count = 2;
    preset.agg = make_slot(&agg, "agg", "anthropic/agg");
    preset.ref_max_tokens = 256;
    preset.ref_temp = 0.6;

    sc_llm_message_t msgs[1] = {0};
    msgs[0] = sc_msg_user("the question");

    sc_llm_response_t *resp = sc_moa_run(&preset, msgs, 1, NULL, 0, NULL, NULL, NULL);
    ASSERT_NOT_NULL(resp);
    ASSERT_STR_EQ(resp->content, "FINAL_ANSWER");
    ASSERT_INT_EQ(r1m.call_count, 1);
    ASSERT_INT_EQ(r2m.call_count, 1);
    ASSERT_INT_EQ(aggm.call_count, 1);
    /* Aggregator saw both reference blocks injected on the user turn. */
    ASSERT(strstr(aggm.captured, "REF_ALPHA") != NULL, "agg sees ref 1");
    ASSERT(strstr(aggm.captured, "REF_BETA") != NULL, "agg sees ref 2");
    ASSERT(strstr(aggm.captured, "the question") != NULL, "agg sees user text");

    sc_llm_response_free(resp);
    free_stack_msgs(msgs, 1);
    free_slot(&preset.refs[0]); free_slot(&preset.refs[1]); free_slot(&preset.agg);
}

static void test_run_reference_failure_continues(void)
{
    mock_t badm, aggm;
    sc_provider_t bad = make_mock(&badm, NULL);    /* returns HTTP 500 */
    sc_provider_t agg = make_mock(&aggm, "OK");

    sc_moa_preset_t preset = {0};
    preset.enabled = 1;
    preset.refs[0] = make_slot(&bad, "x", "ollama/x");
    preset.ref_count = 1;
    preset.agg = make_slot(&agg, "agg", "anthropic/agg");

    sc_llm_message_t msgs[1] = {0};
    msgs[0] = sc_msg_user("q");

    sc_llm_response_t *resp = sc_moa_run(&preset, msgs, 1, NULL, 0, NULL, NULL, NULL);
    ASSERT_NOT_NULL(resp);
    ASSERT_INT_EQ(aggm.call_count, 1);             /* aggregator still ran */
    ASSERT(strstr(aggm.captured, "reference failed") != NULL,
           "failed ref injected as error text");

    sc_llm_response_free(resp);
    free_stack_msgs(msgs, 1);
    free_slot(&preset.refs[0]); free_slot(&preset.agg);
}

static void test_run_disabled_skips_references(void)
{
    mock_t refm, aggm;
    sc_provider_t ref = make_mock(&refm, "SHOULD_NOT_RUN");
    sc_provider_t agg = make_mock(&aggm, "ONLY_AGG");

    sc_moa_preset_t preset = {0};
    preset.enabled = 0;                            /* MoA off for this preset */
    preset.refs[0] = make_slot(&ref, "x", "ollama/x");
    preset.ref_count = 1;
    preset.agg = make_slot(&agg, "agg", "anthropic/agg");

    sc_llm_message_t msgs[1] = {0};
    msgs[0] = sc_msg_user("q");

    sc_llm_response_t *resp = sc_moa_run(&preset, msgs, 1, NULL, 0, NULL, NULL, NULL);
    ASSERT_NOT_NULL(resp);
    ASSERT_INT_EQ(refm.call_count, 0);             /* no reference call */
    ASSERT_INT_EQ(aggm.call_count, 1);
    ASSERT(strstr(aggm.captured, "MoA reference") == NULL, "no injection when disabled");

    sc_llm_response_free(resp);
    free_stack_msgs(msgs, 1);
    free_slot(&preset.refs[0]); free_slot(&preset.agg);
}

/* ---- preset validation at construction ---- */

static void test_local_only_rejects_cloud_aggregator(void)
{
    sc_config_t cfg = {0};
    cfg.moa.preset_count = 1;
    cfg.moa.presets[0].name = (char *)"airgap";
    cfg.moa.presets[0].enabled = 1;
    cfg.moa.presets[0].local_only = 1;
    cfg.moa.presets[0].aggregator.provider = (char *)"anthropic";  /* not local */
    cfg.moa.presets[0].aggregator.model = (char *)"claude";

    /* Only usable preset is rejected → no provider. */
    sc_provider_t *p = sc_provider_moa_new(&cfg, NULL);
    ASSERT_NULL(p);
}

static void test_recursive_preset_blocked(void)
{
    sc_config_t cfg = {0};
    cfg.moa.preset_count = 1;
    cfg.moa.presets[0].name = (char *)"loop";
    cfg.moa.presets[0].enabled = 1;
    cfg.moa.presets[0].aggregator.provider = (char *)"moa";   /* recursive */
    cfg.moa.presets[0].aggregator.model = (char *)"other";

    sc_provider_t *p = sc_provider_moa_new(&cfg, NULL);
    ASSERT_NULL(p);
}

int main(void)
{
    printf("test_moa\n");

    RUN_TEST(test_reference_view_excludes_system_and_tools);
    RUN_TEST(test_injection_appends_without_mutating);
    RUN_TEST(test_injection_synthetic_user_when_tail_not_user);
    RUN_TEST(test_provider_is_local);
    RUN_TEST(test_run_injects_two_references);
    RUN_TEST(test_run_reference_failure_continues);
    RUN_TEST(test_run_disabled_skips_references);
    RUN_TEST(test_local_only_rejects_cloud_aggregator);
    RUN_TEST(test_recursive_preset_blocked);

    TEST_REPORT();
}
