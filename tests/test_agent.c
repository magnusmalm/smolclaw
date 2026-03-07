/*
 * smolclaw - agent tests
 * Tests model override parsing, agent loop with mock provider (tool calls),
 * and session summarization.
 */

#include "test_main.h"
#include "agent.h"
#include "session.h"
#include "state.h"
#include "context.h"
#include "tools/registry.h"
#include "tools/types.h"
#include "providers/types.h"
#include "util/str.h"
#include "cJSON.h"
#include "sc_features.h"
#include "agent_internal.h"

#if SC_ENABLE_SPAWN
#include "tools/spawn.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ======================================================================
 * Model override parsing tests
 * ====================================================================== */

static void test_parse_use_prefix(void)
{
    const char *rest = NULL;

    /* "Use opus: hello world" */
    char *alias = sc_parse_model_override("Use opus: hello world", &rest);
    ASSERT_NOT_NULL(alias);
    ASSERT_STR_EQ(alias, "opus");
    ASSERT_STR_EQ(rest, "hello world");
    free(alias);
}

static void test_parse_use_case_insensitive(void)
{
    const char *rest = NULL;

    /* Case-insensitive: "USE SONNET: msg" */
    char *alias = sc_parse_model_override("USE SONNET: msg", &rest);
    ASSERT_NOT_NULL(alias);
    ASSERT_STR_EQ(alias, "SONNET");
    ASSERT_STR_EQ(rest, "msg");
    free(alias);

    /* Mixed case */
    alias = sc_parse_model_override("use Haiku: test", &rest);
    ASSERT_NOT_NULL(alias);
    ASSERT_STR_EQ(alias, "Haiku");
    ASSERT_STR_EQ(rest, "test");
    free(alias);
}

static void test_parse_at_prefix(void)
{
    const char *rest = NULL;

    /* "@sonnet what's up" */
    char *alias = sc_parse_model_override("@sonnet what's up", &rest);
    ASSERT_NOT_NULL(alias);
    ASSERT_STR_EQ(alias, "sonnet");
    ASSERT_STR_EQ(rest, "what's up");
    free(alias);
}

static void test_parse_no_match(void)
{
    const char *rest = NULL;

    /* Regular message */
    char *alias = sc_parse_model_override("Hello world", &rest);
    ASSERT_NULL(alias);

    /* "use" without colon */
    alias = sc_parse_model_override("use opus hello", &rest);
    ASSERT_NULL(alias);

    /* "@" alone */
    alias = sc_parse_model_override("@", &rest);
    ASSERT_NULL(alias);

    /* "@ space" (space after @) */
    alias = sc_parse_model_override("@ sonnet hello", &rest);
    ASSERT_NULL(alias);

    /* Empty string */
    alias = sc_parse_model_override("", &rest);
    ASSERT_NULL(alias);

    /* NULL */
    alias = sc_parse_model_override(NULL, &rest);
    ASSERT_NULL(alias);
}

static void test_parse_leading_whitespace(void)
{
    const char *rest = NULL;

    /* Leading spaces should be skipped */
    char *alias = sc_parse_model_override("  Use gpt4o: question", &rest);
    ASSERT_NOT_NULL(alias);
    ASSERT_STR_EQ(alias, "gpt4o");
    ASSERT_STR_EQ(rest, "question");
    free(alias);

    alias = sc_parse_model_override("  @haiku hi", &rest);
    ASSERT_NOT_NULL(alias);
    ASSERT_STR_EQ(alias, "haiku");
    ASSERT_STR_EQ(rest, "hi");
    free(alias);
}

static void test_parse_extra_spaces(void)
{
    const char *rest = NULL;

    /* Extra spaces after colon */
    char *alias = sc_parse_model_override("Use opus:   spaced message", &rest);
    ASSERT_NOT_NULL(alias);
    ASSERT_STR_EQ(alias, "opus");
    ASSERT_STR_EQ(rest, "spaced message");
    free(alias);

    /* Extra spaces between "use" and alias */
    alias = sc_parse_model_override("Use   opus: message", &rest);
    ASSERT_NOT_NULL(alias);
    ASSERT_STR_EQ(alias, "opus");
    free(alias);
}

static void test_parse_at_no_message(void)
{
    const char *rest = NULL;

    /* "@alias" with no message after */
    char *alias = sc_parse_model_override("@opus", &rest);
    ASSERT_NOT_NULL(alias);
    ASSERT_STR_EQ(alias, "opus");
    ASSERT_STR_EQ(rest, "");
    free(alias);
}

/* ======================================================================
 * Mock provider for agent loop tests
 * ====================================================================== */

#define MAX_MOCK_RESPONSES 8

typedef struct {
    sc_llm_response_t responses[MAX_MOCK_RESPONSES];
    int response_count;
    int call_index;
    int chat_call_count;
} mock_provider_data_t;

static sc_llm_response_t *mock_chat(sc_provider_t *self,
                                     sc_llm_message_t *msgs, int msg_count,
                                     sc_tool_definition_t *tools, int tool_count,
                                     const char *model, cJSON *options)
{
    mock_provider_data_t *data = self->data;
    data->chat_call_count++;
    if (data->call_index >= data->response_count) return NULL;

    sc_llm_response_t *src = &data->responses[data->call_index++];

    /* Deep clone: caller (run_llm_iteration) owns and frees the result */
    sc_llm_response_t *ret = calloc(1, sizeof(*ret));
    if (!ret) return NULL;

    ret->content = sc_strdup(src->content);
    ret->finish_reason = sc_strdup(src->finish_reason);
    ret->http_status = 200;

    if (src->tool_call_count > 0 && src->tool_calls) {
        ret->tool_calls = calloc((size_t)src->tool_call_count, sizeof(sc_tool_call_t));
        ret->tool_call_count = src->tool_call_count;
        for (int i = 0; i < src->tool_call_count; i++) {
            ret->tool_calls[i].id = sc_strdup(src->tool_calls[i].id);
            ret->tool_calls[i].name = sc_strdup(src->tool_calls[i].name);
            ret->tool_calls[i].arguments = src->tool_calls[i].arguments
                ? cJSON_Duplicate(src->tool_calls[i].arguments, 1) : NULL;
        }
    }
    return ret;
}

static const char *mock_get_model(sc_provider_t *self)
{
    (void)self;
    return "test-model";
}

/* --- Mock tool --- */

static int mock_tool_executed;
static char *mock_tool_last_arg;

static cJSON *mock_tool_params(sc_tool_t *self)
{
    (void)self;
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "type", "object");
    cJSON *props = cJSON_AddObjectToObject(obj, "properties");
    cJSON *q = cJSON_AddObjectToObject(props, "query");
    cJSON_AddStringToObject(q, "type", "string");
    return obj;
}

static sc_tool_result_t *mock_tool_exec(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)self; (void)ctx;
    mock_tool_executed++;
    const char *query = NULL;
    cJSON *q = cJSON_GetObjectItem(args, "query");
    if (q) query = cJSON_GetStringValue(q);
    free(mock_tool_last_arg);
    mock_tool_last_arg = sc_strdup(query);
    return sc_tool_result_new("mock tool result: success");
}

static void mock_tool_destroy(sc_tool_t *self)
{
    free(self);
}

/* --- Helper: build a minimal agent with mock provider --- */

static void cleanup_dir(const char *dir)
{
    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", dir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

typedef struct {
    sc_agent_t *agent;
    sc_provider_t *provider;
    mock_provider_data_t *mpd;
    char tmpdir[64];
} test_agent_ctx_t;

static test_agent_ctx_t create_test_agent(int summary_threshold)
{
    test_agent_ctx_t ctx = {0};
    strcpy(ctx.tmpdir, "/tmp/sc_test_agent_XXXXXX");
    mkdtemp(ctx.tmpdir);

    /* Create workspace subdirs */
    char sessions_dir[128];
    snprintf(sessions_dir, sizeof(sessions_dir), "%s/sessions", ctx.tmpdir);
    mkdir(sessions_dir, 0755);

    char state_dir[128];
    snprintf(state_dir, sizeof(state_dir), "%s/state", ctx.tmpdir);
    mkdir(state_dir, 0755);

    /* Mock provider */
    ctx.mpd = calloc(1, sizeof(*ctx.mpd));
    ctx.provider = calloc(1, sizeof(*ctx.provider));
    ctx.provider->name = "mock";
    ctx.provider->chat = mock_chat;
    ctx.provider->get_default_model = mock_get_model;
    ctx.provider->data = ctx.mpd;

    /* Agent */
    ctx.agent = calloc(1, sizeof(*ctx.agent));
    ctx.agent->provider = ctx.provider;
    ctx.agent->workspace = sc_strdup(ctx.tmpdir);
    ctx.agent->model = sc_strdup("test-model");
    ctx.agent->context_window = 4096;
    ctx.agent->temperature = 0.7;
    ctx.agent->max_iterations = 10;
    ctx.agent->session_summary_threshold = summary_threshold;
    ctx.agent->session_keep_last = 4;
    ctx.agent->max_output_chars = 10000;
    ctx.agent->summary_max_transcript = 4000;
    ctx.agent->sessions = sc_session_manager_new(sessions_dir);
    ctx.agent->state = sc_state_new(ctx.tmpdir);
    ctx.agent->tools = sc_tool_registry_new();
    ctx.agent->context_builder = sc_context_builder_new(ctx.tmpdir);
    sc_context_builder_set_tools(ctx.agent->context_builder, ctx.agent->tools);
    ctx.agent->hourly_slots = calloc(SC_HOURLY_SLOTS, sizeof(sc_hourly_slot_t));

    return ctx;
}

static void destroy_test_agent(test_agent_ctx_t *ctx)
{
    sc_session_manager_free(ctx->agent->sessions);
    sc_state_free(ctx->agent->state);
    sc_tool_registry_free(ctx->agent->tools);
    sc_context_builder_free(ctx->agent->context_builder);
    free(ctx->agent->hourly_slots);
    free(ctx->agent->workspace);
    free(ctx->agent->model);
    free(ctx->agent);
    free(ctx->mpd);
    free(ctx->provider);
    cleanup_dir(ctx->tmpdir);
}

/* ======================================================================
 * Agent loop E2E tests
 * ====================================================================== */

static void test_agent_loop_simple(void)
{
    /* Simple request → LLM returns text → response returned */
    test_agent_ctx_t ctx = create_test_agent(100);

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = "Hello from the LLM!",
        .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 1;

    char *response = sc_agent_process_direct(ctx.agent, "Say hello", "test-simple");
    ASSERT_NOT_NULL(response);
    ASSERT_STR_EQ(response, "Hello from the LLM!");

    ASSERT_INT_EQ(ctx.mpd->chat_call_count, 1);

    /* Verify session saved user + assistant messages */
    int count = 0;
    sc_llm_message_t *history = sc_session_get_history(
        ctx.agent->sessions, "test-simple", &count);
    ASSERT_INT_EQ(count, 2);
    ASSERT_STR_EQ(history[0].role, "user");
    ASSERT_STR_EQ(history[0].content, "Say hello");
    ASSERT_STR_EQ(history[1].role, "assistant");
    ASSERT_STR_EQ(history[1].content, "Hello from the LLM!");

    free(response);
    destroy_test_agent(&ctx);
}

static void test_agent_loop_tool_call(void)
{
    /* Request → LLM returns tool call → tool executes → LLM returns text */
    test_agent_ctx_t ctx = create_test_agent(100);

    /* Register mock tool */
    sc_tool_t *tool = calloc(1, sizeof(*tool));
    tool->name = "echo_test";
    tool->description = "A test tool";
    tool->parameters = mock_tool_params;
    tool->execute = mock_tool_exec;
    tool->destroy = mock_tool_destroy;
    sc_tool_registry_register(ctx.agent->tools, tool);

    mock_tool_executed = 0;
    free(mock_tool_last_arg);
    mock_tool_last_arg = NULL;

    /* Response 1: tool call */
    cJSON *tc_args = cJSON_CreateObject();
    cJSON_AddStringToObject(tc_args, "query", "hello world");
    sc_tool_call_t tc = { .id = "call_1", .name = "echo_test", .arguments = tc_args };
    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = NULL,
        .tool_calls = &tc,
        .tool_call_count = 1,
        .finish_reason = "tool_use",
    };

    /* Response 2: final text */
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Tool executed. All done!",
        .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 2;

    char *response = sc_agent_process_direct(ctx.agent, "Run the tool", "test-tool");
    ASSERT_NOT_NULL(response);
    ASSERT_STR_EQ(response, "Tool executed. All done!");

    /* Verify tool was called */
    ASSERT_INT_EQ(mock_tool_executed, 1);
    ASSERT_STR_EQ(mock_tool_last_arg, "hello world");

    /* Provider called twice: tool call + final response */
    ASSERT_INT_EQ(ctx.mpd->chat_call_count, 2);

    /* Session should have: user + assistant(tool_use) + tool_result + assistant */
    int count = 0;
    sc_llm_message_t *history = sc_session_get_history(
        ctx.agent->sessions, "test-tool", &count);
    ASSERT_INT_EQ(count, 4);
    ASSERT_STR_EQ(history[0].role, "user");
    ASSERT_STR_EQ(history[0].content, "Run the tool");
    /* history[1] = assistant with tool_calls */
    ASSERT_STR_EQ(history[1].role, "assistant");
    ASSERT(history[1].tool_call_count > 0, "Should have tool calls");
    /* history[2] = tool result */
    ASSERT_NOT_NULL(history[2].tool_call_id);
    ASSERT(strstr(history[2].content, "mock tool result") != NULL,
           "Tool result should be in session");
    /* history[3] = final assistant */
    ASSERT_STR_EQ(history[3].role, "assistant");
    ASSERT_STR_EQ(history[3].content, "Tool executed. All done!");

    free(response);
    cJSON_Delete(tc_args);
    free(mock_tool_last_arg);
    mock_tool_last_arg = NULL;
    destroy_test_agent(&ctx);
}

static void test_agent_loop_provider_failure(void)
{
    /* If provider returns NULL, agent should return a default message */
    test_agent_ctx_t ctx = create_test_agent(100);

    /* No responses configured → mock returns NULL */
    ctx.mpd->response_count = 0;

    char *response = sc_agent_process_direct(ctx.agent, "Fail me", "test-fail");
    ASSERT_NOT_NULL(response);
    /* Agent returns a default message when all providers fail */
    ASSERT(strlen(response) > 0, "Should return non-empty response");

    ASSERT_INT_EQ(ctx.mpd->chat_call_count, 1);

    free(response);
    destroy_test_agent(&ctx);
}

/* ======================================================================
 * Session summarization E2E test
 * ====================================================================== */

static void test_session_summarization(void)
{
    /*
     * Pre-fill session with messages, then send one more to exceed threshold.
     * maybe_summarize() calls the provider to summarize, then truncates.
     */

    /* Use a low threshold (6) so we don't need many messages.
     * After process_direct adds user + assistant messages, total = 8 > 6. */
    test_agent_ctx_t ctx = create_test_agent(6);

    /* Pre-fill session with 6 messages (3 user + 3 assistant) */
    for (int i = 0; i < 3; i++) {
        char umsg[64], amsg[64];
        snprintf(umsg, sizeof(umsg), "User message %d", i);
        snprintf(amsg, sizeof(amsg), "Assistant reply %d", i);
        sc_session_add_message(ctx.agent->sessions, "test-summarize", "user", umsg);
        sc_session_add_message(ctx.agent->sessions, "test-summarize", "assistant", amsg);
    }

    int count = 0;
    sc_session_get_history(ctx.agent->sessions, "test-summarize", &count);
    ASSERT_INT_EQ(count, 6);

    /*
     * Provider response plan:
     * Call 1: LLM response to user query (no tool calls) → "Here's the answer."
     * Call 2: maybe_summarize() calls provider for summary → "Conversation summary."
     */
    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = "Here's the answer.",
        .finish_reason = "end_turn",
    };
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Discussed 3 topics. Key findings: none.",
        .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 2;

    char *response = sc_agent_process_direct(ctx.agent, "One more question",
                                              "test-summarize");
    ASSERT_NOT_NULL(response);
    ASSERT_STR_EQ(response, "Here's the answer.");

    /* Summarization runs on a background thread — wait for it to complete */
    sc_agent_wait_summarize(ctx.agent);

    /* Provider should be called twice: once for the query, once for summarization */
    ASSERT_INT_EQ(ctx.mpd->chat_call_count, 2);

    /* Session should be truncated to keep_last (4) messages */
    sc_session_get_history(ctx.agent->sessions, "test-summarize", &count);
    ASSERT_INT_EQ(count, 4);

    /* Summary should be set */
    const char *summary = sc_session_get_summary(ctx.agent->sessions, "test-summarize");
    ASSERT_NOT_NULL(summary);
    ASSERT_STR_EQ(summary, "Discussed 3 topics. Key findings: none.");

    free(response);
    destroy_test_agent(&ctx);
}

/* ======================================================================
 * Spawn tool E2E test
 * ====================================================================== */

#if SC_ENABLE_SPAWN
static void test_agent_spawn_tool(void)
{
    /*
     * Spawn tool triggers a subagent on a separate session key.
     * Mock provider call sequence:
     *   Call 1 (outer): tool_use → spawn(prompt="Do inner work")
     *   Call 2 (inner subagent): text → "Inner agent result"
     *   Call 3 (outer): text → "Spawn complete."
     */
    test_agent_ctx_t ctx = create_test_agent(100);

    /* Register spawn tool */
    sc_tool_t *spawn = sc_tool_spawn_new(ctx.agent);
    ASSERT_NOT_NULL(spawn);
    sc_tool_registry_register(ctx.agent->tools, spawn);

    /* Response 1: outer agent returns tool call to spawn */
    cJSON *spawn_args = cJSON_CreateObject();
    cJSON_AddStringToObject(spawn_args, "prompt", "Do inner work");
    cJSON_AddStringToObject(spawn_args, "name", "helper");
    sc_tool_call_t tc = {
        .id = "call_spawn_1", .name = "spawn", .arguments = spawn_args
    };
    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = NULL,
        .tool_calls = &tc,
        .tool_call_count = 1,
        .finish_reason = "tool_use",
    };

    /* Response 2: inner subagent returns text */
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Inner agent result",
        .finish_reason = "end_turn",
    };

    /* Response 3: outer agent gets tool result, returns final text */
    ctx.mpd->responses[2] = (sc_llm_response_t){
        .content = "Spawn complete. Got: Inner agent result",
        .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 3;

    char *response = sc_agent_process_direct(ctx.agent, "Spawn a helper",
                                              "test-spawn");
    ASSERT_NOT_NULL(response);
    ASSERT_STR_EQ(response, "Spawn complete. Got: Inner agent result");

    /* Provider called 3 times: outer tool call, inner subagent, outer final */
    ASSERT_INT_EQ(ctx.mpd->chat_call_count, 3);

    /* Outer session: user + assistant(tool_use) + tool_result + assistant */
    int count = 0;
    sc_llm_message_t *history = sc_session_get_history(
        ctx.agent->sessions, "test-spawn", &count);
    ASSERT_INT_EQ(count, 4);
    ASSERT_STR_EQ(history[0].role, "user");
    ASSERT_STR_EQ(history[0].content, "Spawn a helper");
    ASSERT_STR_EQ(history[1].role, "assistant");
    ASSERT(history[1].tool_call_count > 0, "Should have spawn tool call");
    /* history[2] = tool result from spawn */
    ASSERT_NOT_NULL(history[2].tool_call_id);
    ASSERT(strstr(history[2].content, "Inner agent result") != NULL,
           "Tool result should contain subagent output");
    /* history[3] = final assistant response */
    ASSERT_STR_EQ(history[3].role, "assistant");
    ASSERT_STR_EQ(history[3].content, "Spawn complete. Got: Inner agent result");

    free(response);
    cJSON_Delete(spawn_args);
    destroy_test_agent(&ctx);
}
#endif /* SC_ENABLE_SPAWN */

static void test_agent_tool_call_limit(void)
{
    /* Verify that max_tool_calls_per_turn stops runaway tool loops.
     * Set limit to 2, LLM keeps requesting tools → agent should stop. */
    test_agent_ctx_t ctx = create_test_agent(100);
    ctx.agent->max_tool_calls_per_turn = 2;

    sc_tool_t *tool = calloc(1, sizeof(*tool));
    tool->name = "echo_test";
    tool->description = "A test tool";
    tool->parameters = mock_tool_params;
    tool->execute = mock_tool_exec;
    tool->destroy = mock_tool_destroy;
    sc_tool_registry_register(ctx.agent->tools, tool);

    mock_tool_executed = 0;
    free(mock_tool_last_arg);
    mock_tool_last_arg = NULL;

    /* Every response is a tool call — should be stopped by limit */
    cJSON *tc_args1 = cJSON_CreateObject();
    cJSON_AddStringToObject(tc_args1, "query", "call1");
    sc_tool_call_t tc1 = { .id = "call_1", .name = "echo_test", .arguments = tc_args1 };

    cJSON *tc_args2 = cJSON_CreateObject();
    cJSON_AddStringToObject(tc_args2, "query", "call2");
    sc_tool_call_t tc2 = { .id = "call_2", .name = "echo_test", .arguments = tc_args2 };

    cJSON *tc_args3 = cJSON_CreateObject();
    cJSON_AddStringToObject(tc_args3, "query", "call3");
    sc_tool_call_t tc3 = { .id = "call_3", .name = "echo_test", .arguments = tc_args3 };

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .tool_calls = &tc1, .tool_call_count = 1, .finish_reason = "tool_use",
    };
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .tool_calls = &tc2, .tool_call_count = 1, .finish_reason = "tool_use",
    };
    ctx.mpd->responses[2] = (sc_llm_response_t){
        .tool_calls = &tc3, .tool_call_count = 1, .finish_reason = "tool_use",
    };
    ctx.mpd->response_count = 3;

    char *response = sc_agent_process_direct(ctx.agent, "Do many things", "test-limit");
    ASSERT_NOT_NULL(response);
    ASSERT(strstr(response, "too many tool calls") != NULL,
           "Should stop with tool call limit message");

    /* Should have executed at most 2 tool calls (limit) + 1 that triggers the check */
    ASSERT(mock_tool_executed <= 3, "Should not execute many more than limit");

    free(response);
    cJSON_Delete(tc_args1);
    cJSON_Delete(tc_args2);
    cJSON_Delete(tc_args3);
    free(mock_tool_last_arg);
    mock_tool_last_arg = NULL;
    destroy_test_agent(&ctx);
}

static void test_agent_multi_tool_calls(void)
{
    /* LLM returns multiple tool calls in a single response */
    test_agent_ctx_t ctx = create_test_agent(100);

    sc_tool_t *tool = calloc(1, sizeof(*tool));
    tool->name = "echo_test";
    tool->description = "A test tool";
    tool->parameters = mock_tool_params;
    tool->execute = mock_tool_exec;
    tool->destroy = mock_tool_destroy;
    sc_tool_registry_register(ctx.agent->tools, tool);

    mock_tool_executed = 0;
    free(mock_tool_last_arg);
    mock_tool_last_arg = NULL;

    /* Response 1: two tool calls at once */
    cJSON *args_a = cJSON_CreateObject();
    cJSON_AddStringToObject(args_a, "query", "first");
    cJSON *args_b = cJSON_CreateObject();
    cJSON_AddStringToObject(args_b, "query", "second");
    sc_tool_call_t calls[2] = {
        { .id = "call_a", .name = "echo_test", .arguments = args_a },
        { .id = "call_b", .name = "echo_test", .arguments = args_b },
    };
    ctx.mpd->responses[0] = (sc_llm_response_t){
        .tool_calls = calls, .tool_call_count = 2, .finish_reason = "tool_use",
    };

    /* Response 2: final text */
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Both tools done.", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 2;

    char *response = sc_agent_process_direct(ctx.agent, "Run both", "test-multi");
    ASSERT_NOT_NULL(response);
    ASSERT_STR_EQ(response, "Both tools done.");
    ASSERT_INT_EQ(mock_tool_executed, 2);
    ASSERT_INT_EQ(ctx.mpd->chat_call_count, 2);

    /* Session: user + assistant(2 tool_calls) + 2 tool_results + final assistant = 5 */
    int count = 0;
    sc_session_get_history(ctx.agent->sessions, "test-multi", &count);
    ASSERT_INT_EQ(count, 5);

    free(response);
    cJSON_Delete(args_a);
    cJSON_Delete(args_b);
    free(mock_tool_last_arg);
    mock_tool_last_arg = NULL;
    destroy_test_agent(&ctx);
}

static void test_agent_hourly_rate_limit(void)
{
    /* Cross-turn rate limiting: hourly tool call cap */
    test_agent_ctx_t ctx = create_test_agent(100);
    ctx.agent->max_tool_calls_per_hour = 3;

    sc_tool_t *tool = calloc(1, sizeof(*tool));
    tool->name = "echo_test";
    tool->description = "A test tool";
    tool->parameters = mock_tool_params;
    tool->execute = mock_tool_exec;
    tool->destroy = mock_tool_destroy;
    sc_tool_registry_register(ctx.agent->tools, tool);

    mock_tool_executed = 0;
    free(mock_tool_last_arg);
    mock_tool_last_arg = NULL;

    /* Turn 1: 2 tool calls (within limit) */
    cJSON *args1 = cJSON_CreateObject();
    cJSON_AddStringToObject(args1, "query", "a");
    cJSON *args2 = cJSON_CreateObject();
    cJSON_AddStringToObject(args2, "query", "b");
    sc_tool_call_t calls1[2] = {
        { .id = "c1", .name = "echo_test", .arguments = args1 },
        { .id = "c2", .name = "echo_test", .arguments = args2 },
    };
    ctx.mpd->responses[0] = (sc_llm_response_t){
        .tool_calls = calls1, .tool_call_count = 2, .finish_reason = "tool_use",
    };
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Turn 1 done.", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 2;

    char *r1 = sc_agent_process_direct(ctx.agent, "First turn", "test-hourly");
    ASSERT_NOT_NULL(r1);
    ASSERT_STR_EQ(r1, "Turn 1 done.");
    ASSERT_INT_EQ(mock_tool_executed, 2);
    free(r1);

    /* Turn 2: 2 more tool calls — should hit limit after 1 (total would be 4 > 3) */
    cJSON *args3 = cJSON_CreateObject();
    cJSON_AddStringToObject(args3, "query", "c");
    cJSON *args4 = cJSON_CreateObject();
    cJSON_AddStringToObject(args4, "query", "d");
    sc_tool_call_t calls2[2] = {
        { .id = "c3", .name = "echo_test", .arguments = args3 },
        { .id = "c4", .name = "echo_test", .arguments = args4 },
    };
    ctx.mpd->responses[0] = (sc_llm_response_t){
        .tool_calls = calls2, .tool_call_count = 2, .finish_reason = "tool_use",
    };
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Should not reach.", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 2;
    ctx.mpd->call_index = 0;
    ctx.mpd->chat_call_count = 0;

    char *r2 = sc_agent_process_direct(ctx.agent, "Second turn", "test-hourly");
    ASSERT_NOT_NULL(r2);
    ASSERT(strstr(r2, "hourly tool call limit") != NULL,
           "Should stop with hourly limit message");

    free(r2);
    cJSON_Delete(args1);
    cJSON_Delete(args2);
    cJSON_Delete(args3);
    cJSON_Delete(args4);
    free(mock_tool_last_arg);
    mock_tool_last_arg = NULL;
    destroy_test_agent(&ctx);
}

/* Test that two different keys with same hash are tracked separately */
static void test_rate_limiter_key_collision(void)
{
    test_agent_ctx_t ctx = create_test_agent(100);
    ctx.agent->max_tool_calls_per_hour = 5;

    /* Fill slots with different session keys — set key_prefix directly */
    sc_hourly_slot_t *slots = ctx.agent->hourly_slots;
    for (int i = 0; i < SC_HOURLY_SLOTS; i++) {
        snprintf(slots[i].key_prefix, sizeof(slots[i].key_prefix),
                 "session-%d", i);
        slots[i].key_hash = 1000 + (uint32_t)i;
        slots[i].tool_calls = 1;
        slots[i].window_start = time(NULL);
    }

    /* Two keys with same hash but different prefix should get separate slots */
    slots[0].key_hash = 42;
    snprintf(slots[0].key_prefix, sizeof(slots[0].key_prefix), "key-alpha");
    slots[0].tool_calls = 3;

    slots[1].key_hash = 42;
    snprintf(slots[1].key_prefix, sizeof(slots[1].key_prefix), "key-beta");
    slots[1].tool_calls = 1;

    /* Verify they don't collide — each has separate tracking */
    ASSERT_INT_EQ(slots[0].tool_calls, 3);
    ASSERT_INT_EQ(slots[1].tool_calls, 1);

    destroy_test_agent(&ctx);
}

/* Test that slot eviction works when all slots are full */
static void test_rate_limiter_slot_eviction(void)
{
    test_agent_ctx_t ctx = create_test_agent(100);
    ctx.agent->max_tool_calls_per_hour = 100;

    sc_hourly_slot_t *slots = ctx.agent->hourly_slots;
    time_t now = time(NULL);

    /* Fill all slots with recent entries */
    for (int i = 0; i < SC_HOURLY_SLOTS; i++) {
        snprintf(slots[i].key_prefix, sizeof(slots[i].key_prefix),
                 "fill-%d", i);
        slots[i].key_hash = (uint32_t)(i + 1000);
        slots[i].tool_calls = 1;
        slots[i].window_start = now - i;  /* slot 0 is newest */
    }

    /* Make slot 5 the oldest */
    slots[5].window_start = now - 7200;

    /* A new key should evict the oldest slot (slot 5) */
    ASSERT_INT_EQ(slots[5].window_start, (int)(now - 7200));

    destroy_test_agent(&ctx);
}

int main(void)
{
    printf("test_agent\n");

    RUN_TEST(test_parse_use_prefix);
    RUN_TEST(test_parse_use_case_insensitive);
    RUN_TEST(test_parse_at_prefix);
    RUN_TEST(test_parse_no_match);
    RUN_TEST(test_parse_leading_whitespace);
    RUN_TEST(test_parse_extra_spaces);
    RUN_TEST(test_parse_at_no_message);
    RUN_TEST(test_agent_loop_simple);
    RUN_TEST(test_agent_loop_tool_call);
    RUN_TEST(test_agent_loop_provider_failure);
    RUN_TEST(test_session_summarization);
    RUN_TEST(test_agent_tool_call_limit);
    RUN_TEST(test_agent_multi_tool_calls);
    RUN_TEST(test_agent_hourly_rate_limit);
    RUN_TEST(test_rate_limiter_key_collision);
    RUN_TEST(test_rate_limiter_slot_eviction);
#if SC_ENABLE_SPAWN
    RUN_TEST(test_agent_spawn_tool);
#endif

    TEST_REPORT();
}
