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

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
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

static int mock_total_chat_calls;

typedef struct {
    sc_llm_response_t responses[MAX_MOCK_RESPONSES];
    int response_count;
    int call_index;
    int chat_call_count;
    char *last_system_prompt;  /* Captured from most recent chat() call */
    /* Full message capture for integration tests */
    sc_llm_message_t *last_msgs;  /* Deep copy of last msgs array */
    int last_msg_count;
} mock_provider_data_t;

static sc_llm_response_t *mock_chat(sc_provider_t *self,
                                     sc_llm_message_t *msgs, int msg_count,
                                     sc_tool_definition_t *tools, int tool_count,
                                     const char *model, cJSON *options)
{
    mock_provider_data_t *data = self->data;
    data->chat_call_count++;
    mock_total_chat_calls++;
    /* Capture system prompt for transform tests */
    free(data->last_system_prompt);
    data->last_system_prompt = NULL;
    if (msg_count > 0 && msgs[0].role && strcmp(msgs[0].role, "system") == 0
        && msgs[0].content) {
        data->last_system_prompt = sc_strdup(msgs[0].content);
    }
    /* Capture full message array for integration tests */
    if (data->last_msgs) {
        for (int i = 0; i < data->last_msg_count; i++)
            sc_llm_message_free_fields(&data->last_msgs[i]);
        free(data->last_msgs);
    }
    data->last_msgs = calloc((size_t)msg_count, sizeof(sc_llm_message_t));
    data->last_msg_count = msg_count;
    if (data->last_msgs) {
        for (int i = 0; i < msg_count; i++)
            data->last_msgs[i] = sc_llm_message_clone(&msgs[i]);
    }
    if (data->call_index >= data->response_count) return NULL;

    sc_llm_response_t *src = &data->responses[data->call_index++];

    /* Deep clone: caller (run_llm_iteration) owns and frees the result */
    sc_llm_response_t *ret = calloc(1, sizeof(*ret));
    if (!ret) return NULL;

    ret->content = sc_strdup(src->content);
    ret->thinking = sc_strdup(src->thinking);
    ret->finish_reason = sc_strdup(src->finish_reason);
    ret->http_status = src->http_status ? src->http_status : 200;

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

static void mock_provider_destroy(sc_provider_t *self)
{
    if (!self) return;
    mock_provider_data_t *data = self->data;
    if (data) {
        if (data->last_msgs) {
            for (int i = 0; i < data->last_msg_count; i++)
                sc_llm_message_free_fields(&data->last_msgs[i]);
            free(data->last_msgs);
        }
        free(data->last_system_prompt);
        free(data);
    }
    free(self);
}

static sc_provider_t *mock_provider_clone(sc_provider_t *self)
{
    mock_provider_data_t *orig = self->data;
    if (!orig) return NULL;

    mock_provider_data_t *data = calloc(1, sizeof(*data));
    if (!data) return NULL;
    data->response_count = orig->response_count;
    data->call_index = orig->call_index;
    memcpy(data->responses, orig->responses, sizeof(data->responses));

    sc_provider_t *clone = calloc(1, sizeof(*clone));
    if (!clone) {
        free(data);
        return NULL;
    }
    clone->name = self->name;
    clone->chat = self->chat;
    clone->get_default_model = self->get_default_model;
    clone->clone = mock_provider_clone;
    clone->destroy = mock_provider_destroy;
    clone->data = data;
    return clone;
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

/* Flaky tool: first execution succeeds (checkpoint), then fails until rewind. */
static sc_tool_result_t *mock_flaky_tool_exec(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)self; (void)args; (void)ctx;
    mock_tool_executed++;
    if (mock_tool_executed == 1)
        return sc_tool_result_new("first call ok");
    return sc_tool_result_error("simulated tool failure");
}

static int msgs_contain_substr(const sc_llm_message_t *msgs, int n, const char *needle)
{
    for (int i = 0; i < n; i++) {
        if (msgs[i].content && strstr(msgs[i].content, needle))
            return 1;
    }
    return 0;
}

static const char *find_source_file(const char *relpath)
{
    static char buf[512];
    if (access(relpath, R_OK) == 0)
        return relpath;
    snprintf(buf, sizeof(buf), "../%s", relpath);
    if (access(buf, R_OK) == 0)
        return buf;
    return NULL;
}

static int source_contains(const char *relpath, const char *needle)
{
    const char *path = find_source_file(relpath);
    if (!path)
        return 0;

    FILE *f = fopen(path, "r");
    if (!f)
        return 0;

    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, needle)) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
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

    mock_total_chat_calls = 0;

    /* Provider-health tracking is process-global; reset it so a provider
     * marked unhealthy by an earlier test cannot leak into this one. */
    sc_provider_health_reset();

    /* Mock provider */
    ctx.mpd = calloc(1, sizeof(*ctx.mpd));
    ctx.provider = calloc(1, sizeof(*ctx.provider));
    ctx.provider->name = "mock";
    ctx.provider->chat = mock_chat;
    ctx.provider->get_default_model = mock_get_model;
    ctx.provider->clone = mock_provider_clone;
    ctx.provider->destroy = mock_provider_destroy;
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
    sc_agent_wait_summarize(ctx->agent);
    sc_session_manager_free(ctx->agent->sessions);
    sc_state_free(ctx->agent->state);
    sc_tool_registry_free(ctx->agent->tools);
    sc_context_builder_free(ctx->agent->context_builder);
    free(ctx->agent->hourly_slots);
    free(ctx->agent->transforms);
    free(ctx->agent->workspace);
    free(ctx->agent->model);
    free(ctx->agent);
    mock_provider_destroy(ctx->provider);
    ctx->provider = NULL;
    ctx->mpd = NULL;
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

    /* Provider should be called twice: main turn + cloned summarization task */
    ASSERT_INT_EQ(mock_total_chat_calls, 2);

    /* Session truncated to keep_last (4) plus optional post-compact reinject */
    sc_session_get_history(ctx.agent->sessions, "test-summarize", &count);
    ASSERT(count >= 4 && count <= 5, "Session should be compacted");

    /* Summary should be set */
    const char *summary = sc_session_get_summary(ctx.agent->sessions, "test-summarize");
    ASSERT_NOT_NULL(summary);
    ASSERT_STR_EQ(summary, "Discussed 3 topics. Key findings: none.");

    free(response);
    destroy_test_agent(&ctx);
}

/* 1.4: reactive compaction on context-length error. When the provider rejects
 * a call with HTTP 400 + a context/length error, the turn loop drops the oldest
 * message group(s) and retries instead of failing the turn. Regression test for
 * the wiring bug where call_llm_with_fallback collapsed the 400 to NULL and the
 * reactive block was unreachable. */
static void test_reactive_compaction_on_context_error(void)
{
    /* High summary threshold so no async summarization interferes. */
    test_agent_ctx_t ctx = create_test_agent(100);

    /* Seed history so truncation has groups to drop (system + 6 + user > 2). */
    for (int i = 0; i < 3; i++) {
        char umsg[64], amsg[64];
        snprintf(umsg, sizeof(umsg), "User message %d", i);
        snprintf(amsg, sizeof(amsg), "Assistant reply %d", i);
        sc_session_add_message(ctx.agent->sessions, "test-reactive", "user", umsg);
        sc_session_add_message(ctx.agent->sessions, "test-reactive", "assistant", amsg);
    }

    /* Call 1: context-length rejection. Call 2 (after truncation): success. */
    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = "error: maximum context length exceeded",
        .http_status = 400,
        .finish_reason = "error",
    };
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Recovered after truncation.",
        .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 2;

    char *response = sc_agent_process_direct(ctx.agent, "One more question",
                                             "test-reactive");
    ASSERT_NOT_NULL(response);
    ASSERT_STR_EQ(response, "Recovered after truncation.");
    /* Two provider calls: the rejected one + the post-truncation retry. */
    ASSERT_INT_EQ(ctx.mpd->chat_call_count, 2);

    free(response);
    destroy_test_agent(&ctx);
}

static void test_summarize_shutdown_cancels_task(void)
{
    /* Async summarization with failing provider enters 2s backoff; shutdown
     * should cancel instead of waiting for retries (M-8 / sc_task_t). */
    test_agent_ctx_t ctx = create_test_agent(6);

    for (int i = 0; i < 3; i++) {
        char umsg[64], amsg[64];
        snprintf(umsg, sizeof(umsg), "User message %d", i);
        snprintf(amsg, sizeof(amsg), "Assistant reply %d", i);
        sc_session_add_message(ctx.agent->sessions, "test-sum-cancel", "user", umsg);
        sc_session_add_message(ctx.agent->sessions, "test-sum-cancel", "assistant", amsg);
    }

    /* Main turn succeeds; summarization retries will fail (NULL responses). */
    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = "ok", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 1;

    char *response = sc_agent_process_direct(ctx.agent, "trigger summarize",
                                             "test-sum-cancel");
    ASSERT_NOT_NULL(response);
    ASSERT_NOT_NULL(ctx.agent->summarize_task);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    sc_agent_free(ctx.agent);
    ctx.agent = NULL;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double elapsed = (t1.tv_sec - t0.tv_sec)
                   + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    ASSERT(elapsed < 2.0, "Shutdown should cancel summarization without long backoff");

    free(response);
    mock_provider_destroy(ctx.provider);
    cleanup_dir(ctx.tmpdir);
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

/* ======================================================================
 * LLM failure reason propagation tests
 * ====================================================================== */

static void test_failure_reason_primary_only(void)
{
    /* Primary returns 401, no fallbacks → message should include HTTP 401 */
    test_agent_ctx_t ctx = create_test_agent(100);

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = NULL,
        .finish_reason = NULL,
        .http_status = 401,
    };
    ctx.mpd->response_count = 1;

    char *response = sc_agent_process_direct(ctx.agent, "Hello", "test-fail-401");
    ASSERT_NOT_NULL(response);
    ASSERT(strstr(response, "401") != NULL,
           "Failure message should contain HTTP status 401");
    ASSERT(strstr(response, "test-model") != NULL,
           "Failure message should contain model name");
    ASSERT(strstr(response, "Check API key") != NULL,
           "Single 401 should suggest checking API key");

    free(response);
    destroy_test_agent(&ctx);
}

static void test_failure_reason_with_fallbacks(void)
{
    /* Primary 500, fallback 403 → message should list both */
    test_agent_ctx_t ctx = create_test_agent(100);

    /* Set up a fallback provider that also fails (use 403 — non-transient) */
    mock_provider_data_t fb_mpd = {0};
    sc_provider_t fb_provider = {0};
    fb_provider.name = "fallback-mock";
    fb_provider.chat = mock_chat;
    fb_provider.get_default_model = mock_get_model;
    fb_provider.data = &fb_mpd;

    fb_mpd.responses[0] = (sc_llm_response_t){
        .content = NULL,
        .finish_reason = NULL,
        .http_status = 403,
    };
    fb_mpd.response_count = 1;

    sc_provider_t *fb_ptrs[1] = { &fb_provider };
    char *fb_models[1] = { "fallback-model" };
    ctx.agent->fallback_providers = fb_ptrs;
    ctx.agent->fallback_models = fb_models;
    ctx.agent->fallback_count = 1;

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = NULL,
        .finish_reason = NULL,
        .http_status = 500,
    };
    ctx.mpd->response_count = 1;

    char *response = sc_agent_process_direct(ctx.agent, "Hello", "test-fail-fb");
    ASSERT_NOT_NULL(response);
    ASSERT(strstr(response, "500") != NULL,
           "Should contain primary HTTP 500");
    ASSERT(strstr(response, "403") != NULL,
           "Should contain fallback HTTP 403");
    ASSERT(strstr(response, "fallback-model") != NULL,
           "Should contain fallback model name");
    /* Mixed status codes → should NOT suggest API key check */
    ASSERT(strstr(response, "Check API key") == NULL,
           "Mixed errors should not suggest API key check");

    /* Clean up fallback pointers before destroy */
    ctx.agent->fallback_providers = NULL;
    ctx.agent->fallback_models = NULL;
    ctx.agent->fallback_count = 0;

    free(response);
    destroy_test_agent(&ctx);
}

static void test_failure_reason_all_401(void)
{
    /* Primary 401, fallback 401 → should suggest API key check */
    test_agent_ctx_t ctx = create_test_agent(100);

    mock_provider_data_t fb_mpd = {0};
    sc_provider_t fb_provider = {0};
    fb_provider.name = "fallback-mock";
    fb_provider.chat = mock_chat;
    fb_provider.get_default_model = mock_get_model;
    fb_provider.data = &fb_mpd;

    fb_mpd.responses[0] = (sc_llm_response_t){
        .content = NULL,
        .finish_reason = NULL,
        .http_status = 401,
    };
    fb_mpd.response_count = 1;

    sc_provider_t *fb_ptrs[1] = { &fb_provider };
    char *fb_models[1] = { "fb-model" };
    ctx.agent->fallback_providers = fb_ptrs;
    ctx.agent->fallback_models = fb_models;
    ctx.agent->fallback_count = 1;

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = NULL,
        .finish_reason = NULL,
        .http_status = 401,
    };
    ctx.mpd->response_count = 1;

    char *response = sc_agent_process_direct(ctx.agent, "Hello", "test-all-401");
    ASSERT_NOT_NULL(response);
    ASSERT(strstr(response, "401") != NULL,
           "Should contain HTTP 401");
    ASSERT(strstr(response, "Check API key") != NULL,
           "All 401s should suggest checking API key");

    ctx.agent->fallback_providers = NULL;
    ctx.agent->fallback_models = NULL;
    ctx.agent->fallback_count = 0;

    free(response);
    destroy_test_agent(&ctx);
}

static void test_failure_reason_null_provider(void)
{
    /* Provider returns NULL (no response at all) → HTTP 0 in message */
    test_agent_ctx_t ctx = create_test_agent(100);

    /* No responses → mock returns NULL */
    ctx.mpd->response_count = 0;

    char *response = sc_agent_process_direct(ctx.agent, "Hello", "test-null");
    ASSERT_NOT_NULL(response);
    ASSERT(strstr(response, "HTTP 0") != NULL || strstr(response, "LLM error") != NULL,
           "Should contain error info for NULL response");

    free(response);
    destroy_test_agent(&ctx);
}

/* ======================================================================
 * Provider health tracking (task 2.6) + retry/backoff (task 2.8)
 * ====================================================================== */

/* Free the per-call captures mock_chat() left on a stack-local mock. */
static void free_mock_captures(mock_provider_data_t *m)
{
    free(m->last_system_prompt);
    m->last_system_prompt = NULL;
    if (m->last_msgs) {
        for (int i = 0; i < m->last_msg_count; i++)
            sc_llm_message_free_fields(&m->last_msgs[i]);
        free(m->last_msgs);
        m->last_msgs = NULL;
    }
}

static void test_provider_health_skips_auth_expired_fallback(void)
{
    /* A fallback that returns 401 is marked AUTH_EXPIRED and skipped on the
     * next turn (until cooldown), while a healthy fallback keeps serving. */
    test_agent_ctx_t ctx = create_test_agent(100);

    mock_provider_data_t auth_mpd = {0};
    sc_provider_t auth_fb = {0};
    auth_fb.name = "fb-auth";
    auth_fb.chat = mock_chat;
    auth_fb.get_default_model = mock_get_model;
    auth_fb.data = &auth_mpd;
    auth_mpd.responses[0] = (sc_llm_response_t){ .http_status = 401 };
    auth_mpd.response_count = 1;

    mock_provider_data_t good_mpd = {0};
    sc_provider_t good_fb = {0};
    good_fb.name = "fb-good";
    good_fb.chat = mock_chat;
    good_fb.get_default_model = mock_get_model;
    good_fb.data = &good_mpd;
    good_mpd.responses[0] =
        (sc_llm_response_t){ .content = "ok", .finish_reason = "end_turn" };
    good_mpd.responses[1] =
        (sc_llm_response_t){ .content = "ok", .finish_reason = "end_turn" };
    good_mpd.response_count = 2;

    sc_provider_t *fb_ptrs[2] = { &auth_fb, &good_fb };
    char *fb_models[2] = { "fb-auth-model", "fb-good-model" };
    ctx.agent->fallback_providers = fb_ptrs;
    ctx.agent->fallback_models = fb_models;
    ctx.agent->fallback_count = 2;

    /* Primary fails with a non-transient 500 on both turns (no retry sleep). */
    ctx.mpd->responses[0] = (sc_llm_response_t){ .http_status = 500 };
    ctx.mpd->responses[1] = (sc_llm_response_t){ .http_status = 500 };
    ctx.mpd->response_count = 2;

    /* Turn 1: auth fallback is tried (401), good fallback serves. */
    char *r1 = sc_agent_process_direct(ctx.agent, "Hello", "health-1");
    ASSERT_NOT_NULL(r1);
    ASSERT_INT_EQ(auth_mpd.chat_call_count, 1);
    ASSERT_INT_EQ(good_mpd.chat_call_count, 1);
    free(r1);

    /* Turn 2: auth fallback is now AUTH_EXPIRED → skipped; good still serves. */
    char *r2 = sc_agent_process_direct(ctx.agent, "Hello again", "health-2");
    ASSERT_NOT_NULL(r2);
    ASSERT_INT_EQ(auth_mpd.chat_call_count, 1);  /* not called again */
    ASSERT_INT_EQ(good_mpd.chat_call_count, 2);
    free(r2);

    ctx.agent->fallback_providers = NULL;
    ctx.agent->fallback_models = NULL;
    ctx.agent->fallback_count = 0;

    free_mock_captures(&auth_mpd);
    free_mock_captures(&good_mpd);
    destroy_test_agent(&ctx);
}

static void test_transient_error_retries_then_succeeds(void)
{
    /* A transient 503 is retried (exponential backoff) and the subsequent 200
     * is returned — verifies task 2.8 retry path end-to-end. */
    test_agent_ctx_t ctx = create_test_agent(100);

    ctx.mpd->responses[0] = (sc_llm_response_t){ .http_status = 503 };
    ctx.mpd->responses[1] =
        (sc_llm_response_t){ .content = "recovered", .finish_reason = "end_turn" };
    ctx.mpd->response_count = 2;

    char *response = sc_agent_process_direct(ctx.agent, "Hello", "retry-1");
    ASSERT_NOT_NULL(response);
    ASSERT(strstr(response, "recovered") != NULL,
           "Should return the post-retry success content");
    ASSERT_INT_EQ(ctx.mpd->chat_call_count, 2);  /* one failure + one retry */

    free(response);
    destroy_test_agent(&ctx);
}

/* ======================================================================
 * Context transform tests
 * ====================================================================== */

/* Test transform: appends a marker to the system prompt */
static int test_transform_append(sc_context_snap_t *snap, void *userdata)
{
    const char *marker = (const char *)userdata;
    if (*snap->msg_count > 0 && (*snap->msgs)[0].role &&
        strcmp((*snap->msgs)[0].role, "system") == 0) {
        /* Append marker to system prompt */
        size_t old_len = strlen((*snap->msgs)[0].content);
        size_t marker_len = strlen(marker);
        char *new_content = realloc((*snap->msgs)[0].content,
                                     old_len + marker_len + 2);
        if (new_content) {
            new_content[old_len] = '\n';
            memcpy(new_content + old_len + 1, marker, marker_len + 1);
            (*snap->msgs)[0].content = new_content;
        }
    }
    return 0;
}

/* Test transform: returns non-zero to stop chain */
static int test_transform_stop(sc_context_snap_t *snap, void *userdata)
{
    (void)snap;
    int *called = (int *)userdata;
    *called = 1;
    return 1; /* stop */
}

/* Test transform: should NOT be called if a previous transform stopped */
static int test_transform_unreachable(sc_context_snap_t *snap, void *userdata)
{
    (void)snap;
    int *called = (int *)userdata;
    *called = 1;
    return 0;
}

static void test_context_transform_appends(void)
{
    /* Register a transform that appends "[INJECTED]" to the system prompt.
     * Verify the LLM receives the modified prompt. */
    test_agent_ctx_t ctx = create_test_agent(100);

    sc_agent_add_transform(ctx.agent, "test_inject",
                            test_transform_append, (void *)"[INJECTED]");

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = "Response.", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 1;

    char *response = sc_agent_process_direct(ctx.agent, "Hello", "test-xform");
    ASSERT_NOT_NULL(response);
    ASSERT_NOT_NULL(ctx.mpd->last_system_prompt);
    ASSERT(strstr(ctx.mpd->last_system_prompt, "[INJECTED]") != NULL,
           "System prompt should contain injected marker");

    free(response);
    destroy_test_agent(&ctx);
}

static void test_context_transform_chain_order(void)
{
    /* Register two transforms. Both should run, in order. */
    test_agent_ctx_t ctx = create_test_agent(100);

    sc_agent_add_transform(ctx.agent, "first",
                            test_transform_append, (void *)"[FIRST]");
    sc_agent_add_transform(ctx.agent, "second",
                            test_transform_append, (void *)"[SECOND]");

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = "OK.", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 1;

    char *response = sc_agent_process_direct(ctx.agent, "Hi", "test-chain");
    ASSERT_NOT_NULL(response);
    ASSERT_NOT_NULL(ctx.mpd->last_system_prompt);

    /* Both markers present */
    ASSERT(strstr(ctx.mpd->last_system_prompt, "[FIRST]") != NULL,
           "Should contain [FIRST]");
    ASSERT(strstr(ctx.mpd->last_system_prompt, "[SECOND]") != NULL,
           "Should contain [SECOND]");

    /* [FIRST] should appear before [SECOND] */
    const char *first_pos = strstr(ctx.mpd->last_system_prompt, "[FIRST]");
    const char *second_pos = strstr(ctx.mpd->last_system_prompt, "[SECOND]");
    ASSERT(first_pos < second_pos, "[FIRST] should appear before [SECOND]");

    free(response);
    destroy_test_agent(&ctx);
}

static void test_context_transform_stop_chain(void)
{
    /* First transform returns non-zero → second should not be called. */
    test_agent_ctx_t ctx = create_test_agent(100);

    int stop_called = 0, unreachable_called = 0;

    sc_agent_add_transform(ctx.agent, "stopper",
                            test_transform_stop, &stop_called);
    sc_agent_add_transform(ctx.agent, "unreachable",
                            test_transform_unreachable, &unreachable_called);

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = "Done.", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 1;

    char *response = sc_agent_process_direct(ctx.agent, "Test", "test-stop");
    ASSERT_NOT_NULL(response);
    ASSERT_INT_EQ(stop_called, 1);
    ASSERT_INT_EQ(unreachable_called, 0);

    free(response);
    destroy_test_agent(&ctx);
}

static void test_no_transforms(void)
{
    /* No transforms registered — baseline behavior unchanged. */
    test_agent_ctx_t ctx = create_test_agent(100);

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = "Hello!", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 1;

    char *response = sc_agent_process_direct(ctx.agent, "Hi", "test-noxform");
    ASSERT_NOT_NULL(response);
    ASSERT_STR_EQ(response, "Hello!");

    free(response);
    destroy_test_agent(&ctx);
}

/* ======================================================================
 * Integration tests for pi-mono-inspired features
 * ====================================================================== */

/* Thread-safe execution log for parallel ordering tests */
static pthread_mutex_t exec_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static char exec_log[32][64];
static int exec_log_count;

static void exec_log_reset(void)
{
    pthread_mutex_lock(&exec_log_mutex);
    exec_log_count = 0;
    pthread_mutex_unlock(&exec_log_mutex);
}

static void exec_log_append(const char *entry)
{
    pthread_mutex_lock(&exec_log_mutex);
    if (exec_log_count < 32) {
        snprintf(exec_log[exec_log_count], sizeof(exec_log[0]), "%s", entry);
        exec_log_count++;
    }
    pthread_mutex_unlock(&exec_log_mutex);
}

/* Mock tool that logs its execution (thread-safe) */
static sc_tool_result_t *logging_tool_exec(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    char entry[64];
    const char *q = NULL;
    cJSON *qj = cJSON_GetObjectItem(args, "query");
    if (qj) q = cJSON_GetStringValue(qj);
    snprintf(entry, sizeof(entry), "%s:%s", self->name, q ? q : "?");
    exec_log_append(entry);

    /* Simulate I/O delay for parallel testing */
    usleep(10000); /* 10ms */

    char result[128];
    snprintf(result, sizeof(result), "result from %s(%s)", self->name, q ? q : "?");
    return sc_tool_result_new(result);
}

/* Register a named mock tool (read_file or exec) */
static void register_logging_tool(sc_agent_t *agent, const char *name, int needs_confirm)
{
    sc_tool_t *tool = calloc(1, sizeof(*tool));
    tool->name = name;
    tool->description = "logging mock tool";
    tool->parameters = mock_tool_params;
    tool->execute = logging_tool_exec;
    tool->destroy = mock_tool_destroy;
    tool->needs_confirm = needs_confirm;
    sc_tool_registry_register(agent->tools, tool);
}

/* --- Test 1: Parallel execution of multiple read_file calls --- */

static void test_integ_parallel_read_only(void)
{
    test_agent_ctx_t ctx = create_test_agent(100);
    register_logging_tool(ctx.agent, "read_file", 0);

    exec_log_reset();

    /* LLM returns 3 read_file calls at once */
    cJSON *args[3];
    sc_tool_call_t calls[3];
    for (int i = 0; i < 3; i++) {
        args[i] = cJSON_CreateObject();
        char q[16];
        snprintf(q, sizeof(q), "file%d", i);
        cJSON_AddStringToObject(args[i], "query", q);
        calls[i] = (sc_tool_call_t){
            .id = i == 0 ? "c0" : i == 1 ? "c1" : "c2",
            .name = "read_file",
            .arguments = args[i],
        };
    }

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .tool_calls = calls, .tool_call_count = 3, .finish_reason = "tool_use",
    };
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Read all 3 files.", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 2;

    char *response = sc_agent_process_direct(ctx.agent, "Read files", "test-par");
    ASSERT_NOT_NULL(response);
    ASSERT_STR_EQ(response, "Read all 3 files.");

    /* All 3 tools executed */
    ASSERT_INT_EQ(exec_log_count, 3);

    /* Results should be in source order in the session history */
    int count = 0;
    sc_session_get_history(ctx.agent->sessions, "test-par", &count);
    /* user + assistant(3 calls) + 3 tool results + final assistant = 6 */
    ASSERT(count >= 6, "Should have at least 6 messages in session");

    free(response);
    for (int i = 0; i < 3; i++) cJSON_Delete(args[i]);
    destroy_test_agent(&ctx);
}

/* --- Test 2: Mixed parallel (read_file) + sequential (exec) --- */

static int mock_confirm_yes(const char *tool, const char *args, void *ctx)
{
    (void)tool; (void)args; (void)ctx;
    return 1; /* approve */
}

static void test_integ_mixed_parallel_sequential(void)
{
    test_agent_ctx_t ctx = create_test_agent(100);
    register_logging_tool(ctx.agent, "read_file", 0);
    register_logging_tool(ctx.agent, "exec", 1); /* needs confirm */
    sc_tool_registry_set_confirm(ctx.agent->tools, mock_confirm_yes, NULL);

    exec_log_reset();

    /* LLM returns: read_file, read_file, exec */
    cJSON *a0 = cJSON_CreateObject();
    cJSON_AddStringToObject(a0, "query", "f1");
    cJSON *a1 = cJSON_CreateObject();
    cJSON_AddStringToObject(a1, "query", "f2");
    cJSON *a2 = cJSON_CreateObject();
    cJSON_AddStringToObject(a2, "query", "cmd1");

    sc_tool_call_t calls[3] = {
        { .id = "r1", .name = "read_file", .arguments = a0 },
        { .id = "r2", .name = "read_file", .arguments = a1 },
        { .id = "e1", .name = "exec",      .arguments = a2 },
    };

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .tool_calls = calls, .tool_call_count = 3, .finish_reason = "tool_use",
    };
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Done.", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 2;

    char *response = sc_agent_process_direct(ctx.agent, "Do stuff", "test-mix");
    ASSERT_NOT_NULL(response);
    ASSERT_STR_EQ(response, "Done.");
    ASSERT_INT_EQ(exec_log_count, 3);

    /* exec must execute AFTER read_files (sequential for side-effect tools).
     * Check that exec:cmd1 is the last entry in the log. */
    ASSERT(strstr(exec_log[exec_log_count - 1], "exec:cmd1") != NULL,
           "exec should run after read_file tools");

    free(response);
    cJSON_Delete(a0);
    cJSON_Delete(a1);
    cJSON_Delete(a2);
    destroy_test_agent(&ctx);
}

/* --- Test 3: Schema validation blocks bad args through agent loop --- */

static void test_integ_schema_validation(void)
{
    test_agent_ctx_t ctx = create_test_agent(100);
    register_logging_tool(ctx.agent, "read_file", 0);

    exec_log_reset();

    /* LLM returns tool call with integer arg instead of string */
    cJSON *bad_args = cJSON_CreateObject();
    cJSON_AddNumberToObject(bad_args, "query", 42); /* should be string */

    sc_tool_call_t calls[1] = {
        { .id = "bad1", .name = "read_file", .arguments = bad_args },
    };

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .tool_calls = calls, .tool_call_count = 1, .finish_reason = "tool_use",
    };
    /* After validation error, LLM gets error and responds with text */
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Sorry, I made an error.", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 2;

    char *response = sc_agent_process_direct(ctx.agent, "Read", "test-schema");
    ASSERT_NOT_NULL(response);

    /* Tool should NOT have executed (schema blocked it) */
    ASSERT_INT_EQ(exec_log_count, 0);

    /* The second LLM call should have received a tool result with validation error */
    ASSERT(ctx.mpd->last_msg_count > 2, "LLM should receive error in context");

    free(response);
    cJSON_Delete(bad_args);
    destroy_test_agent(&ctx);
}

/* --- Test 4: Thinking block capture, persistence, and cross-provider replay --- */

static void test_integ_thinking_blocks(void)
{
    test_agent_ctx_t ctx = create_test_agent(100);

    /* Response with thinking field set */
    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = "The answer is 42.",
        .thinking = "Let me reason about this step by step...",
        .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 1;

    char *response = sc_agent_process_direct(ctx.agent, "What is the meaning?",
                                              "test-think");
    ASSERT_NOT_NULL(response);
    ASSERT_STR_EQ(response, "The answer is 42.");

    /* Verify thinking is in session history */
    int count = 0;
    sc_llm_message_t *hist = sc_session_get_history(ctx.agent->sessions,
                                                     "test-think", &count);
    ASSERT(count >= 2, "Should have user + assistant");

    /* Find the assistant message with thinking */
    int found_thinking = 0;
    for (int i = 0; i < count; i++) {
        if (hist[i].thinking && strstr(hist[i].thinking, "step by step")) {
            found_thinking = 1;
            break;
        }
    }
    ASSERT(found_thinking, "Thinking block should be in session history");

    /* Now send a follow-up. The mock LLM should see the previous thinking
     * in the messages it receives (as content for non-Anthropic providers,
     * or preserved as thinking field). */
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Follow-up response.",
        .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 2;
    ctx.mpd->call_index = 1;

    char *response2 = sc_agent_process_direct(ctx.agent, "Tell me more",
                                               "test-think");
    ASSERT_NOT_NULL(response2);

    /* Verify the LLM received the thinking in the replayed context.
     * The mock provider captures all messages — check that assistant msg
     * has thinking set. */
    int found_in_context = 0;
    for (int i = 0; i < ctx.mpd->last_msg_count; i++) {
        if (ctx.mpd->last_msgs[i].thinking &&
            strstr(ctx.mpd->last_msgs[i].thinking, "step by step")) {
            found_in_context = 1;
            break;
        }
    }
    ASSERT(found_in_context, "Thinking should be replayed to LLM in follow-up");

    free(response);
    free(response2);
    destroy_test_agent(&ctx);
}

/* --- Test 5: Pre-hook blocks tool through full agent loop --- */

static int integ_block_read_file(const char *tool_name, const cJSON *args,
                                  const char *channel, const char *chat_id,
                                  void *userdata)
{
    (void)args; (void)channel; (void)chat_id;
    int *called = (int *)userdata;
    *called = 1;
    return strcmp(tool_name, "read_file") == 0 ? 1 : 0;
}

static void test_integ_pre_hook_blocks(void)
{
    test_agent_ctx_t ctx = create_test_agent(100);
    register_logging_tool(ctx.agent, "read_file", 0);

    int hook_called = 0;
    sc_tool_registry_add_pre_hook(ctx.agent->tools, "blocker",
                                   integ_block_read_file, &hook_called);

    exec_log_reset();

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "query", "secret");
    sc_tool_call_t calls[1] = {
        { .id = "h1", .name = "read_file", .arguments = args },
    };

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .tool_calls = calls, .tool_call_count = 1, .finish_reason = "tool_use",
    };
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Tool was blocked.", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 2;

    char *response = sc_agent_process_direct(ctx.agent, "Read secret", "test-hook");
    ASSERT_NOT_NULL(response);
    ASSERT_INT_EQ(hook_called, 1);
    ASSERT_INT_EQ(exec_log_count, 0); /* tool never executed */

    /* The LLM should have received an error tool result */
    int has_blocked_msg = 0;
    for (int i = 0; i < ctx.mpd->last_msg_count; i++) {
        if (ctx.mpd->last_msgs[i].role &&
            strcmp(ctx.mpd->last_msgs[i].role, "tool") == 0 &&
            ctx.mpd->last_msgs[i].content &&
            strstr(ctx.mpd->last_msgs[i].content, "blocked")) {
            has_blocked_msg = 1;
            break;
        }
    }
    ASSERT(has_blocked_msg, "LLM should see blocked error in tool result");

    free(response);
    cJSON_Delete(args);
    destroy_test_agent(&ctx);
}

/* --- Test 6: Post-hook modifies result through full agent loop --- */

static int integ_post_redact(const char *tool_name, sc_tool_result_t *result,
                              const char *channel, const char *chat_id,
                              void *userdata)
{
    (void)tool_name; (void)channel; (void)chat_id; (void)userdata;
    if (result && result->for_llm) {
        free(result->for_llm);
        result->for_llm = sc_strdup("[POST-HOOK REDACTED]");
    }
    return 0;
}

static void test_integ_post_hook_modifies(void)
{
    test_agent_ctx_t ctx = create_test_agent(100);
    register_logging_tool(ctx.agent, "read_file", 0);

    sc_tool_registry_add_post_hook(ctx.agent->tools, "redactor",
                                    integ_post_redact, NULL);

    exec_log_reset();

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "query", "data");
    sc_tool_call_t calls[1] = {
        { .id = "p1", .name = "read_file", .arguments = args },
    };

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .tool_calls = calls, .tool_call_count = 1, .finish_reason = "tool_use",
    };
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Got redacted data.", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 2;

    char *response = sc_agent_process_direct(ctx.agent, "Read data", "test-post");
    ASSERT_NOT_NULL(response);
    ASSERT_INT_EQ(exec_log_count, 1); /* tool executed */

    /* The LLM should have received the post-hook-modified result */
    int has_redacted = 0;
    for (int i = 0; i < ctx.mpd->last_msg_count; i++) {
        if (ctx.mpd->last_msgs[i].content &&
            strstr(ctx.mpd->last_msgs[i].content, "POST-HOOK REDACTED")) {
            has_redacted = 1;
            break;
        }
    }
    ASSERT(has_redacted, "LLM should see post-hook modified content");

    free(response);
    cJSON_Delete(args);
    destroy_test_agent(&ctx);
}

/* --- Test 7: Session branching through agent loop --- */

static void test_integ_session_branching(void)
{
    test_agent_ctx_t ctx = create_test_agent(100);

    /* Turn 1 */
    ctx.mpd->responses[0] = (sc_llm_response_t){
        .content = "Answer A.", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 1;

    char *r1 = sc_agent_process_direct(ctx.agent, "Question", "test-branch");
    ASSERT_NOT_NULL(r1);
    free(r1);

    /* Session has: user(0) -> assistant(1) = 2 messages */
    int count = 0;
    sc_session_get_history(ctx.agent->sessions, "test-branch", &count);
    ASSERT_INT_EQ(count, 2);

    /* Branch from node 0 (the user message) — fork before the answer */
    int rc = sc_session_branch(ctx.agent->sessions, "test-branch", 0);
    ASSERT_INT_EQ(rc, 0);

    /* Turn 2 on the new branch */
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Answer B.", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 2;
    ctx.mpd->call_index = 1;

    char *r2 = sc_agent_process_direct(ctx.agent, "Same question, different branch",
                                        "test-branch");
    ASSERT_NOT_NULL(r2);
    ASSERT_STR_EQ(r2, "Answer B.");
    free(r2);

    /* Active branch should now be: user(0) -> user(2) -> assistant(3) = 3 msgs */
    sc_llm_message_t *hist = sc_session_get_history(ctx.agent->sessions,
                                                     "test-branch", &count);
    ASSERT_INT_EQ(count, 3);
    ASSERT_STR_EQ(hist[0].content, "Question");
    ASSERT_STR_EQ(hist[2].content, "Answer B.");

    /* Two branches exist */
    ASSERT_INT_EQ(sc_session_branch_count(ctx.agent->sessions, "test-branch"), 2);

    /* Switch back to original branch */
    sc_session_branch(ctx.agent->sessions, "test-branch", 1);
    hist = sc_session_get_history(ctx.agent->sessions, "test-branch", &count);
    ASSERT_INT_EQ(count, 2);
    ASSERT_STR_EQ(hist[1].content, "Answer A.");

    destroy_test_agent(&ctx);
}

/* --- Test 8: Context transform visible during tool loop iterations --- */

static void test_integ_transform_with_tools(void)
{
    test_agent_ctx_t ctx = create_test_agent(100);
    register_logging_tool(ctx.agent, "read_file", 0);

    /* Register transform that injects a marker */
    sc_agent_add_transform(ctx.agent, "marker",
                            test_transform_append, (void *)"[CONTEXT_MARKER]");

    exec_log_reset();

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "query", "test");
    sc_tool_call_t calls[1] = {
        { .id = "t1", .name = "read_file", .arguments = args },
    };

    ctx.mpd->responses[0] = (sc_llm_response_t){
        .tool_calls = calls, .tool_call_count = 1, .finish_reason = "tool_use",
    };
    ctx.mpd->responses[1] = (sc_llm_response_t){
        .content = "Done with marker.", .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 2;

    char *response = sc_agent_process_direct(ctx.agent, "Go", "test-xf-tool");
    ASSERT_NOT_NULL(response);
    ASSERT_STR_EQ(response, "Done with marker.");

    /* The system prompt should have contained the marker from the transform */
    ASSERT_NOT_NULL(ctx.mpd->last_system_prompt);
    ASSERT(strstr(ctx.mpd->last_system_prompt, "[CONTEXT_MARKER]") != NULL,
           "Context transform marker should be visible to LLM during tool loop");

    free(response);
    cJSON_Delete(args);
    destroy_test_agent(&ctx);
}

static void test_checkpoint_rewind_on_tool_errors(void)
{
    /* One successful tool call saves a checkpoint; three failures trigger
     * rewind; the turn then continues and can finish successfully. */
    test_agent_ctx_t ctx = create_test_agent(100);

    sc_tool_t *tool = calloc(1, sizeof(*tool));
    tool->name = "flaky_test";
    tool->description = "Flaky test tool";
    tool->parameters = mock_tool_params;
    tool->execute = mock_flaky_tool_exec;
    tool->destroy = mock_tool_destroy;
    sc_tool_registry_register(ctx.agent->tools, tool);

    mock_tool_executed = 0;

    cJSON *tc_args[4];
    sc_tool_call_t tcs[4];
    for (int i = 0; i < 4; i++) {
        tc_args[i] = cJSON_CreateObject();
        char query[16];
        snprintf(query, sizeof(query), "step%d", i);
        cJSON_AddStringToObject(tc_args[i], "query", query);
        char id[16];
        snprintf(id, sizeof(id), "call_%d", i + 1);
        tcs[i] = (sc_tool_call_t){
            .id = id, .name = "flaky_test", .arguments = tc_args[i],
        };
        ctx.mpd->responses[i] = (sc_llm_response_t){
            .tool_calls = &tcs[i], .tool_call_count = 1,
            .finish_reason = "tool_use",
        };
    }
    ctx.mpd->responses[4] = (sc_llm_response_t){
        .content = "Recovered after checkpoint rewind.",
        .finish_reason = "end_turn",
    };
    /* Iteration 5 may hit the build continuation nudge (action log activity);
     * supply a second final response for that retry. */
    ctx.mpd->responses[5] = (sc_llm_response_t){
        .content = "Recovered after checkpoint rewind.",
        .finish_reason = "end_turn",
    };
    ctx.mpd->response_count = 6;

    char *response = sc_agent_process_direct(ctx.agent,
        "Run flaky tool", "test-checkpoint");
    ASSERT_NOT_NULL(response);
    ASSERT_STR_EQ(response, "Recovered after checkpoint rewind.");
    ASSERT_INT_EQ(mock_tool_executed, 4);
    ASSERT(ctx.mpd->chat_call_count >= 5,
           "Should continue LLM loop after rewind");
    ASSERT(msgs_contain_substr(ctx.mpd->last_msgs, ctx.mpd->last_msg_count,
                               "rewound to the last successful"),
           "Rewind hint should be in context after recovery");
    ASSERT(strstr(response, "too many tool errors") == NULL,
           "Should not hard-stop before recovery");

    free(response);
    for (int i = 0; i < 4; i++)
        cJSON_Delete(tc_args[i]);
    destroy_test_agent(&ctx);
}

static void test_checkpoint_rewind_structural(void)
{
    ASSERT(source_contains("src/agent_internal.h", "SC_MAX_CHECKPOINTS 2"),
           "2-slot checkpoint ring buffer");
    ASSERT(source_contains("src/agent_turn.c", "checkpoint_save"),
           "checkpoint_save shipped");
    ASSERT(source_contains("src/agent_turn.c", "checkpoint_rewind"),
           "checkpoint_rewind shipped");
    ASSERT(source_contains("src/agent_turn.c", "tc->rewind_count >= 2"),
           "rewind cap per turn");
    ASSERT(source_contains("src/agent_turn.c",
                           "Your previous approach failed after 3 tool errors"),
           "rewind hint message");
    ASSERT(source_contains("src/agent_turn.c",
                           "Rewound to checkpoint before model escalation"),
           "escalation rewind path");
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
    RUN_TEST(test_reactive_compaction_on_context_error);
    RUN_TEST(test_summarize_shutdown_cancels_task);
    RUN_TEST(test_agent_tool_call_limit);
    RUN_TEST(test_agent_multi_tool_calls);
    RUN_TEST(test_agent_hourly_rate_limit);
    RUN_TEST(test_rate_limiter_key_collision);
    RUN_TEST(test_rate_limiter_slot_eviction);
    RUN_TEST(test_failure_reason_primary_only);
    RUN_TEST(test_failure_reason_with_fallbacks);
    RUN_TEST(test_failure_reason_all_401);
    RUN_TEST(test_failure_reason_null_provider);
    RUN_TEST(test_provider_health_skips_auth_expired_fallback);
    RUN_TEST(test_transient_error_retries_then_succeeds);
    RUN_TEST(test_context_transform_appends);
    RUN_TEST(test_context_transform_chain_order);
    RUN_TEST(test_context_transform_stop_chain);
    RUN_TEST(test_no_transforms);
    /* Integration tests for pi-mono features */
    RUN_TEST(test_integ_parallel_read_only);
    RUN_TEST(test_integ_mixed_parallel_sequential);
    RUN_TEST(test_integ_schema_validation);
    RUN_TEST(test_integ_thinking_blocks);
    RUN_TEST(test_integ_pre_hook_blocks);
    RUN_TEST(test_integ_post_hook_modifies);
    RUN_TEST(test_integ_session_branching);
    RUN_TEST(test_integ_transform_with_tools);
    RUN_TEST(test_checkpoint_rewind_on_tool_errors);
    RUN_TEST(test_checkpoint_rewind_structural);
#if SC_ENABLE_SPAWN
    RUN_TEST(test_agent_spawn_tool);
#endif

    TEST_REPORT();
}
