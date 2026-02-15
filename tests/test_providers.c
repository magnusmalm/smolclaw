/*
 * smolclaw - provider tests
 * Tests HTTP provider JSON request building and response parsing.
 * Integration tests use mock_http.h for real HTTP round-trips.
 */

#include "test_main.h"
#include "mock_http.h"
#include "providers/types.h"
#include "providers/http.h"
#include "providers/claude.h"
#include "providers/factory.h"
#include "config.h"
#include "cJSON.h"
#include "util/str.h"

static void test_message_constructors(void)
{
    /* System message */
    sc_llm_message_t sys = sc_msg_system("You are helpful.");
    ASSERT_STR_EQ(sys.role, "system");
    ASSERT_STR_EQ(sys.content, "You are helpful.");
    ASSERT_INT_EQ(sys.tool_call_count, 0);
    ASSERT_NULL(sys.tool_call_id);
    sc_llm_message_free_fields(&sys);

    /* User message */
    sc_llm_message_t user = sc_msg_user("Hello!");
    ASSERT_STR_EQ(user.role, "user");
    ASSERT_STR_EQ(user.content, "Hello!");
    sc_llm_message_free_fields(&user);

    /* Assistant message */
    sc_llm_message_t asst = sc_msg_assistant("Hi there!");
    ASSERT_STR_EQ(asst.role, "assistant");
    ASSERT_STR_EQ(asst.content, "Hi there!");
    sc_llm_message_free_fields(&asst);

    /* Tool result message */
    sc_llm_message_t tool = sc_msg_tool_result("call-123", "File contents here");
    ASSERT_STR_EQ(tool.role, "tool");
    ASSERT_STR_EQ(tool.content, "File contents here");
    ASSERT_STR_EQ(tool.tool_call_id, "call-123");
    sc_llm_message_free_fields(&tool);
}

static void test_message_clone(void)
{
    /* Clone a simple message */
    sc_llm_message_t orig = sc_msg_user("test content");
    sc_llm_message_t clone = sc_llm_message_clone(&orig);

    ASSERT_STR_EQ(clone.role, orig.role);
    ASSERT_STR_EQ(clone.content, orig.content);
    ASSERT(clone.role != orig.role, "Clone should have its own copy of role");
    ASSERT(clone.content != orig.content, "Clone should have its own copy of content");

    sc_llm_message_free_fields(&orig);
    sc_llm_message_free_fields(&clone);

    /* Clone a tool result */
    sc_llm_message_t tool = sc_msg_tool_result("id-456", "result data");
    sc_llm_message_t tool_clone = sc_llm_message_clone(&tool);

    ASSERT_STR_EQ(tool_clone.role, "tool");
    ASSERT_STR_EQ(tool_clone.tool_call_id, "id-456");
    ASSERT_STR_EQ(tool_clone.content, "result data");

    sc_llm_message_free_fields(&tool);
    sc_llm_message_free_fields(&tool_clone);
}

static void test_message_with_tool_calls(void)
{
    /* Create tool calls */
    sc_tool_call_t calls[2];

    calls[0].id = sc_strdup("call-1");
    calls[0].name = sc_strdup("read_file");
    calls[0].arguments = cJSON_CreateObject();
    cJSON_AddStringToObject(calls[0].arguments, "path", "/tmp/test.txt");

    calls[1].id = sc_strdup("call-2");
    calls[1].name = sc_strdup("exec");
    calls[1].arguments = cJSON_CreateObject();
    cJSON_AddStringToObject(calls[1].arguments, "command", "ls");

    sc_llm_message_t msg = sc_msg_assistant_with_tools("Let me check.", calls, 2);

    ASSERT_STR_EQ(msg.role, "assistant");
    ASSERT_STR_EQ(msg.content, "Let me check.");
    ASSERT_INT_EQ(msg.tool_call_count, 2);
    ASSERT_NOT_NULL(msg.tool_calls);

    ASSERT_STR_EQ(msg.tool_calls[0].name, "read_file");
    ASSERT_STR_EQ(msg.tool_calls[1].name, "exec");

    /* Verify arguments are deep-copied */
    ASSERT_NOT_NULL(msg.tool_calls[0].arguments);
    cJSON *path = cJSON_GetObjectItem(msg.tool_calls[0].arguments, "path");
    ASSERT_NOT_NULL(path);
    ASSERT_STR_EQ(path->valuestring, "/tmp/test.txt");

    sc_llm_message_free_fields(&msg);

    /* Free originals */
    sc_tool_call_free_fields(&calls[0]);
    sc_tool_call_free_fields(&calls[1]);
}

static void test_message_array_free(void)
{
    /* Create an array of messages */
    int count = 3;
    sc_llm_message_t *msgs = calloc(count, sizeof(sc_llm_message_t));

    msgs[0] = sc_msg_system("system prompt");
    msgs[1] = sc_msg_user("user question");
    msgs[2] = sc_msg_assistant("assistant answer");

    /* Should not crash or leak */
    sc_llm_message_array_free(msgs, count);
}

static void test_response_free(void)
{
    /* Create a response */
    sc_llm_response_t *resp = calloc(1, sizeof(*resp));
    resp->content = sc_strdup("Response text");
    resp->finish_reason = sc_strdup("stop");
    resp->tool_call_count = 0;
    resp->tool_calls = NULL;
    resp->usage.prompt_tokens = 100;
    resp->usage.completion_tokens = 50;
    resp->usage.total_tokens = 150;

    /* Should not crash or leak */
    sc_llm_response_free(resp);
}

static void test_response_with_tool_calls(void)
{
    sc_llm_response_t *resp = calloc(1, sizeof(*resp));
    resp->content = sc_strdup("I'll read that file.");
    resp->finish_reason = sc_strdup("tool_calls");
    resp->tool_call_count = 1;
    resp->tool_calls = calloc(1, sizeof(sc_tool_call_t));
    resp->tool_calls[0].id = sc_strdup("tc_001");
    resp->tool_calls[0].name = sc_strdup("read_file");
    resp->tool_calls[0].arguments = cJSON_CreateObject();
    cJSON_AddStringToObject(resp->tool_calls[0].arguments, "path", "/test");

    ASSERT_STR_EQ(resp->content, "I'll read that file.");
    ASSERT_INT_EQ(resp->tool_call_count, 1);
    ASSERT_STR_EQ(resp->tool_calls[0].name, "read_file");

    sc_llm_response_free(resp);
}

static void test_tool_definition_free(void)
{
    sc_tool_definition_t def;
    def.name = sc_strdup("test_tool");
    def.description = sc_strdup("A test tool");
    def.parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(def.parameters, "type", "object");

    /* Should not crash or leak */
    sc_tool_definition_free(&def);
}

static void test_ollama_provider_create(void)
{
    sc_config_t *cfg = sc_config_default();
    ASSERT_NOT_NULL(cfg);

    /* Ollama should work without an API key */
    free(cfg->provider);
    cfg->provider = sc_strdup("ollama");
    free(cfg->model);
    cfg->model = sc_strdup("llama3.2");

    sc_provider_t *p = sc_provider_create(cfg);
    ASSERT_NOT_NULL(p);
    p->destroy(p);

    sc_config_free(cfg);
}

static void test_xai_provider_create(void)
{
    sc_config_t *cfg = sc_config_default();
    ASSERT_NOT_NULL(cfg);

    /* xAI should require an API key */
    free(cfg->provider);
    cfg->provider = sc_strdup("xai");
    free(cfg->model);
    cfg->model = sc_strdup("grok-3");
    free(cfg->xai.api_key);
    cfg->xai.api_key = sc_strdup("test-xai-key");

    sc_provider_t *p = sc_provider_create(cfg);
    ASSERT_NOT_NULL(p);
    p->destroy(p);

    /* Also works with "grok" as provider name */
    free(cfg->provider);
    cfg->provider = sc_strdup("grok");

    sc_provider_t *p2 = sc_provider_create(cfg);
    ASSERT_NOT_NULL(p2);
    p2->destroy(p2);

    sc_config_free(cfg);
}

static void test_provider_create_for_model(void)
{
    sc_config_t *cfg = sc_config_default();
    ASSERT_NOT_NULL(cfg);

    /* Set up API keys for testing */
    free(cfg->anthropic.api_key);
    cfg->anthropic.api_key = sc_strdup("test-anthropic-key");
    free(cfg->openai.api_key);
    cfg->openai.api_key = sc_strdup("test-openai-key");
    free(cfg->groq.api_key);
    cfg->groq.api_key = sc_strdup("test-groq-key");
    cfg->groq.api_base = sc_strdup("https://api.groq.com/openai/v1");

    /* Claude model → Anthropic provider */
    sc_provider_t *p1 = sc_provider_create_for_model(cfg, "claude-sonnet-4-5-20250929");
    ASSERT_NOT_NULL(p1);
    p1->destroy(p1);

    /* GPT model → OpenAI provider */
    sc_provider_t *p2 = sc_provider_create_for_model(cfg, "gpt-4o");
    ASSERT_NOT_NULL(p2);
    p2->destroy(p2);

    /* Provider prefix syntax: groq/model → Groq provider */
    sc_provider_t *p3 = sc_provider_create_for_model(cfg, "groq/llama-3.3-70b-versatile");
    ASSERT_NOT_NULL(p3);
    p3->destroy(p3);

    /* Ollama provider: explicit prefix → ollama base URL, no key required */
    sc_provider_t *p4 = sc_provider_create_for_model(cfg, "ollama/llama3.2");
    ASSERT_NOT_NULL(p4);
    p4->destroy(p4);

    /* Ollama: model name auto-detection (llama → ollama) */
    sc_provider_t *p5 = sc_provider_create_for_model(cfg, "llama3.2:latest");
    ASSERT_NOT_NULL(p5);
    p5->destroy(p5);

    /* xAI: model name auto-detection (grok → xai) */
    free(cfg->xai.api_key);
    cfg->xai.api_key = sc_strdup("test-xai-key");
    sc_provider_t *p6 = sc_provider_create_for_model(cfg, "grok-3");
    ASSERT_NOT_NULL(p6);
    p6->destroy(p6);

    /* xAI: provider prefix syntax */
    sc_provider_t *p7 = sc_provider_create_for_model(cfg, "xai/grok-3-mini");
    ASSERT_NOT_NULL(p7);
    p7->destroy(p7);

    /* NULL/empty should return NULL */
    ASSERT_NULL(sc_provider_create_for_model(cfg, NULL));
    ASSERT_NULL(sc_provider_create_for_model(cfg, ""));
    ASSERT_NULL(sc_provider_create_for_model(NULL, "gpt-4o"));

    sc_config_free(cfg);
}

/* ========================================================================
 * Integration tests — real HTTP round-trips via mock server
 * ======================================================================== */

/* Canned OpenAI text response */
static const char *OPENAI_TEXT_RESPONSE =
    "{\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\","
    "\"content\":\"Hello!\"},\"finish_reason\":\"stop\"}],"
    "\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}";

/* Canned OpenAI tool call response */
static const char *OPENAI_TOOL_RESPONSE =
    "{\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\","
    "\"content\":null,\"tool_calls\":[{\"id\":\"call_123\","
    "\"type\":\"function\",\"function\":{\"name\":\"read_file\","
    "\"arguments\":\"{\\\"path\\\":\\\"/test.txt\\\"}\"}}]},"
    "\"finish_reason\":\"tool_calls\"}],"
    "\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}";

/* Canned Anthropic text response */
static const char *ANTHROPIC_TEXT_RESPONSE =
    "{\"id\":\"msg_test\",\"type\":\"message\",\"role\":\"assistant\","
    "\"content\":[{\"type\":\"text\",\"text\":\"Hello!\"}],"
    "\"stop_reason\":\"end_turn\","
    "\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}";

/* Canned Anthropic tool use response */
static const char *ANTHROPIC_TOOL_RESPONSE =
    "{\"id\":\"msg_test\",\"type\":\"message\",\"role\":\"assistant\","
    "\"content\":[{\"type\":\"tool_use\",\"id\":\"toolu_123\","
    "\"name\":\"read_file\",\"input\":{\"path\":\"/test.txt\"}}],"
    "\"stop_reason\":\"tool_use\","
    "\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}";

static void test_http_provider_chat(void)
{
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = "/v1/chat/completions",
        .status = 200,
        .body = OPENAI_TEXT_RESPONSE,
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    /* Build base URL: mock_url + "/v1" */
    sc_strbuf_t base;
    sc_strbuf_init(&base);
    sc_strbuf_append(&base, sc_mock_http_url(mock));
    sc_strbuf_append(&base, "/v1");
    char *base_url = sc_strbuf_finish(&base);

    sc_provider_t *p = sc_provider_http_new("test-key", base_url, NULL);
    ASSERT_NOT_NULL(p);

    sc_llm_message_t msgs[1];
    msgs[0] = sc_msg_user("Hi");

    sc_llm_response_t *resp = p->chat(p, msgs, 1, NULL, 0, "test-model", NULL);
    ASSERT_NOT_NULL(resp);
    ASSERT_STR_EQ(resp->content, "Hello!");
    ASSERT_STR_EQ(resp->finish_reason, "stop");
    ASSERT_INT_EQ(resp->usage.prompt_tokens, 10);
    ASSERT_INT_EQ(resp->usage.completion_tokens, 5);
    ASSERT_INT_EQ(resp->tool_call_count, 0);

    /* Verify the mock received a POST */
    sc_mock_request_t req = sc_mock_http_last_request(mock);
    ASSERT_STR_EQ(req.method, "POST");
    ASSERT_STR_EQ(req.uri, "/v1/chat/completions");
    ASSERT_NOT_NULL(req.body);
    sc_mock_request_free(&req);

    sc_llm_response_free(resp);
    sc_llm_message_free_fields(&msgs[0]);
    p->destroy(p);
    free(base_url);
    sc_mock_http_stop(mock);
}

static void test_http_provider_tool_call(void)
{
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = "/v1/chat/completions",
        .status = 200,
        .body = OPENAI_TOOL_RESPONSE,
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_strbuf_t base;
    sc_strbuf_init(&base);
    sc_strbuf_append(&base, sc_mock_http_url(mock));
    sc_strbuf_append(&base, "/v1");
    char *base_url = sc_strbuf_finish(&base);

    sc_provider_t *p = sc_provider_http_new("test-key", base_url, NULL);
    sc_llm_message_t msgs[1];
    msgs[0] = sc_msg_user("Read a file");

    sc_llm_response_t *resp = p->chat(p, msgs, 1, NULL, 0, "test-model", NULL);
    ASSERT_NOT_NULL(resp);
    ASSERT_INT_EQ(resp->tool_call_count, 1);
    ASSERT_STR_EQ(resp->tool_calls[0].id, "call_123");
    ASSERT_STR_EQ(resp->tool_calls[0].name, "read_file");
    ASSERT_NOT_NULL(resp->tool_calls[0].arguments);

    cJSON *path = cJSON_GetObjectItem(resp->tool_calls[0].arguments, "path");
    ASSERT_NOT_NULL(path);
    ASSERT_STR_EQ(path->valuestring, "/test.txt");

    sc_llm_response_free(resp);
    sc_llm_message_free_fields(&msgs[0]);
    p->destroy(p);
    free(base_url);
    sc_mock_http_stop(mock);
}

static void test_http_provider_error(void)
{
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = "/v1/chat/completions",
        .status = 500,
        .body = "{\"error\":\"internal server error\"}",
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_strbuf_t base;
    sc_strbuf_init(&base);
    sc_strbuf_append(&base, sc_mock_http_url(mock));
    sc_strbuf_append(&base, "/v1");
    char *base_url = sc_strbuf_finish(&base);

    sc_provider_t *p = sc_provider_http_new("test-key", base_url, NULL);
    sc_llm_message_t msgs[1];
    msgs[0] = sc_msg_user("Hi");

    sc_llm_response_t *resp = p->chat(p, msgs, 1, NULL, 0, "test-model", NULL);
    ASSERT_NOT_NULL(resp);
    ASSERT(resp->http_status == 500, "Expected HTTP 500 error response");
    ASSERT_NULL(resp->content);
    sc_llm_response_free(resp);

    sc_llm_message_free_fields(&msgs[0]);
    p->destroy(p);
    free(base_url);
    sc_mock_http_stop(mock);
}

static void test_claude_provider_chat(void)
{
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = "/v1/messages",
        .status = 200,
        .body = ANTHROPIC_TEXT_RESPONSE,
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_strbuf_t base;
    sc_strbuf_init(&base);
    sc_strbuf_append(&base, sc_mock_http_url(mock));
    sc_strbuf_append(&base, "/v1");
    char *base_url = sc_strbuf_finish(&base);

    sc_provider_t *p = sc_provider_claude_new("test-key", base_url);
    ASSERT_NOT_NULL(p);

    sc_llm_message_t msgs[1];
    msgs[0] = sc_msg_user("Hi");

    sc_llm_response_t *resp = p->chat(p, msgs, 1, NULL, 0, "claude-test", NULL);
    ASSERT_NOT_NULL(resp);
    ASSERT_STR_EQ(resp->content, "Hello!");
    ASSERT_STR_EQ(resp->finish_reason, "stop");
    ASSERT_INT_EQ(resp->usage.prompt_tokens, 10);
    ASSERT_INT_EQ(resp->usage.completion_tokens, 5);
    ASSERT_INT_EQ(resp->tool_call_count, 0);

    sc_mock_request_t req = sc_mock_http_last_request(mock);
    ASSERT_STR_EQ(req.method, "POST");
    ASSERT_STR_EQ(req.uri, "/v1/messages");
    sc_mock_request_free(&req);

    sc_llm_response_free(resp);
    sc_llm_message_free_fields(&msgs[0]);
    p->destroy(p);
    free(base_url);
    sc_mock_http_stop(mock);
}

static void test_claude_provider_tool_use(void)
{
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = "/v1/messages",
        .status = 200,
        .body = ANTHROPIC_TOOL_RESPONSE,
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_strbuf_t base;
    sc_strbuf_init(&base);
    sc_strbuf_append(&base, sc_mock_http_url(mock));
    sc_strbuf_append(&base, "/v1");
    char *base_url = sc_strbuf_finish(&base);

    sc_provider_t *p = sc_provider_claude_new("test-key", base_url);

    sc_llm_message_t msgs[1];
    msgs[0] = sc_msg_user("Read a file");

    sc_llm_response_t *resp = p->chat(p, msgs, 1, NULL, 0, "claude-test", NULL);
    ASSERT_NOT_NULL(resp);
    ASSERT_STR_EQ(resp->finish_reason, "tool_calls");
    ASSERT_INT_EQ(resp->tool_call_count, 1);
    ASSERT_STR_EQ(resp->tool_calls[0].id, "toolu_123");
    ASSERT_STR_EQ(resp->tool_calls[0].name, "read_file");
    ASSERT_NOT_NULL(resp->tool_calls[0].arguments);

    cJSON *path = cJSON_GetObjectItem(resp->tool_calls[0].arguments, "path");
    ASSERT_NOT_NULL(path);
    ASSERT_STR_EQ(path->valuestring, "/test.txt");

    sc_llm_response_free(resp);
    sc_llm_message_free_fields(&msgs[0]);
    p->destroy(p);
    free(base_url);
    sc_mock_http_stop(mock);
}

static void test_claude_provider_error(void)
{
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = "/v1/messages",
        .status = 401,
        .body = "{\"type\":\"error\",\"error\":{\"type\":\"authentication_error\"}}",
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_strbuf_t base;
    sc_strbuf_init(&base);
    sc_strbuf_append(&base, sc_mock_http_url(mock));
    sc_strbuf_append(&base, "/v1");
    char *base_url = sc_strbuf_finish(&base);

    sc_provider_t *p = sc_provider_claude_new("bad-key", base_url);

    sc_llm_message_t msgs[1];
    msgs[0] = sc_msg_user("Hi");

    sc_llm_response_t *resp = p->chat(p, msgs, 1, NULL, 0, "claude-test", NULL);
    ASSERT_NOT_NULL(resp);
    ASSERT(resp->http_status == 401, "Expected HTTP 401 error response");
    ASSERT_NULL(resp->content);
    sc_llm_response_free(resp);

    sc_llm_message_free_fields(&msgs[0]);
    p->destroy(p);
    free(base_url);
    sc_mock_http_stop(mock);
}

static void test_fallback_chain(void)
{
    /* Primary provider returns 500, fallback returns success.
     * We simulate this by creating two HTTP providers with different mock servers. */

    /* Primary: always returns 500 */
    sc_mock_route_t primary_routes[] = {{
        .method = "POST",
        .path = "/v1/chat/completions",
        .status = 500,
        .body = "{\"error\":\"internal server error\"}",
    }};
    sc_mock_http_t *primary_mock = sc_mock_http_start(primary_routes, 1);
    ASSERT_NOT_NULL(primary_mock);

    /* Fallback: returns success */
    sc_mock_route_t fallback_routes[] = {{
        .method = "POST",
        .path = "/v1/chat/completions",
        .status = 200,
        .body = OPENAI_TEXT_RESPONSE,
    }};
    sc_mock_http_t *fallback_mock = sc_mock_http_start(fallback_routes, 1);
    ASSERT_NOT_NULL(fallback_mock);

    /* Create primary provider */
    sc_strbuf_t base1;
    sc_strbuf_init(&base1);
    sc_strbuf_append(&base1, sc_mock_http_url(primary_mock));
    sc_strbuf_append(&base1, "/v1");
    char *primary_url = sc_strbuf_finish(&base1);

    sc_provider_t *primary = sc_provider_http_new("primary-key", primary_url, NULL);
    ASSERT_NOT_NULL(primary);

    /* Create fallback provider */
    sc_strbuf_t base2;
    sc_strbuf_init(&base2);
    sc_strbuf_append(&base2, sc_mock_http_url(fallback_mock));
    sc_strbuf_append(&base2, "/v1");
    char *fallback_url = sc_strbuf_finish(&base2);

    sc_provider_t *fallback = sc_provider_http_new("fallback-key", fallback_url, NULL);
    ASSERT_NOT_NULL(fallback);

    sc_llm_message_t msgs[1];
    msgs[0] = sc_msg_user("Hello");

    /* Primary should fail */
    sc_llm_response_t *resp = primary->chat(primary, msgs, 1, NULL, 0, "primary-model", NULL);
    ASSERT_NOT_NULL(resp);
    ASSERT(resp->http_status == 500, "Expected HTTP 500 error response");
    ASSERT_NULL(resp->content);
    sc_llm_response_free(resp);

    /* Fallback should succeed (simulating what agent.c does) */
    resp = fallback->chat(fallback, msgs, 1, NULL, 0, "fallback-model", NULL);
    ASSERT_NOT_NULL(resp);
    ASSERT_STR_EQ(resp->content, "Hello!");
    ASSERT_STR_EQ(resp->finish_reason, "stop");

    /* Verify both mocks received requests */
    sc_mock_request_t req1 = sc_mock_http_last_request(primary_mock);
    ASSERT_STR_EQ(req1.method, "POST");
    sc_mock_request_free(&req1);

    sc_mock_request_t req2 = sc_mock_http_last_request(fallback_mock);
    ASSERT_STR_EQ(req2.method, "POST");
    sc_mock_request_free(&req2);

    sc_llm_response_free(resp);
    sc_llm_message_free_fields(&msgs[0]);
    primary->destroy(primary);
    fallback->destroy(fallback);
    free(primary_url);
    free(fallback_url);
    sc_mock_http_stop(primary_mock);
    sc_mock_http_stop(fallback_mock);
}

static void test_fallback_all_fail(void)
{
    /* Both primary and fallback return errors */
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = "/v1/chat/completions",
        .status = 500,
        .body = "{\"error\":\"server error\"}",
    }};
    sc_mock_http_t *mock1 = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock1);
    sc_mock_http_t *mock2 = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock2);

    sc_strbuf_t b1;
    sc_strbuf_init(&b1);
    sc_strbuf_append(&b1, sc_mock_http_url(mock1));
    sc_strbuf_append(&b1, "/v1");
    char *url1 = sc_strbuf_finish(&b1);

    sc_strbuf_t b2;
    sc_strbuf_init(&b2);
    sc_strbuf_append(&b2, sc_mock_http_url(mock2));
    sc_strbuf_append(&b2, "/v1");
    char *url2 = sc_strbuf_finish(&b2);

    sc_provider_t *p1 = sc_provider_http_new("key1", url1, NULL);
    sc_provider_t *p2 = sc_provider_http_new("key2", url2, NULL);
    ASSERT_NOT_NULL(p1);
    ASSERT_NOT_NULL(p2);

    sc_llm_message_t msgs[1];
    msgs[0] = sc_msg_user("Hello");

    /* Both should fail */
    sc_llm_response_t *r1 = p1->chat(p1, msgs, 1, NULL, 0, "model1", NULL);
    ASSERT_NOT_NULL(r1);
    ASSERT(r1->http_status == 500, "Expected HTTP 500 error response");
    ASSERT_NULL(r1->content);
    sc_llm_response_free(r1);
    sc_llm_response_t *r2 = p2->chat(p2, msgs, 1, NULL, 0, "model2", NULL);
    ASSERT_NOT_NULL(r2);
    ASSERT(r2->http_status == 500, "Expected HTTP 500 error response");
    ASSERT_NULL(r2->content);
    sc_llm_response_free(r2);

    sc_llm_message_free_fields(&msgs[0]);
    p1->destroy(p1);
    p2->destroy(p2);
    free(url1);
    free(url2);
    sc_mock_http_stop(mock1);
    sc_mock_http_stop(mock2);
}

int main(void)
{
    printf("test_providers\n");

    RUN_TEST(test_message_constructors);
    RUN_TEST(test_message_clone);
    RUN_TEST(test_message_with_tool_calls);
    RUN_TEST(test_message_array_free);
    RUN_TEST(test_response_free);
    RUN_TEST(test_response_with_tool_calls);
    RUN_TEST(test_tool_definition_free);
    RUN_TEST(test_ollama_provider_create);
    RUN_TEST(test_xai_provider_create);
    RUN_TEST(test_provider_create_for_model);

    /* Integration tests (mock HTTP server) */
    RUN_TEST(test_http_provider_chat);
    RUN_TEST(test_http_provider_tool_call);
    RUN_TEST(test_http_provider_error);
    RUN_TEST(test_claude_provider_chat);
    RUN_TEST(test_claude_provider_tool_use);
    RUN_TEST(test_claude_provider_error);
    RUN_TEST(test_fallback_chain);
    RUN_TEST(test_fallback_all_fail);

    TEST_REPORT();
}
