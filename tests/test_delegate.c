/*
 * smolclaw — delegate tool tests
 *
 * Tests parameter validation, target lookup, and HTTP delegation
 * via the mock HTTP server.
 */

#include "test_main.h"
#include "sc_features.h"

#if SC_ENABLE_DELEGATE

#include "tools/delegate.h"
#include "tools/types.h"
#include "config.h"
#include "cJSON.h"
#include "mock_http.h"

#include <string.h>

/* ========== Helpers ========== */

static sc_delegate_target_t make_target(const char *name, const char *url,
                                         const char *token, int timeout)
{
    sc_delegate_target_t t = {0};
    t.name = (char *)name;
    t.url = (char *)url;
    t.bearer_token = (char *)token;
    t.timeout_secs = timeout;
    return t;
}

static cJSON *make_args(const char *target, const char *task, const char *session)
{
    cJSON *args = cJSON_CreateObject();
    if (target) cJSON_AddStringToObject(args, "target", target);
    if (task) cJSON_AddStringToObject(args, "task", task);
    if (session) cJSON_AddStringToObject(args, "session", session);
    return args;
}

/* ========== Constructor & schema tests ========== */

static void test_delegate_new(void)
{
    sc_delegate_target_t targets[] = {
        make_target("agent-a", "http://localhost:8080/api/message", NULL, 30),
    };
    sc_delegation_config_t cfg = { .targets = targets, .target_count = 1 };

    sc_tool_t *tool = sc_tool_delegate_new(&cfg, NULL);
    ASSERT_NOT_NULL(tool);
    ASSERT_STR_EQ(tool->name, "delegate");
    ASSERT_NOT_NULL(tool->description);
    ASSERT_NOT_NULL(tool->parameters);
    ASSERT_NOT_NULL(tool->execute);
    ASSERT_NOT_NULL(tool->destroy);

    tool->destroy(tool);
}

static void test_delegate_parameters_schema(void)
{
    sc_delegate_target_t targets[] = {
        make_target("a", "http://x", NULL, 10),
    };
    sc_delegation_config_t cfg = { .targets = targets, .target_count = 1 };
    sc_tool_t *tool = sc_tool_delegate_new(&cfg, NULL);

    cJSON *schema = tool->parameters(tool);
    ASSERT_NOT_NULL(schema);

    /* Must have target and task as required */
    cJSON *req = cJSON_GetObjectItem(schema, "required");
    ASSERT_NOT_NULL(req);
    ASSERT_INT_EQ(cJSON_GetArraySize(req), 2);
    ASSERT_STR_EQ(cJSON_GetArrayItem(req, 0)->valuestring, "target");
    ASSERT_STR_EQ(cJSON_GetArrayItem(req, 1)->valuestring, "task");

    /* Must have target, task, session properties */
    cJSON *props = cJSON_GetObjectItem(schema, "properties");
    ASSERT_NOT_NULL(props);
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "target"));
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "task"));
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "session"));

    cJSON_Delete(schema);
    tool->destroy(tool);
}

/* ========== Parameter validation tests ========== */

static void test_delegate_missing_target(void)
{
    sc_delegate_target_t targets[] = {
        make_target("a", "http://x", NULL, 10),
    };
    sc_delegation_config_t cfg = { .targets = targets, .target_count = 1 };
    sc_tool_t *tool = sc_tool_delegate_new(&cfg, NULL);

    cJSON *args = make_args(NULL, "do something", NULL);
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT(r->is_error, "should be error when target missing");
    ASSERT(strstr(r->for_llm, "target") != NULL, "error should mention target");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);
}

static void test_delegate_missing_task(void)
{
    sc_delegate_target_t targets[] = {
        make_target("a", "http://x", NULL, 10),
    };
    sc_delegation_config_t cfg = { .targets = targets, .target_count = 1 };
    sc_tool_t *tool = sc_tool_delegate_new(&cfg, NULL);

    cJSON *args = make_args("a", NULL, NULL);
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT(r->is_error, "should be error when task missing");
    ASSERT(strstr(r->for_llm, "task") != NULL, "error should mention task");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);
}

/* ========== Target lookup tests ========== */

static void test_delegate_unknown_target(void)
{
    sc_delegate_target_t targets[] = {
        make_target("agent-a", "http://x", NULL, 10),
        make_target("agent-b", "http://y", NULL, 10),
    };
    sc_delegation_config_t cfg = { .targets = targets, .target_count = 2 };
    sc_tool_t *tool = sc_tool_delegate_new(&cfg, NULL);

    cJSON *args = make_args("nonexistent", "hello", NULL);
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT(r->is_error, "should be error for unknown target");
    ASSERT(strstr(r->for_llm, "nonexistent") != NULL, "error should mention bad target name");
    ASSERT(strstr(r->for_llm, "agent-a") != NULL, "error should list available target a");
    ASSERT(strstr(r->for_llm, "agent-b") != NULL, "error should list available target b");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);
}

static void test_delegate_empty_url(void)
{
    sc_delegate_target_t targets[] = {
        make_target("agent-a", "", NULL, 10),
    };
    sc_delegation_config_t cfg = { .targets = targets, .target_count = 1 };
    sc_tool_t *tool = sc_tool_delegate_new(&cfg, NULL);

    cJSON *args = make_args("agent-a", "hello", NULL);
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT(r->is_error, "should be error for empty URL");
    ASSERT(strstr(r->for_llm, "URL") != NULL, "error should mention URL");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);
}

static void test_delegate_null_url(void)
{
    sc_delegate_target_t targets[] = {
        make_target("agent-a", NULL, NULL, 10),
    };
    sc_delegation_config_t cfg = { .targets = targets, .target_count = 1 };
    sc_tool_t *tool = sc_tool_delegate_new(&cfg, NULL);

    cJSON *args = make_args("agent-a", "hello", NULL);
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT(r->is_error, "should be error for NULL URL");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);
}

/* ========== HTTP tests (mock server) ========== */

static void test_delegate_success(void)
{
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = "/api/message",
        .status = 200,
        .body = "{\"response\":\"I completed the task\"}"
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    char url[128];
    snprintf(url, sizeof(url), "%s/api/message", mock->url);

    sc_delegate_target_t targets[] = {
        make_target("helper", url, NULL, 10),
    };
    sc_delegation_config_t cfg = { .targets = targets, .target_count = 1 };
    sc_tool_t *tool = sc_tool_delegate_new(&cfg, NULL);

    cJSON *args = make_args("helper", "summarize this", "sess-123");
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT(!r->is_error, "should succeed");
    ASSERT_STR_EQ(r->for_llm, "I completed the task");

    /* Verify request was POST with correct body */
    sc_mock_request_t req = sc_mock_http_last_request(mock);
    ASSERT_STR_EQ(req.method, "POST");
    ASSERT_STR_EQ(req.uri, "/api/message");
    ASSERT_NOT_NULL(req.body);

    /* Verify body contains the task and session */
    cJSON *body = cJSON_Parse(req.body);
    ASSERT_NOT_NULL(body);
    ASSERT_STR_EQ(cJSON_GetObjectItem(body, "message")->valuestring, "summarize this");
    ASSERT_STR_EQ(cJSON_GetObjectItem(body, "session")->valuestring, "sess-123");
    cJSON_Delete(body);

    sc_mock_request_free(&req);
    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);
    sc_mock_http_stop(mock);
}

static void test_delegate_auto_session(void)
{
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = "/api/message",
        .status = 200,
        .body = "{\"response\":\"ok\"}"
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    char url[128];
    snprintf(url, sizeof(url), "%s/api/message", mock->url);

    sc_delegate_target_t targets[] = {
        make_target("helper", url, NULL, 10),
    };
    sc_delegation_config_t cfg = { .targets = targets, .target_count = 1 };
    sc_tool_t *tool = sc_tool_delegate_new(&cfg, NULL);

    /* No session provided — should auto-generate one */
    cJSON *args = make_args("helper", "do it", NULL);
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT(!r->is_error, "should succeed");

    /* Verify a session was generated */
    sc_mock_request_t req = sc_mock_http_last_request(mock);
    cJSON *body = cJSON_Parse(req.body);
    ASSERT_NOT_NULL(body);
    cJSON *sess = cJSON_GetObjectItem(body, "session");
    ASSERT_NOT_NULL(sess);
    ASSERT(cJSON_IsString(sess), "session should be a string");
    ASSERT(strlen(sess->valuestring) > 0, "auto-generated session should not be empty");
    cJSON_Delete(body);

    sc_mock_request_free(&req);
    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);
    sc_mock_http_stop(mock);
}

static void test_delegate_http_error(void)
{
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = "/api/message",
        .status = 500,
        .body = "{\"error\":\"internal\"}"
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    char url[128];
    snprintf(url, sizeof(url), "%s/api/message", mock->url);

    sc_delegate_target_t targets[] = {
        make_target("helper", url, NULL, 10),
    };
    sc_delegation_config_t cfg = { .targets = targets, .target_count = 1 };
    sc_tool_t *tool = sc_tool_delegate_new(&cfg, NULL);

    cJSON *args = make_args("helper", "fail please", NULL);
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT(r->is_error, "should be error on HTTP 500");
    ASSERT(strstr(r->for_llm, "500") != NULL, "error should contain HTTP status");
    ASSERT(strstr(r->for_llm, "helper") != NULL, "error should mention target name");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);
    sc_mock_http_stop(mock);
}

static void test_delegate_json_no_response_field(void)
{
    /* Server returns JSON but without the "response" key */
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = "/api/message",
        .status = 200,
        .body = "{\"result\":\"something else\"}"
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    char url[128];
    snprintf(url, sizeof(url), "%s/api/message", mock->url);

    sc_delegate_target_t targets[] = {
        make_target("helper", url, NULL, 10),
    };
    sc_delegation_config_t cfg = { .targets = targets, .target_count = 1 };
    sc_tool_t *tool = sc_tool_delegate_new(&cfg, NULL);

    cJSON *args = make_args("helper", "hello", NULL);
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT(!r->is_error, "should succeed even without response field");
    /* Should return the raw JSON */
    ASSERT(strstr(r->for_llm, "something else") != NULL,
           "should contain the raw response");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);
    sc_mock_http_stop(mock);
}

static void test_delegate_plain_text_response(void)
{
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = "/api/message",
        .status = 200,
        .content_type = "text/plain",
        .body = "just plain text"
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    char url[128];
    snprintf(url, sizeof(url), "%s/api/message", mock->url);

    sc_delegate_target_t targets[] = {
        make_target("helper", url, NULL, 10),
    };
    sc_delegation_config_t cfg = { .targets = targets, .target_count = 1 };
    sc_tool_t *tool = sc_tool_delegate_new(&cfg, NULL);

    cJSON *args = make_args("helper", "hello", NULL);
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT(!r->is_error, "should succeed with plain text");
    ASSERT_STR_EQ(r->for_llm, "just plain text");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);
    sc_mock_http_stop(mock);
}

static void test_delegate_bearer_token(void)
{
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = "/api/message",
        .status = 200,
        .body = "{\"response\":\"authed\"}"
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    char url[128];
    snprintf(url, sizeof(url), "%s/api/message", mock->url);

    sc_delegate_target_t targets[] = {
        make_target("helper", url, "secret-token-12345", 10),
    };
    sc_delegation_config_t cfg = { .targets = targets, .target_count = 1 };
    sc_tool_t *tool = sc_tool_delegate_new(&cfg, NULL);

    cJSON *args = make_args("helper", "hello", NULL);
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT(!r->is_error, "should succeed with auth");
    ASSERT_STR_EQ(r->for_llm, "authed");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);
    sc_mock_http_stop(mock);
}

static void test_delegate_connection_refused(void)
{
    /* Point at a port nothing is listening on */
    sc_delegate_target_t targets[] = {
        make_target("dead", "http://127.0.0.1:1/api/message", NULL, 2),
    };
    sc_delegation_config_t cfg = { .targets = targets, .target_count = 1 };
    sc_tool_t *tool = sc_tool_delegate_new(&cfg, NULL);

    cJSON *args = make_args("dead", "hello", NULL);
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT(r->is_error, "should be error when connection refused");
    ASSERT(strstr(r->for_llm, "dead") != NULL, "error should mention target");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);
}

#endif /* SC_ENABLE_DELEGATE */

int main(void)
{
#if SC_ENABLE_DELEGATE
    RUN_TEST(test_delegate_new);
    RUN_TEST(test_delegate_parameters_schema);
    RUN_TEST(test_delegate_missing_target);
    RUN_TEST(test_delegate_missing_task);
    RUN_TEST(test_delegate_unknown_target);
    RUN_TEST(test_delegate_empty_url);
    RUN_TEST(test_delegate_null_url);
    RUN_TEST(test_delegate_success);
    RUN_TEST(test_delegate_auto_session);
    RUN_TEST(test_delegate_http_error);
    RUN_TEST(test_delegate_json_no_response_field);
    RUN_TEST(test_delegate_plain_text_response);
    RUN_TEST(test_delegate_bearer_token);
    RUN_TEST(test_delegate_connection_refused);
#else
    printf("  Delegate disabled, skipping tests\n");
    _test_pass++;
#endif
    TEST_REPORT();
}
