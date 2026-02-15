/*
 * smolclaw - web tool tests
 * Tests web_search (Brave, SearXNG) and web_fetch against mock HTTP server.
 */

#include "test_main.h"
#include "mock_http.h"
#include "tools/web.h"
#include "tools/types.h"
#include "util/str.h"
#include "cJSON.h"

/* --- Canned search responses --- */

static const char *BRAVE_RESPONSE =
    "{\"web\":{\"results\":["
    "{\"title\":\"Example Page\",\"url\":\"https://example.com\","
    "\"description\":\"An example page for testing.\"},"
    "{\"title\":\"Test Page\",\"url\":\"https://test.com\","
    "\"description\":\"A test page.\"}"
    "]}}";

static const char *SEARXNG_RESPONSE =
    "{\"results\":["
    "{\"title\":\"SearX Result\",\"url\":\"https://searx.example.com\","
    "\"content\":\"Found via SearXNG.\"},"
    "{\"title\":\"Another Result\",\"url\":\"https://another.example.com\","
    "\"content\":\"More content here.\"}"
    "]}";

static const char *EMPTY_BRAVE_RESPONSE =
    "{\"web\":{\"results\":[]}}";

/* --- web_search tests --- */

static void test_web_search_brave(void)
{
    /* Brave search with configurable brave_base_url pointing at mock */
    sc_mock_route_t routes[] = {{
        .method = "GET",
        .path = NULL, /* catch-all: Brave URL has query params */
        .status = 200,
        .body = BRAVE_RESPONSE,
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_web_search_opts_t opts = {0};
    opts.brave_enabled = 1;
    opts.brave_api_key = "test-brave-key";
    opts.brave_base_url = sc_mock_http_url(mock);
    opts.brave_max_results = 5;

    sc_tool_t *tool = sc_tool_web_search_new(opts);
    ASSERT_NOT_NULL(tool);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "query", "test query");

    sc_tool_result_t *result = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_NOT_NULL(result->for_llm);
    ASSERT_INT_EQ(result->is_error, 0);

    /* Verify result contains parsed Brave data */
    ASSERT(strstr(result->for_llm, "Example Page") != NULL,
           "Should contain first result title");
    ASSERT(strstr(result->for_llm, "https://example.com") != NULL,
           "Should contain first result URL");
    ASSERT(strstr(result->for_llm, "An example page") != NULL,
           "Should contain first result description");
    ASSERT(strstr(result->for_llm, "Test Page") != NULL,
           "Should contain second result title");

    /* Verify the mock received a GET with correct path prefix */
    sc_mock_request_t req = sc_mock_http_last_request(mock);
    ASSERT_STR_EQ(req.method, "GET");
    ASSERT(strstr(req.uri, "/res/v1/web/search") != NULL,
           "Should hit Brave search endpoint");
    ASSERT(strstr(req.uri, "q=test") != NULL,
           "URL should contain query parameter");
    sc_mock_request_free(&req);

    sc_tool_result_free(result);
    cJSON_Delete(args);
    tool->destroy(tool);
    sc_mock_http_stop(mock);
}

static void test_web_search_brave_empty(void)
{
    sc_mock_route_t routes[] = {{
        .method = "GET",
        .path = NULL,
        .status = 200,
        .body = EMPTY_BRAVE_RESPONSE,
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_web_search_opts_t opts = {0};
    opts.brave_enabled = 1;
    opts.brave_api_key = "test-key";
    opts.brave_base_url = sc_mock_http_url(mock);

    sc_tool_t *tool = sc_tool_web_search_new(opts);
    ASSERT_NOT_NULL(tool);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "query", "nothing here");

    sc_tool_result_t *result = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT(strstr(result->for_llm, "No results") != NULL,
           "Should indicate no results for empty Brave response");

    sc_tool_result_free(result);
    cJSON_Delete(args);
    tool->destroy(tool);
    sc_mock_http_stop(mock);
}

static void test_web_search_brave_error(void)
{
    sc_mock_route_t routes[] = {{
        .method = "GET",
        .path = NULL,
        .status = 401,
        .body = "{\"error\":\"unauthorized\"}",
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_web_search_opts_t opts = {0};
    opts.brave_enabled = 1;
    opts.brave_api_key = "bad-key";
    opts.brave_base_url = sc_mock_http_url(mock);

    sc_tool_t *tool = sc_tool_web_search_new(opts);
    ASSERT_NOT_NULL(tool);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "query", "test");

    sc_tool_result_t *result = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(result);
    /* The tool should still return something (error or no results) */
    ASSERT_NOT_NULL(result->for_llm);

    sc_tool_result_free(result);
    cJSON_Delete(args);
    tool->destroy(tool);
    sc_mock_http_stop(mock);
}

static void test_web_search_searxng(void)
{
    sc_mock_route_t routes[] = {{
        .method = "GET",
        .path = NULL, /* catch-all for /search?q=... */
        .status = 200,
        .body = SEARXNG_RESPONSE,
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_web_search_opts_t opts = {0};
    opts.searxng_enabled = 1;
    opts.searxng_base_url = sc_mock_http_url(mock);
    opts.searxng_max_results = 5;

    sc_tool_t *tool = sc_tool_web_search_new(opts);
    ASSERT_NOT_NULL(tool);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "query", "test query");

    sc_tool_result_t *result = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_NOT_NULL(result->for_llm);
    ASSERT_INT_EQ(result->is_error, 0);

    /* Verify result contains parsed SearXNG data */
    ASSERT(strstr(result->for_llm, "SearX Result") != NULL,
           "Should contain first result title");
    ASSERT(strstr(result->for_llm, "https://searx.example.com") != NULL,
           "Should contain first result URL");
    ASSERT(strstr(result->for_llm, "Found via SearXNG") != NULL,
           "Should contain first result content");
    ASSERT(strstr(result->for_llm, "Another Result") != NULL,
           "Should contain second result title");

    sc_tool_result_free(result);
    cJSON_Delete(args);
    tool->destroy(tool);
    sc_mock_http_stop(mock);
}

static void test_web_search_no_results(void)
{
    sc_mock_route_t routes[] = {{
        .method = "GET",
        .path = NULL,
        .status = 200,
        .body = EMPTY_BRAVE_RESPONSE,
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    /* Use SearXNG with empty results format */
    sc_mock_http_stop(mock);

    sc_mock_route_t routes2[] = {{
        .method = "GET",
        .path = NULL,
        .status = 200,
        .body = "{\"results\":[]}",
    }};
    mock = sc_mock_http_start(routes2, 1);
    ASSERT_NOT_NULL(mock);

    sc_web_search_opts_t opts = {0};
    opts.searxng_enabled = 1;
    opts.searxng_base_url = sc_mock_http_url(mock);
    opts.searxng_max_results = 5;

    sc_tool_t *tool = sc_tool_web_search_new(opts);
    ASSERT_NOT_NULL(tool);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "query", "nonexistent");

    sc_tool_result_t *result = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT(strstr(result->for_llm, "No results") != NULL,
           "Should indicate no results");

    sc_tool_result_free(result);
    cJSON_Delete(args);
    tool->destroy(tool);
    sc_mock_http_stop(mock);
}

/* --- web_fetch tests --- */

static void test_web_fetch_html(void)
{
    const char *html_body =
        "<!DOCTYPE html><html><head><title>Test</title>"
        "<script>var x = 1;</script></head>"
        "<body><h1>Hello World</h1><p>This is a test.</p></body></html>";

    sc_mock_route_t routes[] = {{
        .method = "GET",
        .path = "/page",
        .status = 200,
        .content_type = "text/html",
        .body = html_body,
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_tool_t *tool = sc_tool_web_fetch_new(50000);
    ASSERT_NOT_NULL(tool);

    /* Build URL */
    sc_strbuf_t url;
    sc_strbuf_init(&url);
    sc_strbuf_append(&url, sc_mock_http_url(mock));
    sc_strbuf_append(&url, "/page");
    char *url_str = sc_strbuf_finish(&url);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "url", url_str);

    sc_tool_result_t *result = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_INT_EQ(result->is_error, 0);
    ASSERT_NOT_NULL(result->for_llm);

    /* HTML tags should be stripped, script content removed */
    ASSERT(strstr(result->for_llm, "Hello World") != NULL,
           "Should contain visible text");
    ASSERT(strstr(result->for_llm, "This is a test") != NULL,
           "Should contain paragraph text");
    ASSERT(strstr(result->for_llm, "<h1>") == NULL,
           "Should not contain HTML tags");
    ASSERT(strstr(result->for_llm, "var x") == NULL,
           "Should not contain script content");
    ASSERT(strstr(result->for_llm, "extractor: text") != NULL,
           "Should use text extractor for HTML");

    sc_tool_result_free(result);
    cJSON_Delete(args);
    free(url_str);
    tool->destroy(tool);
    sc_mock_http_stop(mock);
}

static void test_web_fetch_json(void)
{
    const char *json_body = "{\"key\":\"value\",\"num\":42}";

    sc_mock_route_t routes[] = {{
        .method = "GET",
        .path = "/api/data",
        .status = 200,
        .content_type = "application/json",
        .body = json_body,
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_tool_t *tool = sc_tool_web_fetch_new(50000);
    ASSERT_NOT_NULL(tool);

    sc_strbuf_t url;
    sc_strbuf_init(&url);
    sc_strbuf_append(&url, sc_mock_http_url(mock));
    sc_strbuf_append(&url, "/api/data");
    char *url_str = sc_strbuf_finish(&url);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "url", url_str);

    sc_tool_result_t *result = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_INT_EQ(result->is_error, 0);
    ASSERT_NOT_NULL(result->for_llm);

    /* JSON should be pretty-printed */
    ASSERT(strstr(result->for_llm, "\"key\"") != NULL,
           "Should contain JSON key");
    ASSERT(strstr(result->for_llm, "\"value\"") != NULL,
           "Should contain JSON value");
    ASSERT(strstr(result->for_llm, "extractor: json") != NULL,
           "Should use json extractor");

    sc_tool_result_free(result);
    cJSON_Delete(args);
    free(url_str);
    tool->destroy(tool);
    sc_mock_http_stop(mock);
}

static void test_web_fetch_truncation(void)
{
    /* Build a body larger than our max_chars limit */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    for (int i = 0; i < 200; i++)
        sc_strbuf_append(&sb, "ABCDEFGHIJ"); /* 2000 chars */
    char *big_body = sc_strbuf_finish(&sb);

    sc_mock_route_t routes[] = {{
        .method = "GET",
        .path = "/big",
        .status = 200,
        .content_type = "text/plain",
        .body = big_body,
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    int max_chars = 500;
    sc_tool_t *tool = sc_tool_web_fetch_new(max_chars);
    ASSERT_NOT_NULL(tool);

    sc_strbuf_t url;
    sc_strbuf_init(&url);
    sc_strbuf_append(&url, sc_mock_http_url(mock));
    sc_strbuf_append(&url, "/big");
    char *url_str = sc_strbuf_finish(&url);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "url", url_str);

    sc_tool_result_t *result = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_INT_EQ(result->is_error, 0);
    ASSERT(strstr(result->for_llm, "truncated: true") != NULL,
           "Should indicate truncation");

    sc_tool_result_free(result);
    cJSON_Delete(args);
    free(url_str);
    free(big_body);
    tool->destroy(tool);
    sc_mock_http_stop(mock);
}

int main(void)
{
    printf("test_web\n");

    /* Disable SSRF protection for tests (mock server is on localhost) */
    setenv("SC_TEST_DISABLE_SSRF", "1", 1);

    RUN_TEST(test_web_search_brave);
    RUN_TEST(test_web_search_brave_empty);
    RUN_TEST(test_web_search_brave_error);
    RUN_TEST(test_web_search_searxng);
    RUN_TEST(test_web_search_no_results);
    RUN_TEST(test_web_fetch_html);
    RUN_TEST(test_web_fetch_json);
    RUN_TEST(test_web_fetch_truncation);

    TEST_REPORT();
}
