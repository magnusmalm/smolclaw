/*
 * smolclaw — MCP server tests
 *
 * Fork-based: parent writes JSON-RPC to child's stdin,
 * reads responses from child's stdout.
 */

#include "test_main.h"
#include "sc_features.h"

#if SC_ENABLE_MCP_SERVER

#include "mcp/server.h"
#include "tools/registry.h"
#include "tools/types.h"
#include "util/str.h"
#include "cJSON.h"

#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>

/* ========== Minimal test tool ========== */

static cJSON *echo_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");
    cJSON *props = cJSON_AddObjectToObject(schema, "properties");
    cJSON *msg = cJSON_AddObjectToObject(props, "message");
    cJSON_AddStringToObject(msg, "type", "string");
    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("message"));
    return schema;
}

static sc_tool_result_t *echo_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)self; (void)ctx;
    cJSON *msg = cJSON_GetObjectItem(args, "message");
    if (msg && cJSON_IsString(msg))
        return sc_tool_result_new(msg->valuestring);
    return sc_tool_result_error("no message");
}

static void echo_destroy(sc_tool_t *self) { free(self); }

static sc_tool_t *make_echo_tool(void)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    t->name = "echo";
    t->description = "Echo a message back";
    t->parameters = echo_parameters;
    t->execute = echo_execute;
    t->destroy = echo_destroy;
    return t;
}

/* ========== Pipe-based server test harness ========== */

typedef struct {
    int write_fd;  /* parent writes to child's stdin */
    int read_fd;   /* parent reads from child's stdout */
    pid_t child;
} mcp_test_t;

static mcp_test_t mcp_test_start(sc_tool_registry_t *reg)
{
    mcp_test_t mt = {0};
    int in_pipe[2], out_pipe[2];
    pipe(in_pipe);
    pipe(out_pipe);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: wire pipes and run server */
        close(in_pipe[1]);
        close(out_pipe[0]);
        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        close(in_pipe[0]);
        close(out_pipe[1]);
        sc_mcp_server_run(reg);
        _exit(0);
    }

    close(in_pipe[0]);
    close(out_pipe[1]);
    mt.write_fd = in_pipe[1];
    mt.read_fd = out_pipe[0];
    mt.child = pid;
    return mt;
}

static void mcp_test_send(mcp_test_t *mt, const char *json)
{
    write(mt->write_fd, json, strlen(json));
    write(mt->write_fd, "\n", 1);
}

/* Read one line with timeout */
static char *mcp_test_recv(mcp_test_t *mt)
{
    char buf[8192];
    size_t pos = 0;

    /* Simple blocking read with timeout via alarm */
    alarm(5);
    while (pos < sizeof(buf) - 1) {
        ssize_t n = read(mt->read_fd, buf + pos, 1);
        if (n <= 0) break;
        if (buf[pos] == '\n') {
            buf[pos] = '\0';
            alarm(0);
            return sc_strdup(buf);
        }
        pos++;
    }
    alarm(0);
    buf[pos] = '\0';
    return pos > 0 ? sc_strdup(buf) : NULL;
}

static void mcp_test_stop(mcp_test_t *mt)
{
    close(mt->write_fd);
    close(mt->read_fd);
    int status;
    waitpid(mt->child, &status, 0);
}

/* ========== Tests ========== */

static void test_initialize(void)
{
    sc_tool_registry_t *reg = sc_tool_registry_new();
    sc_tool_registry_register(reg, make_echo_tool());

    mcp_test_t mt = mcp_test_start(reg);

    mcp_test_send(&mt,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
        "\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},"
        "\"clientInfo\":{\"name\":\"test\"}}}");

    char *resp = mcp_test_recv(&mt);
    ASSERT_NOT_NULL(resp);

    cJSON *json = cJSON_Parse(resp);
    ASSERT_NOT_NULL(json);

    cJSON *result = cJSON_GetObjectItem(json, "result");
    ASSERT_NOT_NULL(result);

    cJSON *ver = cJSON_GetObjectItem(result, "protocolVersion");
    ASSERT_NOT_NULL(ver);
    ASSERT_STR_EQ(ver->valuestring, "2024-11-05");

    cJSON *info = cJSON_GetObjectItem(result, "serverInfo");
    ASSERT_NOT_NULL(info);
    ASSERT_STR_EQ(cJSON_GetObjectItem(info, "name")->valuestring, "smolclaw");

    cJSON_Delete(json);
    free(resp);
    mcp_test_stop(&mt);
    sc_tool_registry_free(reg);
}

static void test_tools_list(void)
{
    sc_tool_registry_t *reg = sc_tool_registry_new();
    sc_tool_registry_register(reg, make_echo_tool());

    mcp_test_t mt = mcp_test_start(reg);

    /* Initialize first */
    mcp_test_send(&mt,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
        "\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},"
        "\"clientInfo\":{\"name\":\"test\"}}}");
    char *r1 = mcp_test_recv(&mt);
    free(r1);

    /* List tools */
    mcp_test_send(&mt,
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}");
    char *resp = mcp_test_recv(&mt);
    ASSERT_NOT_NULL(resp);

    cJSON *json = cJSON_Parse(resp);
    ASSERT_NOT_NULL(json);

    cJSON *result = cJSON_GetObjectItem(json, "result");
    ASSERT_NOT_NULL(result);

    cJSON *tools = cJSON_GetObjectItem(result, "tools");
    ASSERT_NOT_NULL(tools);
    ASSERT(cJSON_GetArraySize(tools) == 1, "should have 1 tool");

    cJSON *tool = cJSON_GetArrayItem(tools, 0);
    ASSERT_STR_EQ(cJSON_GetObjectItem(tool, "name")->valuestring, "echo");

    cJSON_Delete(json);
    free(resp);
    mcp_test_stop(&mt);
    sc_tool_registry_free(reg);
}

static void test_tools_call(void)
{
    sc_tool_registry_t *reg = sc_tool_registry_new();
    sc_tool_registry_register(reg, make_echo_tool());

    mcp_test_t mt = mcp_test_start(reg);

    /* Initialize */
    mcp_test_send(&mt,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
        "\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},"
        "\"clientInfo\":{\"name\":\"test\"}}}");
    char *r1 = mcp_test_recv(&mt);
    free(r1);

    /* Call echo tool */
    mcp_test_send(&mt,
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\","
        "\"params\":{\"name\":\"echo\",\"arguments\":{\"message\":\"hello world\"}}}");
    char *resp = mcp_test_recv(&mt);
    ASSERT_NOT_NULL(resp);

    cJSON *json = cJSON_Parse(resp);
    ASSERT_NOT_NULL(json);

    cJSON *result = cJSON_GetObjectItem(json, "result");
    ASSERT_NOT_NULL(result);

    cJSON *content = cJSON_GetObjectItem(result, "content");
    ASSERT_NOT_NULL(content);
    ASSERT(cJSON_GetArraySize(content) == 1, "should have 1 content item");

    cJSON *item = cJSON_GetArrayItem(content, 0);
    ASSERT_STR_EQ(cJSON_GetObjectItem(item, "type")->valuestring, "text");
    ASSERT_STR_EQ(cJSON_GetObjectItem(item, "text")->valuestring, "hello world");

    cJSON_Delete(json);
    free(resp);
    mcp_test_stop(&mt);
    sc_tool_registry_free(reg);
}

static void test_method_not_found(void)
{
    sc_tool_registry_t *reg = sc_tool_registry_new();
    sc_tool_registry_register(reg, make_echo_tool());

    mcp_test_t mt = mcp_test_start(reg);

    /* Initialize */
    mcp_test_send(&mt,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
        "\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},"
        "\"clientInfo\":{\"name\":\"test\"}}}");
    char *r1 = mcp_test_recv(&mt);
    free(r1);

    /* Unknown method */
    mcp_test_send(&mt,
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"unknown/method\",\"params\":{}}");
    char *resp = mcp_test_recv(&mt);
    ASSERT_NOT_NULL(resp);

    cJSON *json = cJSON_Parse(resp);
    ASSERT_NOT_NULL(json);

    cJSON *error = cJSON_GetObjectItem(json, "error");
    ASSERT_NOT_NULL(error);

    cJSON *code = cJSON_GetObjectItem(error, "code");
    ASSERT_NOT_NULL(code);
    ASSERT_INT_EQ(code->valueint, -32601);

    cJSON_Delete(json);
    free(resp);
    mcp_test_stop(&mt);
    sc_tool_registry_free(reg);
}

static void test_not_initialized(void)
{
    sc_tool_registry_t *reg = sc_tool_registry_new();
    sc_tool_registry_register(reg, make_echo_tool());

    mcp_test_t mt = mcp_test_start(reg);

    /* Call without initializing */
    mcp_test_send(&mt,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}");
    char *resp = mcp_test_recv(&mt);
    ASSERT_NOT_NULL(resp);

    cJSON *json = cJSON_Parse(resp);
    ASSERT_NOT_NULL(json);

    cJSON *error = cJSON_GetObjectItem(json, "error");
    ASSERT_NOT_NULL(error);

    cJSON_Delete(json);
    free(resp);
    mcp_test_stop(&mt);
    sc_tool_registry_free(reg);
}

#endif /* SC_ENABLE_MCP_SERVER */

int main(void)
{
#if SC_ENABLE_MCP_SERVER
    RUN_TEST(test_initialize);
    RUN_TEST(test_tools_list);
    RUN_TEST(test_tools_call);
    RUN_TEST(test_method_not_found);
    RUN_TEST(test_not_initialized);
#else
    printf("  MCP server disabled, skipping tests\n");
    _test_pass++;
#endif
    TEST_REPORT();
}
