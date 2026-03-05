/*
 * smolclaw - MCP client tests
 *
 * Uses a shell script mock server that reads JSON-RPC from stdin
 * and writes responses to stdout.
 */

#include "test_main.h"
#include "mcp/client.h"
#include "mcp/bridge.h"
#include "tools/registry.h"
#include "config.h"
#include "util/str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* Path to the mock server script — created at test time */
static char mock_script_path[256];

/* Create a mock MCP server shell script that handles:
 * - initialize -> capabilities response
 * - tools/list -> returns one "echo" tool
 * - tools/call (echo) -> returns the input message back
 */
static void create_mock_server(void)
{
    char tmpdir[] = "/tmp/sc_test_mcp_XXXXXX";
    char *dir = mkdtemp(tmpdir);
    if (!dir) {
        fprintf(stderr, "Failed to create temp dir\n");
        return;
    }
    snprintf(mock_script_path, sizeof(mock_script_path), "%s/mock_mcp.sh", dir);

    FILE *f = fopen(mock_script_path, "w");
    if (!f) return;

    fprintf(f, "#!/bin/sh\n");
    fprintf(f, "# Mock MCP server — reads JSON-RPC from stdin, responds on stdout\n");
    fprintf(f, "while IFS= read -r line; do\n");
    fprintf(f, "  # Extract method field\n");
    fprintf(f, "  method=$(echo \"$line\" | sed -n 's/.*\"method\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p')\n");
    fprintf(f, "  # Extract id field\n");
    fprintf(f, "  id=$(echo \"$line\" | sed -n 's/.*\"id\"[[:space:]]*:[[:space:]]*\\([0-9]*\\).*/\\1/p')\n");
    fprintf(f, "\n");
    fprintf(f, "  case \"$method\" in\n");
    fprintf(f, "    initialize)\n");
    fprintf(f, "      printf '{\"jsonrpc\":\"2.0\",\"id\":%%s,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"mock\",\"version\":\"1.0\"}}}\\n' \"$id\"\n");
    fprintf(f, "      ;;\n");
    fprintf(f, "    tools/list)\n");
    fprintf(f, "      printf '{\"jsonrpc\":\"2.0\",\"id\":%%s,\"result\":{\"tools\":[{\"name\":\"echo\",\"description\":\"Echo back the message\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"message\":{\"type\":\"string\",\"description\":\"The message to echo\"}},\"required\":[\"message\"]}}]}}\\n' \"$id\"\n");
    fprintf(f, "      ;;\n");
    fprintf(f, "    tools/call)\n");
    fprintf(f, "      # Extract the message argument\n");
    fprintf(f, "      msg=$(echo \"$line\" | sed -n 's/.*\"message\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p')\n");
    fprintf(f, "      printf '{\"jsonrpc\":\"2.0\",\"id\":%%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"%%s\"}]}}\\n' \"$id\" \"$msg\"\n");
    fprintf(f, "      ;;\n");
    fprintf(f, "    notifications/*)\n");
    fprintf(f, "      # Notifications have no id, no response needed\n");
    fprintf(f, "      ;;\n");
    fprintf(f, "    *)\n");
    fprintf(f, "      printf '{\"jsonrpc\":\"2.0\",\"id\":%%s,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}\\n' \"$id\"\n");
    fprintf(f, "      ;;\n");
    fprintf(f, "  esac\n");
    fprintf(f, "done\n");

    fclose(f);
    chmod(mock_script_path, 0755);
}

/* ---------- Tests ---------- */

static void test_mcp_client_lifecycle(void)
{
    char *cmd[] = { "/bin/sh", mock_script_path };
    sc_mcp_client_t *client = sc_mcp_client_start("mock", cmd, 2, NULL, NULL, 0, NULL);
    ASSERT_NOT_NULL(client);

    /* Should be alive */
    ASSERT(sc_mcp_client_is_alive(client), "client should be alive after start");

    /* List tools */
    int count = 0;
    sc_mcp_tool_def_t *tools = sc_mcp_client_list_tools(client, &count);
    ASSERT_NOT_NULL(tools);
    ASSERT_INT_EQ(count, 1);
    ASSERT_STR_EQ(tools[0].name, "echo");
    ASSERT_NOT_NULL(tools[0].input_schema);
    sc_mcp_tool_defs_free(tools, count);

    /* Call tool */
    int is_error = 0;
    char *result = sc_mcp_client_call_tool(client, "echo",
        cJSON_Parse("{\"message\":\"hello world\"}"), &is_error);
    ASSERT_NOT_NULL(result);
    ASSERT_INT_EQ(is_error, 0);
    ASSERT_STR_EQ(result, "hello world");
    free(result);

    /* Stop */
    sc_mcp_client_stop(client);
    ASSERT(sc_mcp_client_is_alive(client) == 0, "client should not be alive after stop");
    sc_mcp_client_free(client);
}

static void test_mcp_bridge_registers_tools(void)
{
    sc_tool_registry_t *reg = sc_tool_registry_new();
    ASSERT_NOT_NULL(reg);

    sc_mcp_server_config_t srv = {0};
    srv.name = "mock";
    char *cmd[] = { "/bin/sh", mock_script_path };
    srv.command = cmd;
    srv.command_count = 2;

    sc_mcp_config_t cfg = {0};
    cfg.enabled = 1;
    cfg.servers = &srv;
    cfg.server_count = 1;

    sc_mcp_bridge_t *bridge = sc_mcp_bridge_start(&cfg, reg, NULL);
    ASSERT_NOT_NULL(bridge);

    /* Should have registered "mock__echo" */
    ASSERT_INT_EQ(sc_tool_registry_count(reg), 1);
    sc_tool_t *tool = sc_tool_registry_get(reg, "mock__echo");
    ASSERT_NOT_NULL(tool);

    /* Execute the proxy tool */
    cJSON *args = cJSON_Parse("{\"message\":\"bridge test\"}");
    sc_tool_result_t *result = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(result);
    ASSERT_INT_EQ(result->is_error, 0);
    ASSERT_STR_EQ(result->for_llm, "bridge test");
    sc_tool_result_free(result);
    cJSON_Delete(args);

    /* Bridge free stops clients, registry free destroys proxy tools */
    sc_mcp_bridge_free(bridge);
    sc_tool_registry_free(reg);
}

static void test_mcp_server_not_found(void)
{
    char *cmd[] = { "/nonexistent/binary" };
    sc_mcp_client_t *client = sc_mcp_client_start("bad", cmd, 1, NULL, NULL, 0, NULL);
    ASSERT_NULL(client);
}

static void test_mcp_server_crash(void)
{
    /* Server that exits immediately after init */
    char tmpdir[] = "/tmp/sc_test_mcp_crash_XXXXXX";
    char *dir = mkdtemp(tmpdir);
    ASSERT_NOT_NULL(dir);

    char crash_script[256];
    snprintf(crash_script, sizeof(crash_script), "%s/crash.sh", dir);

    FILE *f = fopen(crash_script, "w");
    ASSERT_NOT_NULL(f);
    fprintf(f, "#!/bin/sh\n");
    /* Respond to initialize, then exit */
    fprintf(f, "IFS= read -r line\n");
    fprintf(f, "id=$(echo \"$line\" | sed -n 's/.*\"id\"[[:space:]]*:[[:space:]]*\\([0-9]*\\).*/\\1/p')\n");
    fprintf(f, "printf '{\"jsonrpc\":\"2.0\",\"id\":%%s,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"crash\",\"version\":\"1.0\"}}}\\n' \"$id\"\n");
    fprintf(f, "# Read initialized notification then exit\n");
    fprintf(f, "IFS= read -r line\n");
    fprintf(f, "exit 0\n");
    fclose(f);
    chmod(crash_script, 0755);

    char *cmd[] = { "/bin/sh", crash_script };
    sc_mcp_client_t *client = sc_mcp_client_start("crash", cmd, 2, NULL, NULL, 0, NULL);
    ASSERT_NOT_NULL(client);

    /* Give server time to exit */
    usleep(100000); /* 100ms */

    /* Server should be dead */
    ASSERT(sc_mcp_client_is_alive(client) == 0, "crashed server should not be alive");

    /* Tool call should fail */
    int is_error = 0;
    char *result = sc_mcp_client_call_tool(client, "echo",
        cJSON_Parse("{\"message\":\"test\"}"), &is_error);
    /* Result may be an error string or NULL since server is dead */
    ASSERT_INT_EQ(is_error, 1);
    free(result);

    sc_mcp_client_free(client);
}

static void test_mcp_config_parse(void)
{
    /* Create a temp config file with MCP section */
    char tmpdir[] = "/tmp/sc_test_mcp_cfg_XXXXXX";
    char *dir = mkdtemp(tmpdir);
    ASSERT_NOT_NULL(dir);

    char config_path[256];
    snprintf(config_path, sizeof(config_path), "%s/config.json", dir);

    FILE *f = fopen(config_path, "w");
    ASSERT_NOT_NULL(f);
    fprintf(f, "{\n");
    fprintf(f, "  \"mcp\": {\n");
    fprintf(f, "    \"enabled\": true,\n");
    fprintf(f, "    \"servers\": {\n");
    fprintf(f, "      \"test\": {\n");
    fprintf(f, "        \"command\": [\"echo\", \"hello\"],\n");
    fprintf(f, "        \"env\": { \"KEY\": \"val\" }\n");
    fprintf(f, "      }\n");
    fprintf(f, "    }\n");
    fprintf(f, "  }\n");
    fprintf(f, "}\n");
    fclose(f);

    sc_config_t *cfg = sc_config_load(config_path);
    ASSERT_NOT_NULL(cfg);
    ASSERT_INT_EQ(cfg->mcp.enabled, 1);
    ASSERT_INT_EQ(cfg->mcp.server_count, 1);
    ASSERT_STR_EQ(cfg->mcp.servers[0].name, "test");
    ASSERT_INT_EQ(cfg->mcp.servers[0].command_count, 2);
    ASSERT_STR_EQ(cfg->mcp.servers[0].command[0], "echo");
    ASSERT_STR_EQ(cfg->mcp.servers[0].command[1], "hello");
    ASSERT_INT_EQ(cfg->mcp.servers[0].env_count, 1);
    ASSERT_STR_EQ(cfg->mcp.servers[0].env_keys[0], "KEY");
    ASSERT_STR_EQ(cfg->mcp.servers[0].env_values[0], "val");

    sc_config_free(cfg);
}

int main(void)
{
    printf("test_mcp\n");

    create_mock_server();

    RUN_TEST(test_mcp_config_parse);
    RUN_TEST(test_mcp_client_lifecycle);
    RUN_TEST(test_mcp_bridge_registers_tools);
    RUN_TEST(test_mcp_server_not_found);
    RUN_TEST(test_mcp_server_crash);

    TEST_REPORT();
}
