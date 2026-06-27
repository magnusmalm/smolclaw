/*
 * smolclaw - subagent / MCP tool capability tests (task 3.6)
 */

#include "test_main.h"
#include "sc_features.h"
#include "agent.h"
#include "tools/registry.h"

#include <stdlib.h>
#include <string.h>

#if SC_ENABLE_SPAWN
#include "tools/spawn.h"

static void test_spawn_depth_deny_matrix(void)
{
    /* Top level: nothing denied. */
    ASSERT_INT_EQ(sc_spawn_tool_denied_at_depth("spawn", 0), 0);
    ASSERT_INT_EQ(sc_spawn_tool_denied_at_depth("exec", 0), 0);

    /* depth 1: escalation tools blocked, ordinary tools allowed. */
    ASSERT_INT_EQ(sc_spawn_tool_denied_at_depth("spawn", 1), 1);
    ASSERT_INT_EQ(sc_spawn_tool_denied_at_depth("delegate", 1), 1);
    ASSERT_INT_EQ(sc_spawn_tool_denied_at_depth("cron", 1), 1);
    ASSERT_INT_EQ(sc_spawn_tool_denied_at_depth("read_file", 1), 0);
    ASSERT_INT_EQ(sc_spawn_tool_denied_at_depth("notify", 1), 0);  /* only depth>=2 */

    /* depth 2: stricter — notify/converse/background also blocked. */
    ASSERT_INT_EQ(sc_spawn_tool_denied_at_depth("notify", 2), 1);
    ASSERT_INT_EQ(sc_spawn_tool_denied_at_depth("converse", 2), 1);
    ASSERT_INT_EQ(sc_spawn_tool_denied_at_depth("background", 2), 1);
    ASSERT_INT_EQ(sc_spawn_tool_denied_at_depth("spawn", 2), 1);
    ASSERT_INT_EQ(sc_spawn_tool_denied_at_depth("read_file", 2), 0);

    ASSERT_INT_EQ(sc_spawn_tool_denied_at_depth(NULL, 2), 0);  /* null-safe */
}
#endif /* SC_ENABLE_SPAWN */

static void test_mcp_readonly_allowlist(void)
{
    int n = 0;
    const char **ro = sc_tools_readonly_names(&n);
    ASSERT(n > 0, "read-only list is non-empty");
    ASSERT_NOT_NULL(ro);

    sc_tool_registry_t *reg = sc_tool_registry_new();
    ASSERT_NOT_NULL(reg);
    sc_tool_registry_set_allowed(reg, (char **)ro, n);

    /* Read-only tools permitted... */
    ASSERT_INT_EQ(sc_tool_registry_is_allowed(reg, "read_file"), 1);
    ASSERT_INT_EQ(sc_tool_registry_is_allowed(reg, "list_dir"), 1);
    ASSERT_INT_EQ(sc_tool_registry_is_allowed(reg, "memory_search"), 1);
    ASSERT_INT_EQ(sc_tool_registry_is_allowed(reg, "web_fetch"), 1);

    /* ...write / exec / escalation tools blocked. */
    ASSERT_INT_EQ(sc_tool_registry_is_allowed(reg, "write_file"), 0);
    ASSERT_INT_EQ(sc_tool_registry_is_allowed(reg, "edit_file"), 0);
    ASSERT_INT_EQ(sc_tool_registry_is_allowed(reg, "exec"), 0);
    ASSERT_INT_EQ(sc_tool_registry_is_allowed(reg, "memory_write"), 0);
    ASSERT_INT_EQ(sc_tool_registry_is_allowed(reg, "spawn"), 0);

    sc_tool_registry_free(reg);
}

int main(void)
{
    printf("test_subagent_caps\n");

#if SC_ENABLE_SPAWN
    RUN_TEST(test_spawn_depth_deny_matrix);
#endif
    RUN_TEST(test_mcp_readonly_allowlist);

    TEST_REPORT();
}
