/*
 * smolclaw - subagent / MCP tool capability tests (task 3.6)
 */

#include "test_main.h"
#include "sc_features.h"
#include "agent.h"
#include "tools/registry.h"
#include "tools/types.h"

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

/* ---- approval policy + session always-allow cache (task 3.3) ---- */

static int g_confirm_ret;
static int g_confirm_calls;
static int g_exec_calls;

static int mock_confirm(const char *tool, const char *args, void *ctx)
{
    (void)tool; (void)args; (void)ctx;
    g_confirm_calls++;
    return g_confirm_ret;
}

static sc_tool_result_t *danger_exec(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)self; (void)args; (void)ctx;
    g_exec_calls++;
    return sc_tool_result_new("ran");
}

static void danger_destroy(sc_tool_t *self) { free(self); }

static void test_approval_policy_decision(void)
{
    ASSERT_INT_EQ(sc_approval_requires_confirm(SC_APPROVAL_NEVER, 1), 0);
    ASSERT_INT_EQ(sc_approval_requires_confirm(SC_APPROVAL_NEVER, 0), 0);
    ASSERT_INT_EQ(sc_approval_requires_confirm(SC_APPROVAL_ALWAYS, 0), 1);
    ASSERT_INT_EQ(sc_approval_requires_confirm(SC_APPROVAL_ALWAYS, 1), 1);
    ASSERT_INT_EQ(sc_approval_requires_confirm(SC_APPROVAL_DANGEROUS_ONLY, 1), 1);
    ASSERT_INT_EQ(sc_approval_requires_confirm(SC_APPROVAL_DANGEROUS_ONLY, 0), 0);
}

static void test_session_always_allow_cache(void)
{
    sc_tool_registry_t *reg = sc_tool_registry_new();
    sc_tool_registry_register(reg, sc_tool_new_simple(
        "danger", "d", NULL, danger_exec, danger_destroy, 1, NULL));
    sc_tool_registry_set_confirm(reg, mock_confirm, NULL);
    /* default policy = dangerous-only; danger has needs_confirm=1 → confirms */

    /* Deny → execute not reached. */
    g_confirm_ret = 0; g_confirm_calls = 0; g_exec_calls = 0;
    sc_tool_result_free(sc_tool_registry_execute(reg, "danger", NULL, NULL, NULL, NULL));
    ASSERT_INT_EQ(g_confirm_calls, 1);
    ASSERT_INT_EQ(g_exec_calls, 0);

    /* "always" (2) → runs and caches; second call skips confirm. */
    g_confirm_ret = 2; g_confirm_calls = 0; g_exec_calls = 0;
    sc_tool_result_free(sc_tool_registry_execute(reg, "danger", NULL, NULL, NULL, NULL));
    ASSERT_INT_EQ(g_confirm_calls, 1);
    ASSERT_INT_EQ(g_exec_calls, 1);
    sc_tool_result_free(sc_tool_registry_execute(reg, "danger", NULL, NULL, NULL, NULL));
    ASSERT_INT_EQ(g_confirm_calls, 1);   /* cached — not re-prompted */
    ASSERT_INT_EQ(g_exec_calls, 2);

    sc_tool_registry_free(reg);
}

/* Audit M-7: no tool-confirmation bypass via tool-name encoding. The same
 * `name` string drives the allowlist check, the exact-match lookup, and the
 * confirm callback, so a crafted/encoded variant of a confirm-required tool's
 * name cannot reach execution: it simply fails the exact-match lookup ("tool
 * not found") and the real tool's needs_confirm gate is never circumvented. */
static void test_tool_name_no_confirm_bypass(void)
{
    sc_tool_registry_t *reg = sc_tool_registry_new();
    sc_tool_registry_register(reg, sc_tool_new_simple(
        "danger", "d", NULL, danger_exec, danger_destroy, 1, NULL));
    sc_tool_registry_set_confirm(reg, mock_confirm, NULL);
    g_confirm_ret = 0;  /* deny if ever prompted */

    /* Name variants must NOT match the registered tool — no exec, no confirm. */
    const char *variants[] = {
        "danger ",   /* trailing space   */
        " danger",   /* leading space    */
        "Danger",    /* case             */
        "DANGER",
        "danger\t",  /* control char     */
        "danger;",   /* shell-ish suffix */
        "danger\n",
        "dange",     /* prefix           */
    };
    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
        g_confirm_calls = 0; g_exec_calls = 0;
        sc_tool_result_t *r = sc_tool_registry_execute(
            reg, variants[i], NULL, NULL, NULL, NULL);
        sc_tool_result_free(r);
        ASSERT_INT_EQ(g_exec_calls, 0);     /* never executed */
        ASSERT_INT_EQ(g_confirm_calls, 0);  /* confirm gate never even reached */
    }

    /* The exact name still routes through the confirm gate (deny → no exec). */
    g_confirm_calls = 0; g_exec_calls = 0;
    sc_tool_result_free(sc_tool_registry_execute(reg, "danger", NULL, NULL, NULL, NULL));
    ASSERT_INT_EQ(g_confirm_calls, 1);
    ASSERT_INT_EQ(g_exec_calls, 0);

    sc_tool_registry_free(reg);
}

static void test_approval_policy_never_skips_confirm(void)
{
    sc_tool_registry_t *reg = sc_tool_registry_new();
    sc_tool_registry_register(reg, sc_tool_new_simple(
        "danger2", "d", NULL, danger_exec, danger_destroy, 1, NULL));
    sc_tool_registry_set_confirm(reg, mock_confirm, NULL);
    sc_tool_registry_set_approval_policy(reg, SC_APPROVAL_NEVER);

    g_confirm_ret = 0; g_confirm_calls = 0; g_exec_calls = 0;
    sc_tool_result_free(sc_tool_registry_execute(reg, "danger2", NULL, NULL, NULL, NULL));
    ASSERT_INT_EQ(g_confirm_calls, 0);   /* never → no prompt */
    ASSERT_INT_EQ(g_exec_calls, 1);      /* still runs */

    sc_tool_registry_free(reg);
}

int main(void)
{
    printf("test_subagent_caps\n");

#if SC_ENABLE_SPAWN
    RUN_TEST(test_spawn_depth_deny_matrix);
#endif
    RUN_TEST(test_mcp_readonly_allowlist);
    RUN_TEST(test_approval_policy_decision);
    RUN_TEST(test_session_always_allow_cache);
    RUN_TEST(test_approval_policy_never_skips_confirm);
    RUN_TEST(test_tool_name_no_confirm_bypass);

    TEST_REPORT();
}
