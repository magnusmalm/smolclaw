/*
 * smolclaw - exec safety tests (deny-list init, chdir, working_dir resolve)
 */

#include "test_main.h"
#include "tools/exec_common.h"
#include "tools/shell.h"
#include "tools/types.h"
#include "audit.h"
#include "cJSON.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void test_deny_list_init_invalid_pattern(void)
{
    const char *bad[] = { "[invalid" };
    sc_deny_list_t dl = { 0 };

    ASSERT_INT_EQ(sc_deny_list_init_from(&dl, bad, 1), -1);
    ASSERT_NULL(dl.patterns);
    ASSERT_NULL(dl.compiled);
    ASSERT_INT_EQ(dl.count, 0);
}

static void test_deny_list_init_valid_pattern(void)
{
    const char *good[] = { "\\brm\\b" };
    sc_deny_list_t dl = { 0 };

    ASSERT_INT_EQ(sc_deny_list_init_from(&dl, good, 1), 0);
    ASSERT_NOT_NULL(dl.patterns);
    ASSERT_NOT_NULL(dl.compiled);
    ASSERT_INT_EQ(dl.compiled[0], 1);
    ASSERT_INT_EQ(sc_deny_list_matches(&dl, "rm -rf /"), 1);
    ASSERT_INT_EQ(sc_deny_list_matches(&dl, "echo ok"), 0);
    sc_deny_list_free(&dl);
}

static void test_deny_list_production_patterns_compile(void)
{
    sc_deny_list_t dl = { 0 };
    ASSERT_INT_EQ(sc_deny_list_init(&dl), 0);
    ASSERT_INT_EQ(dl.count > 0, 1);
    sc_deny_list_free(&dl);
}

static void test_chdir_failure_refuses_exec(void)
{
    char ws_template[] = "/tmp/sc_chdir_test_XXXXXX";
    char *ws = mkdtemp(ws_template);
    ASSERT_NOT_NULL(ws);

    sc_tool_t *t = sc_tool_exec_new(ws, 0, 10000, 10);
    ASSERT_NOT_NULL(t);
    sc_tool_exec_set_sandbox(t, 0);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "command", "echo ok");
    cJSON_AddStringToObject(args, "working_dir",
                            "/nonexistent/sc_bad_wd_XXXXXX");

    sc_tool_result_t *r = t->execute(t, args, NULL);
    ASSERT_NOT_NULL(r);
    const char *out = r->for_llm ? r->for_llm : "";
    int failed = r->is_error ||
                 strstr(out, "chdir failed") != NULL ||
                 strstr(out, "Exit code: 126") != NULL;
    ASSERT(failed, "bad working_dir should refuse exec");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    t->destroy(t);
    rmdir(ws);
}

static void test_working_dir_uses_resolved_path(void)
{
    char ws_template[] = "/tmp/sc_wd_resolve_XXXXXX";
    char *ws = mkdtemp(ws_template);
    ASSERT_NOT_NULL(ws);

    char subdir[PATH_MAX];
    snprintf(subdir, sizeof(subdir), "%s/sub", ws);
    ASSERT_INT_EQ(mkdir(subdir, 0755), 0);

    char linkpath[PATH_MAX];
    snprintf(linkpath, sizeof(linkpath), "%s/link", ws);
    ASSERT_INT_EQ(symlink(subdir, linkpath), 0);

    char *real_sub = realpath(subdir, NULL);
    ASSERT_NOT_NULL(real_sub);

    sc_tool_t *t = sc_tool_exec_new(ws, 1, 10000, 10);
    ASSERT_NOT_NULL(t);
    sc_tool_exec_set_sandbox(t, 0);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "command", "pwd");
    cJSON_AddStringToObject(args, "working_dir", "link");

    sc_tool_result_t *r = t->execute(t, args, NULL);
    ASSERT_NOT_NULL(r);
    ASSERT(!r->is_error, "pwd via symlink working_dir should succeed");
    const char *out = r->for_llm ? r->for_llm : "";
    ASSERT(strstr(out, real_sub) != NULL, "pwd should show resolved path");

    sc_tool_result_free(r);
    cJSON_Delete(args);
    t->destroy(t);
    free(real_sub);
    unlink(linkpath);
    rmdir(subdir);
    rmdir(ws);
}

int main(void)
{
    printf("test_exec_safety\n");

    sc_audit_init("/dev/null");

    RUN_TEST(test_deny_list_init_invalid_pattern);
    RUN_TEST(test_deny_list_init_valid_pattern);
    RUN_TEST(test_deny_list_production_patterns_compile);
    RUN_TEST(test_chdir_failure_refuses_exec);
    RUN_TEST(test_working_dir_uses_resolved_path);

    sc_audit_shutdown();

    TEST_REPORT();
}