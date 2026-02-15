/*
 * smolclaw - sandbox tests (Landlock + seccomp-bpf)
 *
 * Tests run sandboxed exec commands via the shell tool to verify that
 * the OS-level sandbox correctly restricts filesystem and syscall access.
 */

#include "test_main.h"
#include "util/sandbox.h"
#include "tools/shell.h"
#include "tools/types.h"
#include "config.h"
#include "audit.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* Helper: create a temp workspace dir */
static char *make_tmp_workspace(void)
{
    static char tmpdir[256];
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/sc_sandbox_XXXXXX");
    if (!mkdtemp(tmpdir)) return NULL;
    return tmpdir;
}

/* Helper: run a command via exec tool and return the result */
static sc_tool_result_t *run_sandboxed(const char *workspace, int sandbox,
                                        const char *command)
{
    sc_tool_t *t = sc_tool_exec_new(workspace, 0, 10000, 10);
    if (!t) return NULL;
    sc_tool_exec_set_sandbox(t, sandbox);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "command", command);

    sc_tool_result_t *r = t->execute(t, args, NULL);

    cJSON_Delete(args);
    t->destroy(t);
    return r;
}

static void test_sandbox_available(void)
{
    int flags = sc_sandbox_available();
    /* On Linux 6.1, both should be available */
    ASSERT(flags & SC_SANDBOX_LANDLOCK, "Landlock should be available on Linux 6.1");
    ASSERT(flags & SC_SANDBOX_SECCOMP, "seccomp should be available on Linux 6.1");
}

static void test_sandbox_blocks_etc_write(void)
{
    char *ws = make_tmp_workspace();
    ASSERT_NOT_NULL(ws);

    sc_tool_result_t *r = run_sandboxed(ws, 1, "touch /etc/sc_sandbox_test_file");
    ASSERT_NOT_NULL(r);
    /* Should fail — Landlock denies writes to /etc */
    ASSERT(r->is_error, "touch /etc/... should fail under sandbox");
    sc_tool_result_free(r);

    rmdir(ws);
}

static void test_sandbox_allows_workspace(void)
{
    char *ws = make_tmp_workspace();
    ASSERT_NOT_NULL(ws);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "touch %s/sandbox_test_file && echo ok", ws);

    sc_tool_result_t *r = run_sandboxed(ws, 1, cmd);
    ASSERT_NOT_NULL(r);
    /* Should succeed — workspace has full rw access */
    ASSERT(!r->is_error, "touch in workspace should succeed under sandbox");
    sc_tool_result_free(r);

    /* Cleanup */
    snprintf(cmd, sizeof(cmd), "%s/sandbox_test_file", ws);
    unlink(cmd);
    rmdir(ws);
}

static void test_sandbox_allows_etc_read(void)
{
    char *ws = make_tmp_workspace();
    ASSERT_NOT_NULL(ws);

    sc_tool_result_t *r = run_sandboxed(ws, 1, "cat /etc/hostname");
    ASSERT_NOT_NULL(r);
    /* Should succeed — /etc is read-only accessible */
    ASSERT(!r->is_error, "cat /etc/hostname should succeed under sandbox");
    sc_tool_result_free(r);

    rmdir(ws);
}

static void test_sandbox_blocks_home(void)
{
    char *ws = make_tmp_workspace();
    ASSERT_NOT_NULL(ws);

    /* Try to list home dir ssh keys — should be denied by Landlock */
    sc_tool_result_t *r = run_sandboxed(ws, 1, "ls /root/ 2>&1 || ls ~ 2>&1");
    ASSERT_NOT_NULL(r);
    /* Either the command itself errors or the output shows "Permission denied" */
    const char *output = r->for_llm ? r->for_llm : "";
    int blocked = r->is_error ||
                  strstr(output, "Permission denied") != NULL ||
                  strstr(output, "cannot access") != NULL ||
                  strstr(output, "cannot open") != NULL;
    ASSERT(blocked, "ls /root/ or ~ should be blocked under sandbox");
    sc_tool_result_free(r);

    rmdir(ws);
}

static void test_sandbox_blocks_mount(void)
{
    char *ws = make_tmp_workspace();
    ASSERT_NOT_NULL(ws);

    /* mount should fail with EPERM from seccomp */
    sc_tool_result_t *r = run_sandboxed(ws, 1,
        "mount -t tmpfs none /tmp/sc_test_mount 2>&1; echo exit=$?");
    ASSERT_NOT_NULL(r);
    const char *output = r->for_llm ? r->for_llm : "";
    int blocked = r->is_error ||
                  strstr(output, "not permitted") != NULL ||
                  strstr(output, "Operation not permitted") != NULL ||
                  strstr(output, "permission denied") != NULL ||
                  strstr(output, "exit=1") != NULL ||
                  strstr(output, "exit=32") != NULL;
    ASSERT(blocked, "mount should be blocked by seccomp");
    sc_tool_result_free(r);

    rmdir(ws);
}

static void test_sandbox_disabled(void)
{
    char *ws = make_tmp_workspace();
    ASSERT_NOT_NULL(ws);

    /* With sandbox disabled, /etc read should work (it does without sandbox too) */
    sc_tool_result_t *r = run_sandboxed(ws, 0, "cat /etc/hostname");
    ASSERT_NOT_NULL(r);
    ASSERT(!r->is_error, "cat /etc/hostname should work with sandbox disabled");
    sc_tool_result_free(r);

    rmdir(ws);
}

static void test_config_sandbox_default(void)
{
    sc_config_t *cfg = sc_config_default();
    ASSERT_NOT_NULL(cfg);
    ASSERT_INT_EQ(cfg->sandbox_enabled, 1);
    sc_config_free(cfg);
}

int main(void)
{
    printf("test_sandbox\n");

    sc_audit_init("/dev/null");

    RUN_TEST(test_sandbox_available);
    RUN_TEST(test_sandbox_blocks_etc_write);
    RUN_TEST(test_sandbox_allows_workspace);
    RUN_TEST(test_sandbox_allows_etc_read);
    RUN_TEST(test_sandbox_blocks_home);
    RUN_TEST(test_sandbox_blocks_mount);
    RUN_TEST(test_sandbox_disabled);
    RUN_TEST(test_config_sandbox_default);

    sc_audit_shutdown();

    TEST_REPORT();
}
