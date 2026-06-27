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
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>

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

static void test_sandbox_mandatory_workspace_missing(void)
{
    pid_t pid = fork();
    ASSERT_INT_EQ(pid >= 0, 1);

    if (pid == 0) {
        sc_sandbox_opts_t opts = {
            .workspace = "/nonexistent/sc_sandbox_ws_missing",
            .tmpdir = "/tmp",
        };
        int rc = sc_sandbox_apply(&opts);
        _exit(rc == -1 ? 0 : 1);
    }

    int status = 0;
    ASSERT_INT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT(WIFEXITED(status), "sandbox child should exit normally");
    ASSERT_INT_EQ(WEXITSTATUS(status), 0);
}

/* ---- Task 4.2: per-server capability seccomp probes ------------------ *
 * Each probe forks a child, applies the sandbox with the given caps, then
 * exercises a syscall. The child exits 0 if the syscall was ALLOWED and 1 if
 * BLOCKED (EPERM), so the parent can assert on the exit code. Runs only when
 * seccomp is actually available. */

/* Returns child exit status: 0 = syscall allowed, 1 = blocked. */
static int run_cap_probe(int no_process, int no_network, int test_socket)
{
    char *ws = make_tmp_workspace();
    if (!ws) return -1;

    pid_t pid = fork();
    if (pid < 0) { rmdir(ws); return -1; }
    if (pid == 0) {
        sc_sandbox_opts_t opts = {
            .workspace = ws,
            .tmpdir = "/tmp",
            .cap_no_process = no_process,
            .cap_no_network = no_network,
        };
        sc_sandbox_apply(&opts);

        if (test_socket) {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd >= 0) { close(fd); _exit(0); }  /* allowed */
            _exit(errno == EPERM ? 1 : 2);          /* blocked */
        } else {
            pid_t c = fork();                        /* -> clone syscall */
            if (c == 0) _exit(0);                    /* child of child */
            if (c < 0) _exit(errno == EPERM ? 1 : 2);/* blocked */
            int st = 0; waitpid(c, &st, 0);
            _exit(0);                                /* allowed */
        }
    }

    int status = 0;
    waitpid(pid, &status, 0);
    rmdir(ws);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void test_sandbox_no_network_blocks_socket(void)
{
    if (!(sc_sandbox_available() & SC_SANDBOX_SECCOMP)) return;  /* env w/o seccomp */
    ASSERT_INT_EQ(run_cap_probe(0, 1, 1), 1);  /* cap_no_network -> socket blocked */
}

static void test_sandbox_network_allowed_by_default(void)
{
    if (!(sc_sandbox_available() & SC_SANDBOX_SECCOMP)) return;
    ASSERT_INT_EQ(run_cap_probe(0, 0, 1), 0);  /* default -> socket allowed */
}

static void test_sandbox_no_process_blocks_fork(void)
{
    if (!(sc_sandbox_available() & SC_SANDBOX_SECCOMP)) return;
    ASSERT_INT_EQ(run_cap_probe(1, 0, 0), 1);  /* cap_no_process -> fork blocked */
}

static void test_sandbox_process_allowed_by_default(void)
{
    if (!(sc_sandbox_available() & SC_SANDBOX_SECCOMP)) return;
    ASSERT_INT_EQ(run_cap_probe(0, 0, 0), 0);  /* default -> fork allowed */
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
    RUN_TEST(test_sandbox_mandatory_workspace_missing);
    RUN_TEST(test_sandbox_no_network_blocks_socket);
    RUN_TEST(test_sandbox_network_allowed_by_default);
    RUN_TEST(test_sandbox_no_process_blocks_fork);
    RUN_TEST(test_sandbox_process_allowed_by_default);
    RUN_TEST(test_config_sandbox_default);

    sc_audit_shutdown();

    TEST_REPORT();
}
