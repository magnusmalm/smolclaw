/*
 * tools/shell.c - Shell command execution tool
 *
 * Executes commands via fork/exec with configurable timeout.
 * Deny patterns, env sanitization, and command guard in exec_common.c.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/wait.h>

#include "tools/shell.h"
#include "tools/types.h"
#include "tools/exec_common.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "logger.h"
#include "constants.h"
#include "cJSON.h"

#include "sc_features.h"
#if SC_ENABLE_TEE
#include "tee.h"
#endif
#if SC_ENABLE_OUTPUT_FILTER
#include "tools/output_filter.h"
#endif

/* Shell tool data */
typedef struct {
    char *working_dir;
    int restrict_to_workspace;
    int max_output_chars;
    int timeout_secs;
    sc_deny_list_t deny;
    int use_allowlist;
    char **allowed_commands;
    int allowed_count;
    int sandbox_enabled;
#if SC_ENABLE_TEE
    sc_tee_config_t *tee_cfg;
#endif
} shell_data_t;

/* ---------- Tool implementation ---------- */

static void shell_destroy(sc_tool_t *self)
{
    if (!self) return;
    shell_data_t *d = self->data;
    if (d) {
        sc_exec_data_free(&d->deny, d->allowed_commands,
                          d->allowed_count, d->working_dir);
        free(d);
    }
    free(self);
}

static cJSON *shell_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "command", "The shell command to execute", 1);
    sc_schema_add_string(schema, "working_dir",
                         "Optional working directory for the command", 0);
    return schema;
}

/* Get monotonic clock in seconds */
static double monotonic_secs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Read child output via select() with monotonic deadline.
 * Returns 1 if timed out, 0 if child exited normally. */
static int shell_read_output(int fd, sc_strbuf_t *output, double deadline)
{
    char buf[4096];
    int done = 0;
    while (!done) {
        int timeout_ms;
        if (deadline > 0) {
            double remaining = deadline - monotonic_secs();
            if (remaining <= 0)
                return 1;
            timeout_ms = (remaining > 1.0) ? 1000 : (int)(remaining * 1000);
        } else {
            timeout_ms = 1000;
        }

        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int sel = poll(&pfd, 1, timeout_ms);
        if (sel > 0) {
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                sc_strbuf_append(output, buf);
            } else {
                done = 1;
            }
        } else if (sel == 0) {
            if (deadline > 0 && monotonic_secs() >= deadline)
                return 1;
        } else {
            if (errno == EINTR)
                continue;
            done = 1;
        }
    }
    return 0;
}

/* Append exit code, truncate, build tool result.
 * Returns sc_tool_result_t. Caller frees. */
static sc_tool_result_t *shell_format_result(char *out_str, int exit_code,
                                               int timed_out,
                                               int max_output_chars)
{
    int is_error = timed_out || exit_code != 0;

    /* Append exit code if non-zero and not already timed out */
    if (!timed_out && exit_code != 0) {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        if (out_str && *out_str)
            sc_strbuf_append(&sb, out_str);
        sc_strbuf_appendf(&sb, "\nExit code: %d", exit_code);
        free(out_str);
        out_str = sc_strbuf_finish(&sb);
    }

    if (!out_str || !*out_str) {
        free(out_str);
        out_str = sc_strdup("(no output)");
    }

    /* Truncate if too long */
    size_t len = strlen(out_str);
    size_t max_chars = (size_t)max_output_chars;
    if (len > max_chars) {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        char *trunc = sc_strdup(out_str);
        if (trunc) {
            trunc[max_chars] = '\0';
            sc_strbuf_append(&sb, trunc);
            sc_strbuf_appendf(&sb, "\n... (truncated, %zu more chars)",
                              len - max_chars);
            free(trunc);
        }
        free(out_str);
        out_str = sc_strbuf_finish(&sb);
    }

    sc_tool_result_t *result;
    if (is_error) {
        result = sc_tool_result_error(out_str);
        result->for_user = sc_strdup(out_str);
        result->is_error = 1;
    } else {
        result = sc_tool_result_user(out_str);
    }

    free(out_str);
    return result;
}

static sc_tool_result_t *shell_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    shell_data_t *d = self->data;

    const char *command = sc_json_get_string(args, "command", NULL);
    if (!command)
        return sc_tool_result_error("command is required");

    const char *working_dir = sc_json_get_string(args, "working_dir", NULL);
    const char *cwd = d->working_dir;
    if (working_dir && *working_dir) {
        if (d->restrict_to_workspace) {
            char *resolved_wd = sc_validate_path(working_dir, d->working_dir,
                                                  d->restrict_to_workspace);
            if (!resolved_wd)
                return sc_tool_result_error("working_dir outside workspace");
            free(resolved_wd);
        }
        cwd = working_dir;
    }

    /* Safety guard */
    const char *guard_err = sc_exec_guard_command(&d->deny, command,
        d->use_allowlist, d->allowed_commands, d->allowed_count,
        d->restrict_to_workspace);
    if (guard_err)
        return sc_tool_result_error(guard_err);

    /* Create pipe for stdout+stderr */
    int pipefd[2];
    if (pipe(pipefd) != 0)
        return sc_tool_result_error("failed to create pipe");

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return sc_tool_result_error("failed to fork");
    }

    if (pid == 0) {
        setpgid(0, 0);
        close(pipefd[0]);
        sc_exec_child(command, cwd, d->working_dir, d->sandbox_enabled,
                      pipefd[1]);
    }

    /* Parent */
    close(pipefd[1]);

    sc_strbuf_t output;
    sc_strbuf_init(&output);

    double deadline = (d->timeout_secs > 0)
        ? monotonic_secs() + (double)d->timeout_secs
        : 0;

    int timed_out = shell_read_output(pipefd[0], &output, deadline);
    close(pipefd[0]);

    int status = 0;
    if (timed_out) {
        kill(-pid, SIGKILL);
        waitpid(pid, &status, 0);
        sc_strbuf_appendf(&output,
            "\nError: command timed out after %d seconds", d->timeout_secs);
        status = -1;
    } else {
        waitpid(pid, &status, 0);
    }

    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    char *out_str = sc_strbuf_finish(&output);

#if SC_ENABLE_TEE || SC_ENABLE_OUTPUT_FILTER
    /* Pre-truncation: tee raw output and/or apply output filter */
    if (out_str) {
        size_t raw_len = strlen(out_str);
        char *tee_path = NULL;
#if SC_ENABLE_TEE
        /* Tee full output before truncation if it will be truncated */
        if (d->tee_cfg && raw_len > (size_t)d->max_output_chars) {
            tee_path = sc_tee_save(d->tee_cfg, out_str, raw_len, "exec");
        }
#endif
#if SC_ENABLE_OUTPUT_FILTER
        /* Try to compress output for known CLI tools */
        sc_filter_type_t ftype = sc_filter_detect(command);
        if (ftype != SC_FILTER_NONE) {
            char *filtered = sc_filter_apply(ftype, out_str, raw_len);
            if (filtered) {
                free(out_str);
                out_str = filtered;
            }
        }
#endif
#if SC_ENABLE_TEE
        /* Append tee hint if we saved the full output */
        if (tee_path) {
            sc_strbuf_t hint;
            sc_strbuf_init(&hint);
            sc_strbuf_append(&hint, out_str);
            sc_strbuf_appendf(&hint, "\n[full output: %s]", tee_path);
            free(out_str);
            out_str = sc_strbuf_finish(&hint);
            free(tee_path);
        }
#endif
    }
#endif

    return shell_format_result(out_str, exit_code, timed_out,
                                d->max_output_chars);
}

sc_tool_t *sc_tool_exec_new(const char *working_dir, int restrict_to_workspace,
                            int max_output_chars, int timeout_secs)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    shell_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(t); return NULL; }

    d->working_dir = sc_strdup(working_dir);
    d->restrict_to_workspace = restrict_to_workspace;
    d->max_output_chars = max_output_chars;
    d->timeout_secs = timeout_secs;
    sc_deny_list_init(&d->deny);

    t->name = "exec";
    t->description = "Execute a shell command and return its output. Use with caution.";
    t->parameters = shell_parameters;
    t->execute = shell_execute;
    t->destroy = shell_destroy;
    t->needs_confirm = 1;
    t->data = d;
    return t;
}

void sc_tool_exec_set_allowlist(sc_tool_t *t, int use_allowlist,
                                 char *const *commands, int count)
{
    if (!t || !t->data) return;
    shell_data_t *d = t->data;
    sc_exec_set_allowlist(&d->use_allowlist, &d->allowed_commands,
                          &d->allowed_count, use_allowlist, commands, count);
}

void sc_tool_exec_set_sandbox(sc_tool_t *t, int enabled)
{
    if (!t || !t->data) return;
    shell_data_t *d = t->data;
    d->sandbox_enabled = enabled;
}

void sc_tool_exec_set_tee(sc_tool_t *t, struct sc_tee_config *tee_cfg)
{
#if SC_ENABLE_TEE
    if (!t || !t->data) return;
    shell_data_t *d = t->data;
    d->tee_cfg = tee_cfg;
#else
    (void)t; (void)tee_cfg;
#endif
}
