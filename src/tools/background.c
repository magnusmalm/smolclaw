/*
 * tools/background.c - Background process management tools
 *
 * Three tools: exec_background (start), bg_poll (check output), bg_kill (terminate).
 * Module-static process registry, max SC_BG_MAX_PROCS slots.
 * Deny patterns, env sanitization, and command guard in exec_common.c.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <pthread.h>

#include "tools/background.h"
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
static sc_tee_config_t *bg_tee_cfg;
#endif

#define LOG_TAG "background"

/* ---------- Process registry ---------- */

typedef struct {
    pid_t pid;
    int fd;        /* read end of stdout+stderr pipe */
    int alive;     /* 1 = running, 0 = exited */
    int exit_code;
} sc_bg_process_t;

static sc_bg_process_t *bg_procs;
static int bg_max_procs;
static pthread_mutex_t bg_lock = PTHREAD_MUTEX_INITIALIZER;

static int bg_find_free_slot(void)
{
    for (int i = 0; i < bg_max_procs; i++) {
        if (bg_procs[i].pid == 0)
            return i;
    }
    return -1;
}

static void bg_clear_slot(int slot)
{
    if (slot < 0 || slot >= bg_max_procs) return;
    if (bg_procs[slot].fd > 0) {
        close(bg_procs[slot].fd);
    }
    memset(&bg_procs[slot], 0, sizeof(bg_procs[slot]));
}

void sc_bg_cleanup_all(void)
{
    pthread_mutex_lock(&bg_lock);
    for (int i = 0; i < bg_max_procs; i++) {
        if (bg_procs[i].pid > 0) {
            kill(bg_procs[i].pid, SIGTERM);
            waitpid(bg_procs[i].pid, NULL, 0);
            bg_clear_slot(i);
        }
    }
    free(bg_procs);
    bg_procs = NULL;
    bg_max_procs = 0;
    pthread_mutex_unlock(&bg_lock);
}

/* ---------- exec_background tool ---------- */

typedef struct {
    char *workspace;
    int restrict_to_workspace;
    sc_deny_list_t deny;
    int use_allowlist;
    char **allowed_commands;
    int allowed_count;
    int sandbox_enabled;
} exec_bg_data_t;

static void exec_bg_destroy(sc_tool_t *self)
{
    if (!self) return;
    exec_bg_data_t *d = self->data;
    if (d) {
        sc_exec_data_free(&d->deny, d->allowed_commands,
                          d->allowed_count, d->workspace);
        free(d);
    }
    free(self);
}

static cJSON *exec_bg_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "command",
                         "Shell command to run in the background", 1);
    return schema;
}

/* Reap completed processes to free slots and prevent zombies */
static void bg_reap_finished(void)
{
    for (int i = 0; i < bg_max_procs; i++) {
        if (bg_procs[i].pid > 0 && bg_procs[i].alive) {
            int status;
            pid_t w = waitpid(bg_procs[i].pid, &status, WNOHANG);
            if (w > 0) {
                bg_procs[i].alive = 0;
                bg_procs[i].exit_code = WIFEXITED(status)
                    ? WEXITSTATUS(status) : -1;
            }
        }
    }
}

static sc_tool_result_t *exec_bg_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    exec_bg_data_t *d = self->data;

    const char *command = sc_json_get_string(args, "command", NULL);
    if (!command || command[0] == '\0')
        return sc_tool_result_error("command is required");

    /* Safety guard */
    const char *guard_err = sc_exec_guard_command(&d->deny, command,
        d->use_allowlist, d->allowed_commands, d->allowed_count,
        d->restrict_to_workspace);
    if (guard_err)
        return sc_tool_result_error(guard_err);

    /* Opportunistically reap finished processes before allocating a slot */
    pthread_mutex_lock(&bg_lock);
    bg_reap_finished();

    /* Find free slot */
    int slot = bg_find_free_slot();
    if (slot < 0)
    {
        pthread_mutex_unlock(&bg_lock);
        sc_strbuf_t esb;
        sc_strbuf_init(&esb);
        sc_strbuf_appendf(&esb, "Maximum background processes reached (limit: %d)",
                          bg_max_procs);
        char *emsg = sc_strbuf_finish(&esb);
        sc_tool_result_t *er = sc_tool_result_error(emsg);
        free(emsg);
        return er;
    }

    /* Create pipe for stdout+stderr */
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        pthread_mutex_unlock(&bg_lock);
        return sc_tool_result_error("Failed to create pipe");
    }

    pid_t pid = fork();
    if (pid < 0) {
        pthread_mutex_unlock(&bg_lock);
        close(pipefd[0]);
        close(pipefd[1]);
        return sc_tool_result_error("Failed to fork");
    }

    if (pid == 0) {
        /* Child */
        close(pipefd[0]);
        sc_exec_child(command, d->workspace, d->workspace,
                      d->sandbox_enabled, pipefd[1]);
    }

    /* Parent */
    close(pipefd[1]);

    /* Set read end to non-blocking */
    int flags = fcntl(pipefd[0], F_GETFL);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    bg_procs[slot].pid = pid;
    bg_procs[slot].fd = pipefd[0];
    bg_procs[slot].alive = 1;
    bg_procs[slot].exit_code = 0;
    pthread_mutex_unlock(&bg_lock);

    SC_LOG_INFO(LOG_TAG, "Started background process slot=%d pid=%d: %s",
                slot, (int)pid, command);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Background process started (slot %d, pid %d)",
                      slot, (int)pid);
    char *msg = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(msg);
    free(msg);
    return r;
}

sc_tool_t *sc_tool_exec_bg_new(const char *workspace, int restrict_to_workspace,
                               int max_procs)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    exec_bg_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(t); return NULL; }

    d->workspace = sc_strdup(workspace);
    d->restrict_to_workspace = restrict_to_workspace;
    sc_deny_list_init(&d->deny);

    /* Initialize process table — refuse if active processes exist */
    if (bg_procs) {
        for (int i = 0; i < bg_max_procs; i++) {
            if (bg_procs[i].pid > 0) {
                SC_LOG_ERROR("background", "Cannot reinitialize: active processes exist");
                sc_deny_list_free(&d->deny);
                free(d->workspace);
                free(d);
                free(t);
                return NULL;
            }
        }
        free(bg_procs);
    }
    bg_max_procs = max_procs > 0 ? max_procs : SC_BG_MAX_PROCS;
    bg_procs = calloc((size_t)bg_max_procs, sizeof(sc_bg_process_t));
    if (!bg_procs) {
        sc_deny_list_free(&d->deny);
        free(d->workspace);
        free(d);
        free(t);
        return NULL;
    }

    t->name = "exec_background";
    t->description = "Start a shell command in the background. Returns a slot "
                     "number to use with bg_poll and bg_kill.";
    t->parameters = exec_bg_parameters;
    t->execute = exec_bg_execute;
    t->destroy = exec_bg_destroy;
    t->needs_confirm = 1;
    t->data = d;
    return t;
}

/* ---------- bg_poll tool ---------- */

static cJSON *bg_poll_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_integer(schema, "slot",
                          "Slot number returned by exec_background", 1);
    return schema;
}

static sc_tool_result_t *bg_poll_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)self;
    (void)ctx;

    int slot = sc_json_get_int(args, "slot", -1);

    pthread_mutex_lock(&bg_lock);
    if (slot < 0 || slot >= bg_max_procs) {
        pthread_mutex_unlock(&bg_lock);
        return sc_tool_result_error("Invalid slot number");
    }

    sc_bg_process_t *proc = &bg_procs[slot];
    if (proc->pid == 0) {
        pthread_mutex_unlock(&bg_lock);
        return sc_tool_result_error("No process in this slot");
    }

    /* Read available output (non-blocking), capped to prevent OOM */
    sc_strbuf_t output;
    sc_strbuf_init(&output);
    char buf[4096];
    ssize_t n;
    int capped = 0;
    while ((n = read(proc->fd, buf, sizeof(buf) - 1)) > 0) {
        if (output.len + (size_t)n > SC_MAX_OUTPUT_CHARS) {
            size_t remaining = SC_MAX_OUTPUT_CHARS - output.len;
            if (remaining > 0) {
                buf[remaining] = '\0';
                sc_strbuf_append(&output, buf);
            }
            capped = 1;
            /* Drain remaining data without storing */
            while (read(proc->fd, buf, sizeof(buf)) > 0)
                ;
            break;
        }
        buf[n] = '\0';
        sc_strbuf_append(&output, buf);
    }
    if (capped)
        sc_strbuf_append(&output, "\n[output truncated]");

    /* Check if process has exited */
    if (proc->alive) {
        int status;
        pid_t w = waitpid(proc->pid, &status, WNOHANG);
        if (w > 0) {
            proc->alive = 0;
            proc->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        }
    }

    int is_alive = proc->alive;
    int exit_code = proc->exit_code;
    char *out_str = sc_strbuf_finish(&output);
    pthread_mutex_unlock(&bg_lock);

    /* Truncate if too long */
    size_t len = out_str ? strlen(out_str) : 0;
    if (len > (size_t)SC_MAX_OUTPUT_CHARS) {
#if SC_ENABLE_TEE
        if (bg_tee_cfg) {
            char *tee_path = sc_tee_save(bg_tee_cfg, out_str, len, "bg_poll");
            if (tee_path) {
                out_str[SC_MAX_OUTPUT_CHARS] = '\0';
                sc_strbuf_t hint;
                sc_strbuf_init(&hint);
                sc_strbuf_append(&hint, out_str);
                sc_strbuf_appendf(&hint, "\n[full output: %s]", tee_path);
                free(out_str);
                out_str = sc_strbuf_finish(&hint);
                free(tee_path);
            } else {
                out_str[SC_MAX_OUTPUT_CHARS] = '\0';
            }
        } else
#endif
        {
            out_str[SC_MAX_OUTPUT_CHARS] = '\0';
        }
    }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Status: %s", is_alive ? "running" : "exited");
    if (!is_alive)
        sc_strbuf_appendf(&sb, " (exit code: %d)", exit_code);
    sc_strbuf_append(&sb, "\nOutput:\n");
    sc_strbuf_append(&sb, (out_str && out_str[0]) ? out_str : "(no new output)");

    free(out_str);
    char *result_str = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(result_str);
    free(result_str);
    return r;
}

static void bg_poll_destroy(sc_tool_t *self)
{
    free(self);
}

sc_tool_t *sc_tool_bg_poll_new(void)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    t->name = "bg_poll";
    t->description = "Check output and status of a background process by slot number.";
    t->parameters = bg_poll_parameters;
    t->execute = bg_poll_execute;
    t->destroy = bg_poll_destroy;
    t->data = NULL;
    return t;
}

/* ---------- bg_kill tool ---------- */

static cJSON *bg_kill_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_integer(schema, "slot",
                          "Slot number of the process to kill", 1);
    return schema;
}

static sc_tool_result_t *bg_kill_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)self;
    (void)ctx;

    int slot = sc_json_get_int(args, "slot", -1);

    pthread_mutex_lock(&bg_lock);
    if (slot < 0 || slot >= bg_max_procs) {
        pthread_mutex_unlock(&bg_lock);
        return sc_tool_result_error("Invalid slot number");
    }

    sc_bg_process_t *proc = &bg_procs[slot];
    if (proc->pid == 0) {
        pthread_mutex_unlock(&bg_lock);
        return sc_tool_result_error("No process in this slot");
    }

    if (proc->alive) {
        kill(proc->pid, SIGTERM);
        /* Brief wait then force kill if needed */
        int status = 0;
        pid_t w = waitpid(proc->pid, &status, WNOHANG);
        if (w == 0) {
            usleep(100000); /* 100ms */
            w = waitpid(proc->pid, &status, WNOHANG);
            if (w == 0) {
                kill(proc->pid, SIGKILL);
                waitpid(proc->pid, &status, 0);
            }
        }
        proc->alive = 0;
        proc->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

    pid_t killed_pid = proc->pid;
    bg_clear_slot(slot);
    pthread_mutex_unlock(&bg_lock);

    SC_LOG_INFO(LOG_TAG, "Killed background process slot=%d pid=%d",
                slot, (int)killed_pid);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Process in slot %d (pid %d) terminated",
                      slot, (int)killed_pid);
    char *msg = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(msg);
    free(msg);

    return r;
}

static void bg_kill_destroy(sc_tool_t *self)
{
    free(self);
}

sc_tool_t *sc_tool_bg_kill_new(void)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    t->name = "bg_kill";
    t->description = "Kill a background process by slot number.";
    t->parameters = bg_kill_parameters;
    t->execute = bg_kill_execute;
    t->destroy = bg_kill_destroy;
    t->data = NULL;
    return t;
}

void sc_tool_exec_bg_set_allowlist(sc_tool_t *t, int use_allowlist,
                                    char *const *commands, int count)
{
    if (!t || !t->data) return;
    exec_bg_data_t *d = (exec_bg_data_t *)t->data;
    sc_exec_set_allowlist(&d->use_allowlist, &d->allowed_commands,
                          &d->allowed_count, use_allowlist, commands, count);
}

void sc_tool_exec_bg_set_sandbox(sc_tool_t *t, int enabled)
{
    if (!t || !t->data) return;
    exec_bg_data_t *d = (exec_bg_data_t *)t->data;
    d->sandbox_enabled = enabled;
}

void sc_tool_bg_poll_set_tee(struct sc_tee_config *tee_cfg)
{
#if SC_ENABLE_TEE
    bg_tee_cfg = tee_cfg;
#else
    (void)tee_cfg;
#endif
}
