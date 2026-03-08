/*
 * tools/git.c - Git tool with subcommand allowlist
 *
 * Provides safe git operations via fork+execvp (no shell).
 * Only allows a curated set of subcommands.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "tools/git.h"
#include "tools/types.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "logger.h"
#include "constants.h"
#include "cJSON.h"

#define GIT_TAG "git_tool"
#define GIT_MAX_OUTPUT (64 * 1024)  /* 64 KB output cap */
#define GIT_TIMEOUT_SECS 30
#define GIT_MAX_ARGS 64

typedef struct {
    char *working_dir;
    int restrict_to_workspace;
} git_data_t;

/* Allowed subcommands with per-command confirmation requirement */
static const struct {
    const char *name;
    int needs_confirm;
} git_subcmds[] = {
    { "status",   0 },
    { "log",      0 },
    { "diff",     0 },
    { "show",     0 },
    { "blame",    0 },
    { "branch",   0 },
    { "tag",      0 },
    { "remote",   0 },
    { "rev-parse",0 },
    { "ls-files", 0 },
    { "add",      1 },
    { "commit",   1 },
    { "checkout", 1 },
    { "stash",    1 },
    { "fetch",    0 },
    { "pull",     1 },
    { "merge",    1 },
    { "rebase",   1 },
    { "reset",    1 },
    { "clean",    1 },
    { "restore",  1 },
    { "switch",   1 },
};
#define GIT_SUBCMD_COUNT (int)(sizeof(git_subcmds) / sizeof(git_subcmds[0]))

static int is_allowed_subcmd(const char *subcmd, int *needs_confirm)
{
    for (int i = 0; i < GIT_SUBCMD_COUNT; i++) {
        if (strcmp(git_subcmds[i].name, subcmd) == 0) {
            if (needs_confirm)
                *needs_confirm = git_subcmds[i].needs_confirm;
            return 1;
        }
    }
    return 0;
}

/* Split args string into tokens (respects double quotes) */
static int split_args(const char *args, char **out, int max)
{
    int count = 0;
    const char *p = args;

    while (*p && count < max) {
        /* Skip whitespace */
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        if (*p == '"') {
            /* Double-quoted argument */
            p++;
            const char *start = p;
            while (*p && *p != '"') p++;
            size_t len = (size_t)(p - start);
            out[count] = malloc(len + 1);
            if (!out[count]) return count;
            memcpy(out[count], start, len);
            out[count][len] = '\0';
            count++;
            if (*p == '"') p++;
        } else if (*p == '\'') {
            /* Single-quoted argument */
            p++;
            const char *start = p;
            while (*p && *p != '\'') p++;
            size_t len = (size_t)(p - start);
            out[count] = malloc(len + 1);
            if (!out[count]) return count;
            memcpy(out[count], start, len);
            out[count][len] = '\0';
            count++;
            if (*p == '\'') p++;
        } else {
            /* Unquoted argument */
            const char *start = p;
            while (*p && *p != ' ' && *p != '\t') p++;
            size_t len = (size_t)(p - start);
            out[count] = malloc(len + 1);
            if (!out[count]) return count;
            memcpy(out[count], start, len);
            out[count][len] = '\0';
            count++;
        }
    }
    return count;
}

static cJSON *git_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");

    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *subcmd = cJSON_AddObjectToObject(props, "subcommand");
    cJSON_AddStringToObject(subcmd, "type", "string");
    cJSON_AddStringToObject(subcmd, "description",
        "Git subcommand (status, log, diff, show, blame, branch, tag, "
        "remote, rev-parse, ls-files, add, commit, checkout, stash, "
        "fetch, pull, merge, rebase, reset, clean, restore, switch)");

    cJSON *args = cJSON_AddObjectToObject(props, "args");
    cJSON_AddStringToObject(args, "type", "string");
    cJSON_AddStringToObject(args, "description",
        "Additional arguments for the git subcommand");

    cJSON *repo = cJSON_AddObjectToObject(props, "repo_path");
    cJSON_AddStringToObject(repo, "type", "string");
    cJSON_AddStringToObject(repo, "description",
        "Path to the git repository (defaults to working directory)");

    cJSON *required = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(required, cJSON_CreateString("subcommand"));

    return schema;
}

/* Build git argv from subcommand + args string. Check for dangerous flags.
 * Returns argc on success, -1 if dangerous flag detected.
 * Caller must free extra_args[0..extra_count-1]. */
static int git_build_argv(const char *dir, const char *subcmd,
                           const char *args_str,
                           char **argv_out,
                           char **extra_args, int *extra_count)
{
    int argc = 0;
    *extra_count = 0;

    argv_out[argc++] = "git";
    argv_out[argc++] = "-C";
    argv_out[argc++] = (char *)dir;
    argv_out[argc++] = (char *)subcmd;

    if (args_str && args_str[0]) {
        *extra_count = split_args(args_str, extra_args, GIT_MAX_ARGS - 4);
        for (int i = 0; i < *extra_count && argc < GIT_MAX_ARGS - 1; i++)
            argv_out[argc++] = extra_args[i];
    }
    argv_out[argc] = NULL;

    /* Block dangerous flag patterns in args.
     * -c/--config can execute arbitrary commands via core.pager, core.editor,
     * core.sshCommand, credential.helper, etc.
     * --git-dir/--work-tree escape workspace restrictions.
     * --exec/--upload-pack/--receive-pack execute arbitrary commands.
     * --hard/--force/-f can cause data loss (reset --hard, clean -f, etc.). */
    for (int i = 4; i < argc; i++) {
        const char *a = argv_out[i];
        if (strncmp(a, "--exec", 6) == 0 ||
            strncmp(a, "--upload-pack", 13) == 0 ||
            strncmp(a, "--receive-pack", 14) == 0 ||
            strncmp(a, "--config", 8) == 0 ||
            strncmp(a, "--git-dir", 9) == 0 ||
            strncmp(a, "--work-tree", 11) == 0 ||
            strncmp(a, "--replace-object", 16) == 0 ||
            strncmp(a, "--hard", 6) == 0 ||
            strncmp(a, "--force", 7) == 0 ||
            (a[0] == '-' && a[1] == 'c' && (a[2] == '\0' || a[2] == ' ')) ||
            (a[0] == '-' && a[1] == 'f' && (a[2] == '\0')) ||
            (a[0] == '-' && a[1] == 'p' && (a[2] == '\0' || a[2] == ' ')))
            return -1;
    }
    return argc;
}

/* Fork, exec git with argv, capture output with timeout and size cap.
 * Returns malloc'd output string (caller owns), NULL on pipe/fork failure.
 * Sets *status_out (wait status) and *timed_out flag. */
static char *git_run_subprocess(char **argv, int *status_out, int *timed_out)
{
    *status_out = 0;
    *timed_out = 0;

    int pipefd[2];
    if (pipe(pipefd) != 0)
        return NULL;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }

    if (pid == 0) {
        /* Child */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        int max_fd = (int)sysconf(_SC_OPEN_MAX);
        if (max_fd < 0) max_fd = 1024;
        for (int fd = 3; fd < max_fd; fd++)
            close(fd);

        execvp("git", argv);
        _exit(127);
    }

    /* Parent */
    close(pipefd[1]);

    sc_strbuf_t output;
    sc_strbuf_init(&output);
    char buf[4096];
    int truncated = 0;
    time_t start = time(NULL);

    while (1) {
        if (time(NULL) - start > GIT_TIMEOUT_SECS) {
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            sc_strbuf_append(&output, "\n[git command timed out]");
            *timed_out = 1;
            break;
        }

        ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = '\0';

        if (output.len + (size_t)n > GIT_MAX_OUTPUT) {
            size_t remaining = GIT_MAX_OUTPUT - output.len;
            if (remaining > 0) {
                buf[remaining] = '\0';
                sc_strbuf_append(&output, buf);
            }
            truncated = 1;
            break;
        }
        sc_strbuf_append(&output, buf);
    }
    close(pipefd[0]);

    waitpid(pid, status_out, 0);

    if (truncated)
        sc_strbuf_append(&output, "\n[output truncated at 64KB]");

    return sc_strbuf_finish(&output);
}

static sc_tool_result_t *git_execute(sc_tool_t *self, cJSON *args_json,
                                      void *ctx)
{
    (void)ctx;
    git_data_t *gd = self->data;

    const char *subcmd = sc_json_get_string(args_json, "subcommand", NULL);
    if (!subcmd || !subcmd[0])
        return sc_tool_result_error("Missing required parameter: subcommand");

    /* Validate subcommand */
    int cmd_needs_confirm = 0;
    if (!is_allowed_subcmd(subcmd, &cmd_needs_confirm))
        return sc_tool_result_error(
            "Subcommand not allowed. Allowed: status, log, diff, show, "
            "blame, branch, tag, remote, rev-parse, ls-files, add, commit, "
            "checkout, stash, fetch, pull, merge, rebase, reset, clean, "
            "restore, switch");

    /* Validate repo_path if provided */
    const char *repo_path = sc_json_get_string(args_json, "repo_path", NULL);
    char *resolved_repo = NULL;
    if (repo_path && repo_path[0]) {
        if (gd->restrict_to_workspace) {
            char *validated = sc_validate_path(repo_path, gd->working_dir, 1);
            if (!validated)
                return sc_tool_result_error(
                    "repo_path is outside the workspace");
            resolved_repo = validated;
        } else {
            resolved_repo = realpath(repo_path, NULL);
            if (!resolved_repo)
                return sc_tool_result_error("repo_path does not exist");
        }
    }

    const char *use_dir = resolved_repo ? resolved_repo : gd->working_dir;

    /* Build argv */
    char *argv_storage[GIT_MAX_ARGS];
    char *extra_args[GIT_MAX_ARGS - 4];
    int extra_count = 0;
    const char *args_str = sc_json_get_string(args_json, "args", NULL);

    int argc = git_build_argv(use_dir, subcmd, args_str,
                               argv_storage, extra_args, &extra_count);
    if (argc < 0) {
        for (int j = 0; j < extra_count; j++) free(extra_args[j]);
        free(resolved_repo);
        return sc_tool_result_error("Dangerous git flag blocked");
    }

    /* Fork + exec */
    int status = 0;
    int timed_out = 0;
    char *result_str = git_run_subprocess(argv_storage, &status, &timed_out);

    for (int j = 0; j < extra_count; j++) free(extra_args[j]);
    free(resolved_repo);

    if (!result_str)
        return sc_tool_result_error("pipe() or fork() failed");

    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        sc_strbuf_t err;
        sc_strbuf_init(&err);
        sc_strbuf_appendf(&err, "git %s exited with code %d:\n%s",
                          subcmd, WEXITSTATUS(status),
                          result_str[0] ? result_str : "");
        char *err_str = sc_strbuf_finish(&err);
        free(result_str);
        sc_tool_result_t *r = sc_tool_result_error(err_str);
        free(err_str);
        return r;
    }

    sc_tool_result_t *r = sc_tool_result_new(
        result_str[0] ? result_str : "Command completed with no output");
    free(result_str);
    return r;
}

static void git_destroy(sc_tool_t *self)
{
    if (!self) return;
    git_data_t *gd = self->data;
    if (gd) {
        free(gd->working_dir);
        free(gd);
    }
    free(self);
}

sc_tool_t *sc_tool_git_new(const char *working_dir, int restrict_to_workspace)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    git_data_t *gd = calloc(1, sizeof(*gd));
    if (!gd) { free(t); return NULL; }

    gd->working_dir = sc_strdup(working_dir ? working_dir : ".");
    gd->restrict_to_workspace = restrict_to_workspace;

    t->name = "git";
    t->description = "Execute git commands safely. Supports: status, log, diff, "
                     "show, blame, branch, tag, remote, rev-parse, ls-files, add, "
                     "commit, checkout, stash, fetch, pull, merge, rebase, reset, "
                     "clean, restore, switch. Uses fork+exec (no shell).";
    t->parameters = git_parameters;
    t->execute = git_execute;
    t->set_context = NULL;
    t->destroy = git_destroy;
    t->needs_confirm = 1; /* Individual subcommands checked at runtime */
    t->data = gd;

    return t;
}
