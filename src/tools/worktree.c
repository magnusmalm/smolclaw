/*
 * tools/worktree.c - Git worktree isolation
 *
 * worktree_enter: creates a git worktree for isolated work
 * worktree_exit: keeps or removes the worktree
 *
 * Git invocations use fork+execvp (no shell), aligned with git.c.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>

#include "tools/worktree.h"
#include "tools/types.h"
#include "agent.h"
#include "util/str.h"
#include "logger.h"
#include "cJSON.h"

#define LOG_TAG "worktree"
#define WORKTREE_DIR ".claude/worktrees"
#define WT_GIT_TIMEOUT_SECS 30
#define WT_GIT_MAX_OUTPUT (64 * 1024)

typedef struct {
    sc_agent_t *agent;
    char *original_cwd;
    char *worktree_path;
    char *worktree_branch;
    int   active;
} worktree_data_t;

static worktree_data_t s_wt;

static int valid_slug(const char *s)
{
    if (!s || !s[0] || strlen(s) > 64) return 0;
    if (strstr(s, "..")) return 0;
    for (const char *p = s; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' && *p != '.')
            return 0;
    }
    return 1;
}

static int mkdir_p(const char *path, mode_t mode)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, mode) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir(buf, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int wt_git_succeeded(int status, int timed_out)
{
    return !timed_out && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int wt_argv_has_worktree(char *const argv[])
{
    for (int i = 0; argv[i]; i++) {
        if (strcmp(argv[i], "worktree") == 0)
            return 1;
    }
    return 0;
}

/* Run git with argv (NULL-terminated). Use "git -C <repo> ..." for repo scope.
 * Most commands close inherited fds 3+ (same as git.c) so execvp succeeds when
 * the parent has many open fds. git-worktree helper dispatch fails with exit 127
 * if fds are stripped — skip close for worktree subcommands (audit 4298ba13). */
static char *wt_git_run(char *const argv[], int *status_out, int *timed_out)
{
    int close_extra_fds = !wt_argv_has_worktree(argv);

    *status_out = 0;
    *timed_out = 0;

    int pipefd[2];
    if (pipe(pipefd) != 0) return NULL;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        if (close_extra_fds) {
            int max_fd = (int)sysconf(_SC_OPEN_MAX);
            if (max_fd < 0) max_fd = 1024;
            for (int fd = 3; fd < max_fd; fd++)
                close(fd);
        }

        execvp("git", argv);
        _exit(127);
    }

    close(pipefd[1]);

    sc_strbuf_t output;
    sc_strbuf_init(&output);
    char buf[4096];
    time_t start = time(NULL);
    int status = 0;

    while (1) {
        if (time(NULL) - start > WT_GIT_TIMEOUT_SECS) {
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            *timed_out = 1;
            sc_strbuf_append(&output, "\n[git command timed out]");
            break;
        }

        ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = '\0';

        if (output.len + (size_t)n > WT_GIT_MAX_OUTPUT) {
            size_t remaining = WT_GIT_MAX_OUTPUT - output.len;
            if (remaining > 0) {
                buf[remaining] = '\0';
                sc_strbuf_append(&output, buf);
            }
            break;
        }
        sc_strbuf_append(&output, buf);
    }
    close(pipefd[0]);

    waitpid(pid, &status, 0);
    *status_out = status;

    char *out = sc_strbuf_finish(&output);
    if (!wt_git_succeeded(status, *timed_out)) {
        int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        SC_LOG_WARN(LOG_TAG, "git failed (exit=%d): %s", code,
                    out && out[0] ? out : "(no output)");
    }
    return out;
}

static char *wt_git_rev_parse_root(const char *cwd)
{
    char *argv[] = {"git", "-C", (char *)cwd, "rev-parse", "--show-toplevel",
                    NULL};
    int status = 0, timed_out = 0;
    char *out = wt_git_run(argv, &status, &timed_out);
    if (!wt_git_succeeded(status, timed_out)) {
        free(out);
        return NULL;
    }
    return out;
}

static char *wt_git_status_porcelain(const char *cwd)
{
    char *argv[] = {"git", "-C", (char *)cwd, "status", "--porcelain", NULL};
    int status = 0, timed_out = 0;
    char *out = wt_git_run(argv, &status, &timed_out);
    if (!wt_git_succeeded(status, timed_out)) {
        free(out);
        return NULL;
    }
    return out;
}

static char *wt_git_worktree_add(const char *root, const char *branch,
                                 const char *path, int *status_out,
                                 int *timed_out)
{
    char *argv[] = {"git", "-C", (char *)root, "worktree", "add", "-B",
                    (char *)branch, (char *)path, NULL};
    return wt_git_run(argv, status_out, timed_out);
}

static char *wt_git_worktree_remove(const char *cwd, const char *path)
{
    char *argv[] = {"git", "-C", (char *)cwd, "worktree", "remove", "--force",
                    (char *)path, NULL};
    int status = 0, timed_out = 0;
    char *out = wt_git_run(argv, &status, &timed_out);
    free(out);
    return NULL;
}

static char *wt_git_branch_delete(const char *cwd, const char *branch)
{
    char *argv[] = {"git", "-C", (char *)cwd, "branch", "-D", (char *)branch,
                    NULL};
    int status = 0, timed_out = 0;
    char *out = wt_git_run(argv, &status, &timed_out);
    free(out);
    return NULL;
}

static int worktree_has_changes(const char *path)
{
    char *status = wt_git_status_porcelain(path);
    int dirty = (status && status[0] != '\0');
    free(status);
    return dirty;
}

static void enter_destroy(sc_tool_t *self)
{
    if (!self) return;
    free(self);
}

static cJSON *enter_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");
    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *name = cJSON_AddObjectToObject(props, "name");
    cJSON_AddStringToObject(name, "type", "string");
    cJSON_AddStringToObject(name, "description",
        "Short name for the worktree (alphanumeric, dash, underscore, dot). "
        "Used as branch name suffix.");

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("name"));
    return schema;
}

static sc_tool_result_t *enter_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)self; (void)ctx;

    if (s_wt.active)
        return sc_tool_result_error("Already in a worktree. Exit first.");

    const char *name = NULL;
    cJSON *n = cJSON_GetObjectItem(args, "name");
    if (n && cJSON_IsString(n)) name = n->valuestring;
    if (!name || !valid_slug(name))
        return sc_tool_result_error("Invalid name. Use alphanumeric, dash, underscore, dot. Max 64 chars.");

    char *root = wt_git_rev_parse_root(s_wt.agent->workspace);
    if (!root || root[0] == '\0') {
        free(root);
        return sc_tool_result_error("Not in a git repository.");
    }
    size_t rlen = strlen(root);
    while (rlen > 0 && (root[rlen-1] == '\n' || root[rlen-1] == '\r'))
        root[--rlen] = '\0';

    char wt_path[1024];
    snprintf(wt_path, sizeof(wt_path), "%s/%s/%s", root, WORKTREE_DIR, name);

    char wt_rel[256];
    snprintf(wt_rel, sizeof(wt_rel), "%s/%s", WORKTREE_DIR, name);

    char branch[128];
    snprintf(branch, sizeof(branch), "worktree-%s", name);

    char wt_parent[1024];
    snprintf(wt_parent, sizeof(wt_parent), "%s/%s", root, WORKTREE_DIR);
    if (mkdir_p(wt_parent, 0755) != 0) {
        free(root);
        return sc_tool_result_error("Failed to create worktree parent directory");
    }

    int wt_status = 0, wt_timed_out = 0;
    char *out = wt_git_worktree_add(root, branch, wt_rel, &wt_status,
                                    &wt_timed_out);

    struct stat st;
    if (!wt_git_succeeded(wt_status, wt_timed_out) ||
        stat(wt_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        sc_strbuf_t err;
        sc_strbuf_init(&err);
        sc_strbuf_appendf(&err, "Failed to create worktree: %s",
                          out ? out : "unknown error");
        free(out);
        free(root);
        char *msg = sc_strbuf_finish(&err);
        sc_tool_result_t *r = sc_tool_result_error(msg);
        free(msg);
        return r;
    }
    free(out);

    s_wt.original_cwd = sc_strdup(s_wt.agent->workspace);
    s_wt.worktree_path = sc_strdup(wt_path);
    s_wt.worktree_branch = sc_strdup(branch);
    s_wt.active = 1;

    free(s_wt.agent->workspace);
    s_wt.agent->workspace = sc_strdup(wt_path);
    sc_tool_registry_set_workspace(s_wt.agent->tools, wt_path);

    SC_LOG_INFO(LOG_TAG, "Entered worktree: %s (branch: %s)", wt_path, branch);
    free(root);

    sc_strbuf_t result;
    sc_strbuf_init(&result);
    sc_strbuf_appendf(&result,
        "Entered worktree '%s' on branch '%s'.\n"
        "Working directory: %s\n"
        "All file operations now target this isolated copy.\n"
        "Use worktree_exit to return (action: 'keep' or 'remove').",
        name, branch, wt_path);
    char *msg = sc_strbuf_finish(&result);
    sc_tool_result_t *r = sc_tool_result_new(msg);
    free(msg);
    return r;
}

static void exit_destroy(sc_tool_t *self)
{
    if (!self) return;
    free(self);
}

static cJSON *exit_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");
    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *action = cJSON_AddObjectToObject(props, "action");
    cJSON_AddStringToObject(action, "type", "string");
    cJSON_AddStringToObject(action, "description",
        "'keep' to leave worktree on disk, 'remove' to clean up.");
    cJSON *action_enum = cJSON_AddArrayToObject(action, "enum");
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("keep"));
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("remove"));

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("action"));
    return schema;
}

static sc_tool_result_t *exit_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)self; (void)ctx;

    if (!s_wt.active)
        return sc_tool_result_error("Not in a worktree.");

    const char *action = NULL;
    cJSON *a = cJSON_GetObjectItem(args, "action");
    if (a && cJSON_IsString(a)) action = a->valuestring;
    if (!action || (strcmp(action, "keep") != 0 && strcmp(action, "remove") != 0))
        return sc_tool_result_error("action must be 'keep' or 'remove'.");

    int has_changes = worktree_has_changes(s_wt.worktree_path);

    free(s_wt.agent->workspace);
    s_wt.agent->workspace = sc_strdup(s_wt.original_cwd);
    sc_tool_registry_set_workspace(s_wt.agent->tools, s_wt.original_cwd);

    sc_strbuf_t result;
    sc_strbuf_init(&result);

    if (strcmp(action, "remove") == 0) {
        if (has_changes) {
            sc_strbuf_appendf(&result,
                "WARNING: Worktree has uncommitted changes. "
                "Refusing to remove. Use 'keep' instead, or commit/discard changes first.\n"
                "Worktree left at: %s (branch: %s)",
                s_wt.worktree_path, s_wt.worktree_branch);
        } else {
            wt_git_worktree_remove(s_wt.original_cwd, s_wt.worktree_path);
            wt_git_branch_delete(s_wt.original_cwd, s_wt.worktree_branch);

            sc_strbuf_appendf(&result,
                "Worktree removed and branch '%s' deleted.",
                s_wt.worktree_branch);
            SC_LOG_INFO(LOG_TAG, "Removed worktree: %s", s_wt.worktree_path);
        }
    } else {
        sc_strbuf_appendf(&result,
            "Worktree kept at: %s (branch: %s)%s",
            s_wt.worktree_path, s_wt.worktree_branch,
            has_changes ? "\nNote: worktree has uncommitted changes." : "");
        SC_LOG_INFO(LOG_TAG, "Kept worktree: %s", s_wt.worktree_path);
    }

    free(s_wt.original_cwd);
    free(s_wt.worktree_path);
    free(s_wt.worktree_branch);
    memset(&s_wt, 0, sizeof(s_wt));

    char *msg = sc_strbuf_finish(&result);
    sc_tool_result_t *r = sc_tool_result_new(msg);
    free(msg);
    return r;
}

void sc_worktree_reset_state(void)
{
    free(s_wt.original_cwd);
    free(s_wt.worktree_path);
    free(s_wt.worktree_branch);
    memset(&s_wt, 0, sizeof(s_wt));
}

sc_tool_t *sc_tool_worktree_enter_new(sc_agent_t *agent)
{
    s_wt.agent = agent;

    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->name = "worktree_enter";
    t->description =
        "Create an isolated git worktree for safe parallel development. "
        "All file operations switch to the worktree directory. "
        "Use for risky changes that might need to be discarded.";
    t->parameters = enter_parameters;
    t->execute = enter_execute;
    t->destroy = enter_destroy;
    return t;
}

sc_tool_t *sc_tool_worktree_exit_new(sc_agent_t *agent)
{
    s_wt.agent = agent;

    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->name = "worktree_exit";
    t->description =
        "Exit the current git worktree. Use action 'keep' to leave the "
        "worktree on disk (for later merging), or 'remove' to clean up "
        "(only if no uncommitted changes).";
    t->parameters = exit_parameters;
    t->execute = exit_execute;
    t->destroy = exit_destroy;
    return t;
}