/*
 * tools/worktree.c - Git worktree isolation
 *
 * worktree_enter: creates a git worktree for isolated work
 * worktree_exit: keeps or removes the worktree
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <ctype.h>

#include "tools/worktree.h"
#include "tools/types.h"
#include "agent.h"
#include "util/str.h"
#include "logger.h"
#include "cJSON.h"

#define LOG_TAG "worktree"
#define WORKTREE_DIR ".claude/worktrees"

typedef struct {
    sc_agent_t *agent;
    char *original_cwd;       /* saved before entering worktree */
    char *worktree_path;      /* absolute path to worktree */
    char *worktree_branch;    /* branch name */
    int   active;
} worktree_data_t;

/* Shared state between enter and exit tools */
static worktree_data_t s_wt;

/* Validate slug: alphanumeric, dash, underscore, dot only */
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

/* Run a git command and return output. Caller frees. */
static char *git_exec(const char *cwd, const char *args)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "cd '%s' && git %s 2>&1", cwd, args);
    FILE *f = popen(cmd, "r");
    if (!f) return NULL;
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    char buf[256];
    while (fgets(buf, sizeof(buf), f))
        sc_strbuf_append(&sb, buf);
    int status = pclose(f);
    char *out = sc_strbuf_finish(&sb);
    if (status != 0) {
        SC_LOG_WARN(LOG_TAG, "git %s failed: %s", args, out ? out : "");
    }
    return out;
}

/* Check if worktree has uncommitted changes or new commits */
static int worktree_has_changes(const char *path)
{
    char *status = git_exec(path, "status --porcelain");
    int dirty = (status && status[0] != '\0');
    free(status);
    return dirty;
}

/* --- worktree_enter --- */

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

    /* Find git root */
    char *root = git_exec(s_wt.agent->workspace, "rev-parse --show-toplevel");
    if (!root || root[0] == '\0') {
        free(root);
        return sc_tool_result_error("Not in a git repository.");
    }
    /* Trim trailing newline */
    size_t rlen = strlen(root);
    while (rlen > 0 && (root[rlen-1] == '\n' || root[rlen-1] == '\r'))
        root[--rlen] = '\0';

    /* Build worktree path */
    char wt_path[1024];
    snprintf(wt_path, sizeof(wt_path), "%s/%s/%s", root, WORKTREE_DIR, name);

    /* Build branch name */
    char branch[128];
    snprintf(branch, sizeof(branch), "worktree-%s", name);

    /* Create worktree dir */
    char mkdir_cmd[1024];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p '%s/%s'", root, WORKTREE_DIR);
    system(mkdir_cmd);

    /* Create worktree */
    char add_cmd[512];
    snprintf(add_cmd, sizeof(add_cmd), "worktree add -B '%s' '%s'",
             branch, wt_path);
    char *out = git_exec(root, add_cmd);

    /* Check if worktree was created */
    struct stat st;
    if (stat(wt_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        free(root);
        sc_strbuf_t err;
        sc_strbuf_init(&err);
        sc_strbuf_appendf(&err, "Failed to create worktree: %s", out ? out : "unknown error");
        free(out);
        char *msg = sc_strbuf_finish(&err);
        sc_tool_result_t *r = sc_tool_result_error(msg);
        free(msg);
        return r;
    }
    free(out);

    /* Save state */
    s_wt.original_cwd = sc_strdup(s_wt.agent->workspace);
    s_wt.worktree_path = sc_strdup(wt_path);
    s_wt.worktree_branch = sc_strdup(branch);
    s_wt.active = 1;

    /* Switch agent workspace to worktree */
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

/* --- worktree_exit --- */

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

    /* Restore original workspace */
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
            /* Remove worktree */
            char rm_cmd[512];
            snprintf(rm_cmd, sizeof(rm_cmd), "worktree remove --force '%s'",
                     s_wt.worktree_path);
            char *out = git_exec(s_wt.original_cwd, rm_cmd);
            free(out);

            /* Delete branch */
            char br_cmd[256];
            snprintf(br_cmd, sizeof(br_cmd), "branch -D '%s'",
                     s_wt.worktree_branch);
            out = git_exec(s_wt.original_cwd, br_cmd);
            free(out);

            sc_strbuf_appendf(&result,
                "Worktree removed and branch '%s' deleted.",
                s_wt.worktree_branch);
            SC_LOG_INFO(LOG_TAG, "Removed worktree: %s", s_wt.worktree_path);
        }
    } else {
        /* Keep */
        sc_strbuf_appendf(&result,
            "Worktree kept at: %s (branch: %s)%s",
            s_wt.worktree_path, s_wt.worktree_branch,
            has_changes ? "\nNote: worktree has uncommitted changes." : "");
        SC_LOG_INFO(LOG_TAG, "Kept worktree: %s", s_wt.worktree_path);
    }

    /* Clean up state */
    free(s_wt.original_cwd);
    free(s_wt.worktree_path);
    free(s_wt.worktree_branch);
    memset(&s_wt, 0, sizeof(s_wt));

    char *msg = sc_strbuf_finish(&result);
    sc_tool_result_t *r = sc_tool_result_new(msg);
    free(msg);
    return r;
}

/* --- Public API --- */

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
