/*
 * tools/repo_search.c — repo_search tool (task 4.5)
 *
 * Exposes the project-memory code index to the agent: build/refresh the index,
 * check status, and run ranked searches over indexed source files.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/repo_search.h"
#include "tools/types.h"
#include "project_memory.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "cJSON.h"

#define REPO_SEARCH_MAX_HITS 50

typedef struct {
    char *workspace;
} repo_search_data_t;

static cJSON *repo_search_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "action",
        "\"search\" (default): ranked search over indexed source files. "
        "\"build\": (re)build the full index. \"refresh\": incremental update. "
        "\"status\": index summary.", 0);
    sc_schema_add_string(schema, "query",
        "Search query (required for action=search). Terms are matched against "
        "file paths, identifiers, symbols, and imports.", 0);
    sc_schema_add_string(schema, "max_results",
        "Maximum hits to return (default 10, max 50).", 0);
    return schema;
}

static sc_tool_result_t *repo_search_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    repo_search_data_t *d = self->data;
    if (!d || !d->workspace)
        return sc_tool_result_error("repo_search not initialized");

    const char *action = sc_json_get_string(args, "action", "search");

    if (strcmp(action, "build") == 0 || strcmp(action, "refresh") == 0) {
        int incremental = (strcmp(action, "refresh") == 0);
        int n = sc_pm_build(d->workspace, incremental);
        if (n < 0) return sc_tool_result_error("Failed to build project index");
        char msg[128];
        snprintf(msg, sizeof(msg), "Indexed %d source file%s.", n, n == 1 ? "" : "s");
        return sc_tool_result_new(msg);
    }

    if (strcmp(action, "status") == 0) {
        char *s = sc_pm_status(d->workspace);
        sc_tool_result_t *r = sc_tool_result_new(s ? s : "unknown");
        free(s);
        return r;
    }

    /* default: search */
    const char *query = sc_json_get_string(args, "query", NULL);
    if (!query || !query[0])
        return sc_tool_result_error("query is required for action=search");

    int max_results = sc_json_get_int(args, "max_results", 10);
    if (max_results < 1) max_results = 1;
    if (max_results > REPO_SEARCH_MAX_HITS) max_results = REPO_SEARCH_MAX_HITS;

    int count = 0;
    sc_pm_hit_t *hits = sc_pm_search(d->workspace, query, max_results, &count);
    if (!hits || count == 0) {
        sc_pm_hits_free(hits, count);
        return sc_tool_result_new(
            "No matches. If the index is stale or missing, run action=build first.");
    }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%d match%s:\n", count, count == 1 ? "" : "es");
    for (int i = 0; i < count; i++)
        sc_strbuf_appendf(&sb, "  [%s] %s  (score %d)\n",
                          hits[i].language ? hits[i].language : "",
                          hits[i].path, hits[i].score);
    sc_pm_hits_free(hits, count);

    char *out = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(out);
    free(out);
    return r;
}

static void repo_search_destroy(sc_tool_t *self)
{
    if (!self) return;
    repo_search_data_t *d = self->data;
    if (d) { free(d->workspace); free(d); }
    free(self);
}

sc_tool_t *sc_tool_repo_search_new(const char *workspace)
{
    if (!workspace) return NULL;
    repo_search_data_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->workspace = sc_strdup(workspace);
    if (!d->workspace) { free(d); return NULL; }

    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) { free(d->workspace); free(d); return NULL; }

    t->name = "repo_search";
    t->description =
        "Search the current project's source code by keyword (action=search, "
        "query=...). Matches file paths, identifiers, symbols, and imports from "
        "a local index. Use action=build to (re)index, action=refresh for an "
        "incremental update, or action=status. Helpful for locating where "
        "something is defined or used across the codebase.";
    t->parameters = repo_search_parameters;
    t->execute = repo_search_execute;
    t->destroy = repo_search_destroy;
    t->needs_confirm = 0;
    t->data = d;
    return t;
}
