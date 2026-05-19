/*
 * tools/symbol_lookup.c — Thin convenience wrapper for C symbol lookup
 *
 * High-usability Drill-down primitive.
 * Provides "symbol_lookup" tool name with simplified parameters and
 * friendly defaults. Internally creates a temporary code_graph tool
 * instance and forces action="symbols" + max_results=30 etc.
 *
 * This completely reuses the existing code_graph implementation
 * (extract_c_symbols, scan, regex patterns, output formatting, error
 * paths, workspace restriction) without any code duplication or
 * modification to code_graph.c/.h.
 *
 * The wrapper is intentionally minimal ("thin").
 */

#include <stdlib.h>
#include <string.h>

#include "tools/symbol_lookup.h"
#include "tools/code_graph.h"
#include "tools/types.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "cJSON.h"

typedef struct {
    char *workspace;  /* current workspace root; updated via set_workspace */
} symbol_lookup_data_t;

static void symbol_lookup_destroy(sc_tool_t *self)
{
    if (!self) return;
    symbol_lookup_data_t *d = self->data;
    if (d) {
        free(d->workspace);
        free(d);
    }
    free(self);
}

static void symbol_lookup_set_workspace(sc_tool_t *self, const char *workspace)
{
    symbol_lookup_data_t *d = self->data;
    if (!d || !workspace) return;
    free(d->workspace);
    d->workspace = sc_strdup(workspace);
}

static cJSON *symbol_lookup_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");

    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *name = cJSON_AddObjectToObject(props, "name");
    cJSON_AddStringToObject(name, "type", "string");
    cJSON_AddStringToObject(name, "description",
        "Symbol name or case-insensitive substring to search for (e.g. 'ret' matches "
        "set_retention, MAX_RETENTION, retention_info). Primary argument for Drill-down.");

    cJSON *path = cJSON_AddObjectToObject(props, "path");
    cJSON_AddStringToObject(path, "type", "string");
    cJSON_AddStringToObject(path, "description",
        "Directory or single file to restrict the scan to (relative to workspace). "
        "Default: '.' (current workspace root).");

    cJSON *max_results = cJSON_AddObjectToObject(props, "max_results");
    cJSON_AddStringToObject(max_results, "type", "integer");
    cJSON_AddStringToObject(max_results, "description",
        "Maximum results to return (bounded for LLM context). Default: 30 "
        "(chosen as researcher-friendly default for Drill-down).");

    return schema;
}

static sc_tool_result_t *symbol_lookup_execute(sc_tool_t *self, cJSON *args,
                                               void *ctx)
{
    (void)ctx;
    symbol_lookup_data_t *d = self->data;
    if (!d || !d->workspace)
        return sc_tool_result_error("symbol_lookup tool not initialized");

    /* Flexible param names: 'name' is preferred, fall back to 'query' for compatibility */
    const char *name = sc_json_get_string(args, "name",
                          sc_json_get_string(args, "query", NULL));
    const char *path = sc_json_get_string(args, "path", ".");

    int max_results = sc_json_get_int(args, "max_results", 30);
    if (max_results <= 0) max_results = 30;
    if (max_results > 256) max_results = 256; /* safety cap matching code_graph */

    /* Thin delegation: create a fresh code_graph instance (reuses all its state,
     * compiled patterns, scanner, and the exact symbols action + formatting).
     * The temp instance is destroyed after the call; this is acceptable for
     * the low-frequency researcher Drill-down use case.
     */
    sc_tool_t *cg = sc_tool_code_graph_new(d->workspace);
    if (!cg)
        return sc_tool_result_error("failed to initialize internal code_graph for lookup");

    cJSON *sym_args = cJSON_CreateObject();
    cJSON_AddStringToObject(sym_args, "action", "symbols");
    if (name && *name)
        cJSON_AddStringToObject(sym_args, "name_filter", name);
    if (path && *path)
        cJSON_AddStringToObject(sym_args, "path", path);
    cJSON_AddNumberToObject(sym_args, "max_results", (double)max_results);
    const char *kinds = sc_json_get_string(args, "kinds", NULL);
    if (kinds && *kinds)
        cJSON_AddStringToObject(sym_args, "kinds", kinds);
    /* kinds now forwarded to core post-filter (see action_symbols) */

    sc_tool_result_t *res = cg->execute(cg, sym_args, NULL);

    cJSON_Delete(sym_args);
    cg->destroy(cg);

    if (!res)
        return sc_tool_result_error("symbol lookup execution failed internally");

    /* Return the result as-is — the output text ("func: name at path:line ...")
     * is already the exact researcher-friendly format produced by code_graph.
     */
    return res;
}

sc_tool_t *sc_tool_symbol_lookup_new(const char *workspace)
{
    if (!workspace) return NULL;

    symbol_lookup_data_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->workspace = sc_strdup(workspace);

    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) {
        free(d->workspace);
        free(d);
        return NULL;
    }

    t->name = "symbol_lookup";
    t->description = "Thin convenience wrapper for C/C++ symbol lookup (Drill-down stage). "
                     "Internally delegates to code_graph with action=\"symbols\" and "
                     "researcher-friendly defaults (max_results=30). "
                     "Use 'name' for case-insensitive filter. Returns the same high-quality "
                     "path:line + context output ready for scratchpad and reasoning. "
                     "Enabled by the same SC_ENABLE_CODE_GRAPH flag. No build step required.";
    t->parameters = symbol_lookup_parameters;
    t->execute = symbol_lookup_execute;
    t->set_workspace = symbol_lookup_set_workspace;
    t->destroy = symbol_lookup_destroy;
    t->needs_confirm = 0;
    t->data = d;
    return t;
}