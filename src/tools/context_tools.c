/*
 * tools/context_tools.c — Search context artifacts via FTS5
 *
 * Provides the context_search tool which searches reference documents
 * placed in {workspace}/context/. Documents are indexed into the same
 * FTS5 table as memory but with a "ctx:" source prefix.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "tools/context_tools.h"
#include "tools/types.h"
#include "memory_index.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "cJSON.h"

typedef struct {
    sc_memory_index_t *idx;  /* Borrowed, not owned */
} ctx_search_data_t;

static cJSON *ctx_search_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");

    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *query = cJSON_AddObjectToObject(props, "query");
    cJSON_AddStringToObject(query, "type", "string");
    cJSON_AddStringToObject(query, "description",
        "Search query for context documents. Supports terms, \"exact phrases\", "
        "and term* prefix matching.");

    cJSON *max_r = cJSON_AddObjectToObject(props, "max_results");
    cJSON_AddStringToObject(max_r, "type", "integer");
    cJSON_AddStringToObject(max_r, "description",
        "Maximum number of results to return (default 10, max 50).");

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("query"));
    return schema;
}

static sc_tool_result_t *ctx_search_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    ctx_search_data_t *d = self->data;
    if (!d || !d->idx)
        return sc_tool_result_error("context search index not available");

    const char *query = sc_json_get_string(args, "query", NULL);
    if (!query || query[0] == '\0')
        return sc_tool_result_error("query is required");

    int max_results = sc_json_get_int(args, "max_results", 10);

    int count = 0;
    sc_memory_search_result_t *results = sc_memory_index_search_prefix(
        d->idx, query, "ctx:", max_results, &count);

    if (!results || count == 0) {
        sc_memory_search_results_free(results, count);
        return sc_tool_result_new("No context documents matched.");
    }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Found %d result%s:\n", count, count == 1 ? "" : "s");

    for (int i = 0; i < count; i++) {
        sc_strbuf_appendf(&sb, "\n--- [%s] ---\n%s\n",
                          results[i].source, results[i].snippet);
    }

    sc_memory_search_results_free(results, count);

    char *output = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(output);
    free(output);
    return r;
}

static void ctx_search_destroy(sc_tool_t *self)
{
    if (!self) return;
    free(self->data);
    free(self);
}

sc_tool_t *sc_tool_context_search_new(sc_memory_index_t *idx)
{
    if (!idx) return NULL;

    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    ctx_search_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(t); return NULL; }
    d->idx = idx;

    t->name = "context_search";
    t->description = "Search reference documents in the context/ directory. "
                     "Use for project documentation, API schemas, specs, "
                     "and other reference material.";
    t->parameters = ctx_search_parameters;
    t->execute = ctx_search_execute;
    t->destroy = ctx_search_destroy;
    t->needs_confirm = 0;
    t->data = d;
    return t;
}
