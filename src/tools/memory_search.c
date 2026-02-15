/*
 * tools/memory_search.c — Full-text search across memory files
 *
 * Backed by SQLite FTS5 index. Complements memory_read (file-based,
 * chronological) with ranked keyword search.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "tools/memory_search.h"
#include "tools/types.h"
#include "memory_index.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "cJSON.h"

typedef struct {
    sc_memory_index_t *idx;  /* Borrowed, not owned */
} search_data_t;

static cJSON *search_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");

    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *query = cJSON_AddObjectToObject(props, "query");
    cJSON_AddStringToObject(query, "type", "string");
    cJSON_AddStringToObject(query, "description",
        "Search query. Supports terms, \"exact phrases\", and term* prefix matching.");

    cJSON *max_r = cJSON_AddObjectToObject(props, "max_results");
    cJSON_AddStringToObject(max_r, "type", "integer");
    cJSON_AddStringToObject(max_r, "description",
        "Maximum number of results to return (default 10, max 50).");

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("query"));
    return schema;
}

static sc_tool_result_t *search_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    search_data_t *d = self->data;
    if (!d || !d->idx)
        return sc_tool_result_error("memory search index not available");

    const char *query = sc_json_get_string(args, "query", NULL);
    if (!query || query[0] == '\0')
        return sc_tool_result_error("query is required");

    int max_results = sc_json_get_int(args, "max_results", 10);

    int count = 0;
    sc_memory_search_result_t *results = sc_memory_index_search(
        d->idx, query, max_results, &count);

    if (!results || count == 0) {
        sc_memory_search_results_free(results, count);
        return sc_tool_result_new("No results found.");
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

static void search_destroy(sc_tool_t *self)
{
    if (!self) return;
    free(self->data);  /* idx is borrowed, don't free it */
    free(self);
}

sc_tool_t *sc_tool_memory_search_new(sc_memory_index_t *idx)
{
    if (!idx) return NULL;

    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    search_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(t); return NULL; }
    d->idx = idx;

    t->name = "memory_search";
    t->description = "Search the agent's memory (long-term memory and daily notes) "
                     "by keyword. Use when you need to find specific information "
                     "that may not be in the recent context window.";
    t->parameters = search_parameters;
    t->execute = search_execute;
    t->destroy = search_destroy;
    t->needs_confirm = 0;
    t->data = d;
    return t;
}
