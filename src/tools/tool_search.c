/*
 * tools/tool_search.c - Deferred tool schema fetching
 *
 * When the agent has many MCP tools, their schemas are deferred (not
 * sent on every API call). The LLM calls tool_search to fetch full
 * schemas on demand. Discovered tools are then included in subsequent
 * API calls.
 *
 * Two query modes:
 *   "select:name1,name2" — exact match by name
 *   "keyword terms"      — scored search across name + description
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

/* Portable case-insensitive substring search (ci_strstr is GNU extension) */
static const char *ci_strstr(const char *haystack, const char *needle)
{
    if (!haystack || !needle) return NULL;
    size_t nlen = strlen(needle);
    if (nlen == 0) return haystack;
    for (; *haystack; haystack++) {
        if (strncasecmp(haystack, needle, nlen) == 0)
            return haystack;
    }
    return NULL;
}

#include "tools/tool_search.h"
#include "tools/types.h"
#include "tools/registry.h"
#include "util/str.h"
#include "logger.h"
#include "cJSON.h"

#define LOG_TAG "tool_search"
#define MAX_RESULTS 5

typedef struct {
    sc_tool_registry_t *registry;
} search_data_t;

static void search_destroy(sc_tool_t *self)
{
    if (!self) return;
    free(self->data);
    free(self);
}

static cJSON *search_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");

    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *query = cJSON_AddObjectToObject(props, "query");
    cJSON_AddStringToObject(query, "type", "string");
    cJSON_AddStringToObject(query, "description",
        "Search query. Use 'select:tool_name' for exact match "
        "(comma-separated for multiple), or keywords to search by "
        "name and description.");

    cJSON *max_res = cJSON_AddObjectToObject(props, "max_results");
    cJSON_AddStringToObject(max_res, "type", "integer");
    cJSON_AddStringToObject(max_res, "description",
        "Maximum number of results (default 5).");

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("query"));
    return schema;
}

/* Build a JSON object with the full tool schema for the result */
static cJSON *tool_schema_json(sc_tool_t *t)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "name", t->name);
    if (t->description)
        cJSON_AddStringToObject(obj, "description", t->description);
    if (t->parameters) {
        cJSON *params = t->parameters(t);
        if (params)
            cJSON_AddItemToObject(obj, "parameters", params);
    }
    return obj;
}

/* Score how well a query term matches a tool name + description */
static int score_tool(const char *term, const sc_tool_t *t)
{
    int score = 0;

    /* Name exact match (case-insensitive) */
    if (ci_strstr(t->name, term)) {
        /* Check if it's a full segment match (between __ or _) */
        const char *p = ci_strstr(t->name, term);
        int at_boundary = (p == t->name || *(p - 1) == '_');
        score += at_boundary ? 10 : 5;
    }

    /* Description match */
    if (t->description && ci_strstr(t->description, term))
        score += 2;

    return score;
}

static sc_tool_result_t *search_exact(search_data_t *d, const char *names_csv)
{
    cJSON *results = cJSON_CreateArray();
    int count = 0;

    /* Parse comma-separated names */
    char *copy = sc_strdup(names_csv);
    char *saveptr = NULL;
    char *tok = strtok_r(copy, ",", &saveptr);

    while (tok && count < MAX_RESULTS * 2) {
        /* Trim whitespace */
        while (*tok == ' ') tok++;
        char *end = tok + strlen(tok) - 1;
        while (end > tok && *end == ' ') *end-- = '\0';

        if (!*tok) { tok = strtok_r(NULL, ",", &saveptr); continue; }

        sc_tool_t *t = sc_tool_registry_get(d->registry, tok);
        if (t) {
            cJSON_AddItemToArray(results, tool_schema_json(t));
            sc_tool_registry_mark_discovered(d->registry, tok);
            count++;
            SC_LOG_INFO(LOG_TAG, "Discovered tool: %s", tok);
        }

        tok = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);

    if (count == 0) {
        cJSON_Delete(results);
        return sc_tool_result_error("No matching tools found.");
    }

    char *json = cJSON_Print(results);
    cJSON_Delete(results);
    sc_tool_result_t *r = sc_tool_result_new(json);
    free(json);
    return r;
}

static sc_tool_result_t *search_keywords(search_data_t *d, const char *query,
                                          int max_results)
{
    if (max_results <= 0) max_results = MAX_RESULTS;
    if (max_results > 20) max_results = 20;

    /* Tokenize query */
    char *qcopy = sc_strdup(query);
    char *terms[16];
    int nterms = 0;
    char *saveptr = NULL;
    char *tok = strtok_r(qcopy, " \t", &saveptr);
    while (tok && nterms < 16) {
        terms[nterms++] = tok;
        tok = strtok_r(NULL, " \t", &saveptr);
    }

    if (nterms == 0) {
        free(qcopy);
        return sc_tool_result_error("Empty search query.");
    }

    /* Score all deferred tools */
    typedef struct { sc_tool_t *tool; int score; } scored_t;
    scored_t *scored = calloc((size_t)d->registry->count, sizeof(scored_t));
    int n = 0;

    for (int i = 0; i < d->registry->count; i++) {
        sc_tool_t *t = d->registry->tools[i];
        if (!t->deferred) continue;
        if (!sc_tool_registry_is_allowed(d->registry, t->name)) continue;

        int total = 0;
        for (int j = 0; j < nterms; j++)
            total += score_tool(terms[j], t);

        if (total > 0) {
            scored[n].tool = t;
            scored[n].score = total;
            n++;
        }
    }
    free(qcopy);

    /* Sort by score descending (simple insertion sort, small N) */
    for (int i = 1; i < n; i++) {
        scored_t key = scored[i];
        int j = i - 1;
        while (j >= 0 && scored[j].score < key.score) {
            scored[j + 1] = scored[j];
            j--;
        }
        scored[j + 1] = key;
    }

    /* Build results */
    cJSON *results = cJSON_CreateArray();
    int count = n < max_results ? n : max_results;
    for (int i = 0; i < count; i++) {
        cJSON_AddItemToArray(results, tool_schema_json(scored[i].tool));
        sc_tool_registry_mark_discovered(d->registry, scored[i].tool->name);
        SC_LOG_INFO(LOG_TAG, "Discovered tool: %s (score=%d)",
                    scored[i].tool->name, scored[i].score);
    }
    free(scored);

    if (count == 0) {
        cJSON_Delete(results);
        return sc_tool_result_error("No matching tools found.");
    }

    char *json = cJSON_Print(results);
    cJSON_Delete(results);
    sc_tool_result_t *r = sc_tool_result_new(json);
    free(json);
    return r;
}

static sc_tool_result_t *search_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    search_data_t *d = self->data;

    const char *query = NULL;
    cJSON *q = cJSON_GetObjectItem(args, "query");
    if (q && cJSON_IsString(q)) query = q->valuestring;
    if (!query || !query[0])
        return sc_tool_result_error("'query' is required.");

    int max_results = MAX_RESULTS;
    cJSON *mr = cJSON_GetObjectItem(args, "max_results");
    if (mr && cJSON_IsNumber(mr)) max_results = mr->valueint;

    /* Exact match mode */
    if (strncmp(query, "select:", 7) == 0)
        return search_exact(d, query + 7);

    /* Keyword search mode */
    return search_keywords(d, query, max_results);
}

sc_tool_t *sc_tool_search_new(sc_tool_registry_t *registry)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    search_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(t); return NULL; }
    d->registry = registry;

    t->name = "tool_search";
    t->description =
        "Search for and fetch full schemas of deferred tools. "
        "Use 'select:tool_name' for exact match (comma-separated for multiple), "
        "or keywords to search by name and description. "
        "Fetched tools become available for subsequent calls.";
    t->parameters = search_parameters;
    t->execute = search_execute;
    t->destroy = search_destroy;
    t->data = d;
    return t;
}
