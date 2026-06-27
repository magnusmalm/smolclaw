/*
 * tools/session_search.c — Full-text search across stored sessions (task 4.11)
 *
 * Backed by the same SQLite FTS5 index used for memory search, but over the
 * session transcripts under {SMOLCLAW_HOME}/sessions/. Two actions:
 *   - search: ranked keyword search → matching sessions + snippets
 *   - list:   most-recently-modified sessions
 *
 * The index is built lazily on the first search (deferred), so enabling the
 * tool costs nothing until used. Complements memory_search (long-term facts)
 * with conversation recall ("did we discuss X?").
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>

#include "tools/session_search.h"
#include "tools/types.h"
#include "memory_index.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "logger.h"
#include "cJSON.h"

#define SESSION_SEARCH_MAX_RESULTS 50
#define SESSION_LIST_MAX           50

typedef struct {
    char *sessions_dir;
    char *db_path;
    sc_memory_index_t *idx;   /* owned; created on first search */
    int initialized;
    pthread_mutex_t lock;     /* guards lazy init */
} session_search_data_t;

/* Lazily build the FTS5 index over the sessions dir. Returns 1 if usable. */
static int ensure_index(session_search_data_t *d)
{
    pthread_mutex_lock(&d->lock);
    if (!d->initialized) {
        d->idx = sc_memory_index_new(d->db_path);
        if (d->idx) {
            static const char *exts[] = { ".jsonl", ".json" };
            sc_memory_index_rebuild_dir(d->idx, d->sessions_dir, "session:",
                                        exts, 2);
        }
        d->initialized = 1;
    }
    int ok = d->idx != NULL;
    pthread_mutex_unlock(&d->lock);
    return ok;
}

static cJSON *session_search_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "action",
        "\"search\" (default): ranked keyword search across session "
        "transcripts. \"list\": most recently active sessions.", 0);
    sc_schema_add_string(schema, "query",
        "Search query (required for action=search). Supports terms, "
        "\"exact phrases\", and term* prefix matching.", 0);
    sc_schema_add_string(schema, "max_results",
        "Maximum results to return (default 10, max 50).", 0);
    return schema;
}

/* action=list: most-recently-modified session files. */
static sc_tool_result_t *do_list(session_search_data_t *d, int max_results)
{
    DIR *dir = opendir(d->sessions_dir);
    if (!dir)
        return sc_tool_result_new("No sessions found.");

    struct entry { char name[256]; long mtime; } items[SESSION_LIST_MAX];
    int n = 0;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        size_t len = strlen(ent->d_name);
        int is_session = (len > 6 && strcmp(ent->d_name + len - 6, ".jsonl") == 0) ||
                         (len > 5 && strcmp(ent->d_name + len - 5, ".json") == 0);
        if (!is_session) continue;

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", d->sessions_dir, ent->d_name);
        struct stat st;
        if (stat(path, &st) != 0) continue;

        /* Keep the `max` most recent: insert into a small sorted set. */
        if (n < SESSION_LIST_MAX) {
            snprintf(items[n].name, sizeof(items[n].name), "%s", ent->d_name);
            items[n].mtime = (long)st.st_mtime;
            n++;
        } else {
            /* Replace the oldest if this is newer. */
            int oldest = 0;
            for (int i = 1; i < n; i++)
                if (items[i].mtime < items[oldest].mtime) oldest = i;
            if ((long)st.st_mtime > items[oldest].mtime) {
                snprintf(items[oldest].name, sizeof(items[oldest].name), "%s", ent->d_name);
                items[oldest].mtime = (long)st.st_mtime;
            }
        }
    }
    closedir(dir);

    if (n == 0)
        return sc_tool_result_new("No sessions found.");

    /* Simple insertion sort by mtime desc (n <= 50). */
    for (int i = 1; i < n; i++) {
        struct entry key = items[i];
        int j = i - 1;
        while (j >= 0 && items[j].mtime < key.mtime) { items[j + 1] = items[j]; j--; }
        items[j + 1] = key;
    }

    if (max_results > n) max_results = n;
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%d recent session%s:\n", max_results,
                      max_results == 1 ? "" : "s");
    for (int i = 0; i < max_results; i++)
        sc_strbuf_appendf(&sb, "  %s\n", items[i].name);

    char *out = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(out);
    free(out);
    return r;
}

static sc_tool_result_t *do_search(session_search_data_t *d, const char *query,
                                    int max_results)
{
    if (!query || !query[0])
        return sc_tool_result_error("query is required for action=search");
    if (!ensure_index(d))
        return sc_tool_result_error("session search index unavailable");

    int count = 0;
    sc_memory_search_result_t *results = sc_memory_index_search(
        d->idx, query, max_results, &count);
    if (!results || count == 0) {
        sc_memory_search_results_free(results, count);
        return sc_tool_result_new("No matching sessions found.");
    }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Found %d matching session%s:\n",
                      count, count == 1 ? "" : "s");
    for (int i = 0; i < count; i++)
        sc_strbuf_appendf(&sb, "\n--- [%s] ---\n%s\n",
                          results[i].source, results[i].snippet);

    sc_memory_search_results_free(results, count);
    char *out = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(out);
    free(out);
    return r;
}

static sc_tool_result_t *session_search_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    session_search_data_t *d = self->data;
    if (!d) return sc_tool_result_error("session search not initialized");

    const char *action = sc_json_get_string(args, "action", "search");
    int max_results = sc_json_get_int(args, "max_results", 10);
    if (max_results < 1) max_results = 1;
    if (max_results > SESSION_SEARCH_MAX_RESULTS)
        max_results = SESSION_SEARCH_MAX_RESULTS;

    if (strcmp(action, "list") == 0)
        return do_list(d, max_results);
    return do_search(d, sc_json_get_string(args, "query", NULL), max_results);
}

static void session_search_destroy(sc_tool_t *self)
{
    if (!self) return;
    session_search_data_t *d = self->data;
    if (d) {
        if (d->idx) sc_memory_index_free(d->idx);
        pthread_mutex_destroy(&d->lock);
        free(d->sessions_dir);
        free(d->db_path);
        free(d);
    }
    free(self);
}

sc_tool_t *sc_tool_session_search_new(const char *sessions_dir)
{
    if (!sessions_dir) return NULL;

    session_search_data_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->sessions_dir = sc_strdup(sessions_dir);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/.session_search.db", sessions_dir);
    d->db_path = sc_strbuf_finish(&sb);

    if (!d->sessions_dir || !d->db_path) {
        free(d->sessions_dir); free(d->db_path); free(d);
        return NULL;
    }
    pthread_mutex_init(&d->lock, NULL);

    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) {
        pthread_mutex_destroy(&d->lock);
        free(d->sessions_dir); free(d->db_path); free(d);
        return NULL;
    }

    t->name = "session_search";
    t->description =
        "Search past conversation sessions by keyword (action=search, query=...) "
        "or list recent sessions (action=list). Use to recall earlier "
        "discussions that are no longer in the context window — e.g. \"did we "
        "talk about the deploy script?\". Distinct from memory_search, which "
        "covers curated long-term facts.";
    t->parameters = session_search_parameters;
    t->execute = session_search_execute;
    t->destroy = session_search_destroy;
    t->needs_confirm = 0;
    t->data = d;
    return t;
}
