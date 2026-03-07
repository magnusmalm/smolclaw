/*
 * memory_index.c — SQLite FTS5 search index for memory files
 *
 * The markdown files in memory/ are the source of truth.
 * This module maintains a full-text search index that is rebuilt
 * on startup and updated incrementally on writes.
 */

#include "memory_index.h"
#include "logger.h"
#include "util/str.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define LOG_TAG "memory_index"

struct sc_memory_index {
    sqlite3 *db;
    sqlite3_stmt *stmt_put;
    sqlite3_stmt *stmt_remove;
    sqlite3_stmt *stmt_search;
    sqlite3_stmt *stmt_clear;
};

/* Read file into malloc'd string (NULL on failure) */
static char *read_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len <= 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);

    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t n = fread(buf, 1, (size_t)len, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

/* Derive source key from filename: "MEMORY.md" → "long_term", "20260301.md" → "20260301" */
static char *source_from_filename(const char *filename)
{
    if (strcmp(filename, "MEMORY.md") == 0)
        return sc_strdup("long_term");

    /* Strip .md extension */
    size_t len = strlen(filename);
    if (len > 3 && strcmp(filename + len - 3, ".md") == 0) {
        char *s = malloc(len - 2);
        if (!s) return NULL;
        memcpy(s, filename, len - 3);
        s[len - 3] = '\0';
        return s;
    }
    return sc_strdup(filename);
}

sc_memory_index_t *sc_memory_index_new(const char *db_path)
{
    if (!db_path) return NULL;

    sc_memory_index_t *idx = calloc(1, sizeof(*idx));
    if (!idx) return NULL;

    int rc = sqlite3_open(db_path, &idx->db);
    if (rc != SQLITE_OK) {
        SC_LOG_ERROR(LOG_TAG, "Failed to open index database: %s",
                     sqlite3_errmsg(idx->db));
        sqlite3_close(idx->db);
        free(idx);
        return NULL;
    }

    /* WAL mode for crash safety and concurrent reads */
    sqlite3_exec(idx->db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);

    /* Create FTS5 virtual table */
    const char *create_sql =
        "CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5("
        "  source UNINDEXED,"
        "  content,"
        "  tokenize = 'porter unicode61'"
        ")";
    char *err = NULL;
    rc = sqlite3_exec(idx->db, create_sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        SC_LOG_ERROR(LOG_TAG, "Failed to create FTS5 table: %s",
                     err ? err : "unknown");
        sqlite3_free(err);
        sqlite3_close(idx->db);
        free(idx);
        return NULL;
    }

    /* Prepare statements */
    /* Put: delete old then insert (FTS5 doesn't support REPLACE) */
    sqlite3_prepare_v2(idx->db,
        "DELETE FROM memory_fts WHERE source = ?1",
        -1, &idx->stmt_remove, NULL);
    sqlite3_prepare_v2(idx->db,
        "INSERT INTO memory_fts(source, content) VALUES (?1, ?2)",
        -1, &idx->stmt_put, NULL);
    sqlite3_prepare_v2(idx->db,
        "SELECT source, snippet(memory_fts, 1, '»', '«', '...', 64), "
        "       rank "
        "FROM memory_fts WHERE memory_fts MATCH ?1 "
        "ORDER BY rank LIMIT ?2",
        -1, &idx->stmt_search, NULL);
    sqlite3_prepare_v2(idx->db,
        "DELETE FROM memory_fts",
        -1, &idx->stmt_clear, NULL);

    SC_LOG_DEBUG(LOG_TAG, "Index opened at %s", db_path);
    return idx;
}

void sc_memory_index_free(sc_memory_index_t *idx)
{
    if (!idx) return;
    sqlite3_finalize(idx->stmt_put);
    sqlite3_finalize(idx->stmt_remove);
    sqlite3_finalize(idx->stmt_search);
    sqlite3_finalize(idx->stmt_clear);
    sqlite3_close(idx->db);
    free(idx);
}

int sc_memory_index_put(sc_memory_index_t *idx, const char *source,
                        const char *content)
{
    if (!idx || !source || !content) return -1;

    /* Delete existing entry */
    sqlite3_reset(idx->stmt_remove);
    sqlite3_bind_text(idx->stmt_remove, 1, source, -1, SQLITE_TRANSIENT);
    sqlite3_step(idx->stmt_remove);

    /* Insert new */
    sqlite3_reset(idx->stmt_put);
    sqlite3_bind_text(idx->stmt_put, 1, source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(idx->stmt_put, 2, content, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(idx->stmt_put);
    if (rc != SQLITE_DONE) {
        SC_LOG_WARN(LOG_TAG, "Failed to index '%s': %s",
                    source, sqlite3_errmsg(idx->db));
        return -1;
    }

    SC_LOG_DEBUG(LOG_TAG, "Indexed '%s' (%d bytes)", source, (int)strlen(content));
    return 0;
}

int sc_memory_index_remove(sc_memory_index_t *idx, const char *source)
{
    if (!idx || !source) return -1;

    sqlite3_reset(idx->stmt_remove);
    sqlite3_bind_text(idx->stmt_remove, 1, source, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(idx->stmt_remove);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* Recursively scan directory for .md files and index them */
static int scan_dir(sc_memory_index_t *idx, const char *dir_path)
{
    DIR *d = opendir(dir_path);
    if (!d) return 0;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "%s/%s", dir_path, ent->d_name);
        char *path = sc_strbuf_finish(&sb);

        struct stat st;
        if (stat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                count += scan_dir(idx, path);
            } else if (S_ISREG(st.st_mode)) {
                size_t nlen = strlen(ent->d_name);
                if (nlen > 3 && strcmp(ent->d_name + nlen - 3, ".md") == 0) {
                    /* Skip search.db and non-markdown files */
                    char *content = read_file(path);
                    if (content) {
                        char *source = source_from_filename(ent->d_name);
                        if (source) {
                            sc_memory_index_put(idx, source, content);
                            count++;
                            free(source);
                        }
                        free(content);
                    }
                }
            }
        }
        free(path);
    }
    closedir(d);
    return count;
}

int sc_memory_index_rebuild(sc_memory_index_t *idx, const char *memory_dir)
{
    if (!idx || !memory_dir) return -1;

    /* Clear existing index */
    sqlite3_reset(idx->stmt_clear);
    sqlite3_step(idx->stmt_clear);

    /* Begin transaction for bulk insert */
    sqlite3_exec(idx->db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    int count = scan_dir(idx, memory_dir);

    sqlite3_exec(idx->db, "COMMIT", NULL, NULL, NULL);

    SC_LOG_INFO(LOG_TAG, "Rebuilt index: %d documents from %s", count, memory_dir);
    return count;
}

/* Escape FTS5 query: wrap each token in double quotes for safety.
 * If the query looks like it already uses FTS5 syntax (quotes, *, OR/AND/NOT),
 * pass it through and catch errors. */
static int has_fts5_syntax(const char *query)
{
    return (strchr(query, '"') != NULL ||
            strchr(query, '*') != NULL ||
            strstr(query, " OR ") != NULL ||
            strstr(query, " AND ") != NULL ||
            strstr(query, " NOT ") != NULL);
}

static char *simple_quote_query(const char *query)
{
    /* Quote each whitespace-separated term individually so FTS5
     * interprets them as implicit AND without special syntax */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    const char *p = query;
    int first = 1;
    while (*p) {
        /* Skip whitespace */
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        /* Find end of token */
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (!first) sc_strbuf_append(&sb, " ");
        first = 0;
        sc_strbuf_append(&sb, "\"");
        for (const char *t = start; t < p; t++) {
            if (*t == '"')
                sc_strbuf_append(&sb, "\"\"");
            else
                sc_strbuf_appendf(&sb, "%c", *t);
        }
        sc_strbuf_append(&sb, "\"");
    }
    return sc_strbuf_finish(&sb);
}

sc_memory_search_result_t *sc_memory_index_search(sc_memory_index_t *idx,
                                                   const char *query,
                                                   int max_results,
                                                   int *out_count)
{
    if (!idx || !query || !out_count) return NULL;
    *out_count = 0;

    if (max_results <= 0) max_results = 10;
    if (max_results > 50) max_results = 50;

    /* Default to safe quoted query; only use raw if it has FTS5 syntax */
    int use_raw = has_fts5_syntax(query);
    char *safe = use_raw ? NULL : simple_quote_query(query);

    sqlite3_reset(idx->stmt_search);
    sqlite3_bind_text(idx->stmt_search, 1, safe ? safe : query, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(idx->stmt_search, 2, max_results);

    /* Allocate results array */
    sc_memory_search_result_t *results = calloc((size_t)max_results,
                                                 sizeof(sc_memory_search_result_t));
    if (!results) { free(safe); return NULL; }

    int count = 0;
    int rc = sqlite3_step(idx->stmt_search);

    /* If raw FTS5 query fails with syntax error, retry with quoted version */
    if (rc != SQLITE_ROW && rc != SQLITE_DONE && use_raw) {
        char *fallback = simple_quote_query(query);
        if (fallback) {
            sqlite3_reset(idx->stmt_search);
            sqlite3_bind_text(idx->stmt_search, 1, fallback, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(idx->stmt_search, 2, max_results);
            rc = sqlite3_step(idx->stmt_search);
            free(fallback);
        }
    }
    free(safe);

    while (rc == SQLITE_ROW && count < max_results) {
        const char *source = (const char *)sqlite3_column_text(idx->stmt_search, 0);
        const char *snippet = (const char *)sqlite3_column_text(idx->stmt_search, 1);
        double rank = sqlite3_column_double(idx->stmt_search, 2);

        results[count].source = sc_strdup(source ? source : "");
        results[count].snippet = sc_strdup(snippet ? snippet : "");
        results[count].rank = rank;
        count++;

        rc = sqlite3_step(idx->stmt_search);
    }

    *out_count = count;

    if (count == 0) {
        free(results);
        return NULL;
    }

    return results;
}

void sc_memory_search_results_free(sc_memory_search_result_t *results, int count)
{
    if (!results) return;
    for (int i = 0; i < count; i++) {
        free(results[i].source);
        free(results[i].snippet);
    }
    free(results);
}
