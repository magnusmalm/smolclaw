/*
 * memory_index.c — SQLite FTS5 search index for memory files
 *
 * The markdown files in memory/ are the source of truth.
 * This module maintains a full-text search index that is rebuilt
 * on startup and updated incrementally on writes.
 *
 * Features:
 * - Content hashing (FNV1a) for incremental rebuild — skip unchanged files
 * - Chunking for large files (>200 lines) for better snippet quality
 * - Prefix-filtered search for context artifacts
 * - Generalized rebuild_dir() for indexing arbitrary directories
 */

#include "memory_index.h"
#include "logger.h"
#include "util/str.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/stat.h>

#define LOG_TAG "memory_index"

/* Chunking constants */
#define CHUNK_THRESHOLD_LINES 200
#define CHUNK_SIZE_LINES      100
#define CHUNK_OVERLAP_LINES   10

struct sc_memory_index {
    sqlite3 *db;
    sqlite3_stmt *stmt_put;
    sqlite3_stmt *stmt_remove;
    sqlite3_stmt *stmt_search;
    sqlite3_stmt *stmt_search_recency;
    sqlite3_stmt *stmt_clear;
    /* Content hashing for incremental rebuild */
    sqlite3_stmt *stmt_hash_get;
    sqlite3_stmt *stmt_hash_put;
    sqlite3_stmt *stmt_hash_remove;
    sqlite3_stmt *stmt_hash_list;
    /* Prefix-filtered search */
    sqlite3_stmt *stmt_search_prefix;
    sqlite3_stmt *stmt_search_prefix_recency;
    /* Chunk removal */
    sqlite3_stmt *stmt_remove_chunks;
};

/* FNV1a hash — same as agent_turn.c */
static uint32_t fnv1a_str(const char *s)
{
    uint32_t h = 2166136261u;
    for (; s && *s; s++)
        h = (h ^ (uint8_t)*s) * 16777619u;
    return h;
}

/* Format hash as 8-char hex string */
static void hash_to_hex(uint32_t h, char *out)
{
    snprintf(out, 9, "%08x", h);
}

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

/* Derive source key with prefix from filename.
 * Strips the extension. E.g. prefix="ctx:", filename="schema.json" → "ctx:schema" */
static char *source_from_filename_prefix(const char *filename, const char *prefix)
{
    /* Find last dot for extension stripping */
    const char *dot = strrchr(filename, '.');
    size_t name_len = dot ? (size_t)(dot - filename) : strlen(filename);
    size_t prefix_len = prefix ? strlen(prefix) : 0;

    char *s = malloc(prefix_len + name_len + 1);
    if (!s) return NULL;
    if (prefix_len > 0)
        memcpy(s, prefix, prefix_len);
    memcpy(s + prefix_len, filename, name_len);
    s[prefix_len + name_len] = '\0';
    return s;
}

/* Count lines in a string */
static int count_lines(const char *s)
{
    int n = 0;
    for (; *s; s++)
        if (*s == '\n') n++;
    return n + 1; /* count last line even without trailing newline */
}

/* Check if filename has one of the given extensions */
static int has_extension(const char *filename, const char **extensions, int ext_count)
{
    const char *dot = strrchr(filename, '.');
    if (!dot) return 0;
    for (int i = 0; i < ext_count; i++) {
        if (strcmp(dot, extensions[i]) == 0)
            return 1;
    }
    return 0;
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

    /* Content hashing table for incremental rebuild */
    sqlite3_exec(idx->db,
        "CREATE TABLE IF NOT EXISTS memory_hashes ("
        "  source TEXT PRIMARY KEY,"
        "  content_hash TEXT NOT NULL,"
        "  mtime INTEGER NOT NULL"
        ")", NULL, NULL, NULL);

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
        "SELECT source, snippet(memory_fts, 1, '»', '«', '...', 64), "
        "       rank "
        "FROM memory_fts WHERE memory_fts MATCH ?1 "
        "ORDER BY CASE WHEN source = 'long_term' THEN '19000101' "
        "ELSE source END DESC LIMIT ?2",
        -1, &idx->stmt_search_recency, NULL);
    sqlite3_prepare_v2(idx->db,
        "DELETE FROM memory_fts",
        -1, &idx->stmt_clear, NULL);

    /* Hash statements */
    sqlite3_prepare_v2(idx->db,
        "SELECT content_hash, mtime FROM memory_hashes WHERE source = ?1",
        -1, &idx->stmt_hash_get, NULL);
    sqlite3_prepare_v2(idx->db,
        "INSERT OR REPLACE INTO memory_hashes(source, content_hash, mtime) "
        "VALUES (?1, ?2, ?3)",
        -1, &idx->stmt_hash_put, NULL);
    sqlite3_prepare_v2(idx->db,
        "DELETE FROM memory_hashes WHERE source = ?1",
        -1, &idx->stmt_hash_remove, NULL);
    sqlite3_prepare_v2(idx->db,
        "SELECT source FROM memory_hashes",
        -1, &idx->stmt_hash_list, NULL);

    /* Prefix-filtered search statements */
    sqlite3_prepare_v2(idx->db,
        "SELECT source, snippet(memory_fts, 1, '»', '«', '...', 64), "
        "       rank "
        "FROM memory_fts WHERE memory_fts MATCH ?1 AND source LIKE ?3 "
        "ORDER BY rank LIMIT ?2",
        -1, &idx->stmt_search_prefix, NULL);
    sqlite3_prepare_v2(idx->db,
        "SELECT source, snippet(memory_fts, 1, '»', '«', '...', 64), "
        "       rank "
        "FROM memory_fts WHERE memory_fts MATCH ?1 AND source LIKE ?3 "
        "ORDER BY source DESC LIMIT ?2",
        -1, &idx->stmt_search_prefix_recency, NULL);

    /* Chunk removal: delete source + all "source:chunk_%" entries */
    sqlite3_prepare_v2(idx->db,
        "DELETE FROM memory_fts WHERE source = ?1 OR source LIKE ?2",
        -1, &idx->stmt_remove_chunks, NULL);

    SC_LOG_DEBUG(LOG_TAG, "Index opened at %s", db_path);
    return idx;
}

void sc_memory_index_free(sc_memory_index_t *idx)
{
    if (!idx) return;
    sqlite3_finalize(idx->stmt_put);
    sqlite3_finalize(idx->stmt_remove);
    sqlite3_finalize(idx->stmt_search);
    sqlite3_finalize(idx->stmt_search_recency);
    sqlite3_finalize(idx->stmt_clear);
    sqlite3_finalize(idx->stmt_hash_get);
    sqlite3_finalize(idx->stmt_hash_put);
    sqlite3_finalize(idx->stmt_hash_remove);
    sqlite3_finalize(idx->stmt_hash_list);
    sqlite3_finalize(idx->stmt_search_prefix);
    sqlite3_finalize(idx->stmt_search_prefix_recency);
    sqlite3_finalize(idx->stmt_remove_chunks);
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

    /* Update hash entry */
    char hex[9];
    hash_to_hex(fnv1a_str(content), hex);
    sqlite3_reset(idx->stmt_hash_put);
    sqlite3_bind_text(idx->stmt_hash_put, 1, source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(idx->stmt_hash_put, 2, hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(idx->stmt_hash_put, 3, 0);
    sqlite3_step(idx->stmt_hash_put);

    SC_LOG_DEBUG(LOG_TAG, "Indexed '%s' (%d bytes)", source, (int)strlen(content));
    return 0;
}

int sc_memory_index_remove(sc_memory_index_t *idx, const char *source)
{
    if (!idx || !source) return -1;

    sqlite3_reset(idx->stmt_remove);
    sqlite3_bind_text(idx->stmt_remove, 1, source, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(idx->stmt_remove);

    /* Also remove hash entry */
    sqlite3_reset(idx->stmt_hash_remove);
    sqlite3_bind_text(idx->stmt_hash_remove, 1, source, -1, SQLITE_TRANSIENT);
    sqlite3_step(idx->stmt_hash_remove);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* ========== Chunking ========== */

int sc_memory_index_put_chunked(sc_memory_index_t *idx, const char *source,
                                const char *content)
{
    if (!idx || !source || !content) return -1;

    int lines = count_lines(content);
    if (lines <= CHUNK_THRESHOLD_LINES) {
        return sc_memory_index_put(idx, source, content);
    }

    /* Remove base + old chunks first */
    sc_memory_index_remove_chunked(idx, source);

    /* Split into overlapping chunks */
    const char *p = content;
    int chunk_num = 0;
    int line_num = 0;

    while (*p) {
        /* Find start of this chunk (line_num already positioned) */
        const char *chunk_start = p;
        int chunk_lines = 0;

        /* Advance CHUNK_SIZE_LINES lines */
        while (*p && chunk_lines < CHUNK_SIZE_LINES) {
            if (*p == '\n') chunk_lines++;
            p++;
        }
        /* Include remainder of last line */
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;

        /* Extract chunk text */
        size_t chunk_len = (size_t)(p - chunk_start);
        char *chunk = malloc(chunk_len + 1);
        if (!chunk) break;
        memcpy(chunk, chunk_start, chunk_len);
        chunk[chunk_len] = '\0';

        /* Build source key: "source:chunk_N" */
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "%s:chunk_%d", source, chunk_num);
        char *chunk_source = sc_strbuf_finish(&sb);

        sc_memory_index_put(idx, chunk_source, chunk);
        free(chunk_source);
        free(chunk);

        chunk_num++;
        line_num += chunk_lines;

        /* Back up by overlap lines for next chunk */
        if (*p) {
            int backup = CHUNK_OVERLAP_LINES;
            const char *back = p;
            while (backup > 0 && back > chunk_start) {
                back--;
                if (*back == '\n') backup--;
            }
            if (back > chunk_start) {
                /* Move past the newline we stopped at */
                if (*back == '\n') back++;
                p = back;
            }
        }
    }

    SC_LOG_DEBUG(LOG_TAG, "Chunked '%s': %d lines → %d chunks",
                 source, lines, chunk_num);
    return 0;
}

int sc_memory_index_remove_chunked(sc_memory_index_t *idx, const char *source)
{
    if (!idx || !source) return -1;

    /* Build LIKE pattern: "source:chunk_%" */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s:chunk_%%", source);
    char *pattern = sc_strbuf_finish(&sb);

    sqlite3_reset(idx->stmt_remove_chunks);
    sqlite3_bind_text(idx->stmt_remove_chunks, 1, source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(idx->stmt_remove_chunks, 2, pattern, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(idx->stmt_remove_chunks);
    free(pattern);

    /* Remove hash entries too */
    sqlite3_reset(idx->stmt_hash_remove);
    sqlite3_bind_text(idx->stmt_hash_remove, 1, source, -1, SQLITE_TRANSIENT);
    sqlite3_step(idx->stmt_hash_remove);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* ========== Incremental rebuild ========== */

/* Check if a source's content has changed since last index.
 * Returns 1 if needs re-indexing, 0 if unchanged. */
static int needs_reindex(sc_memory_index_t *idx, const char *source,
                         const char *content, long mtime)
{
    sqlite3_reset(idx->stmt_hash_get);
    sqlite3_bind_text(idx->stmt_hash_get, 1, source, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(idx->stmt_hash_get);
    if (rc != SQLITE_ROW)
        return 1; /* no previous hash → needs indexing */

    long old_mtime = (long)sqlite3_column_int64(idx->stmt_hash_get, 1);
    if (old_mtime == mtime)
        return 0; /* mtime unchanged → skip hash check */

    /* mtime changed, compare content hash */
    const char *old_hash = (const char *)sqlite3_column_text(idx->stmt_hash_get, 0);
    char new_hash[9];
    hash_to_hex(fnv1a_str(content), new_hash);

    return (old_hash == NULL || strcmp(old_hash, new_hash) != 0);
}

/* Update hash entry after indexing */
static void update_hash(sc_memory_index_t *idx, const char *source,
                        const char *content, long mtime)
{
    char hex[9];
    hash_to_hex(fnv1a_str(content), hex);
    sqlite3_reset(idx->stmt_hash_put);
    sqlite3_bind_text(idx->stmt_hash_put, 1, source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(idx->stmt_hash_put, 2, hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(idx->stmt_hash_put, 3, mtime);
    sqlite3_step(idx->stmt_hash_put);
}

/* Collect all known sources from hash table, for stale detection */
typedef struct {
    char **sources;
    int count;
    int cap;
} source_set_t;

static void source_set_init(source_set_t *ss)
{
    ss->sources = NULL;
    ss->count = 0;
    ss->cap = 0;
}

static void source_set_add(source_set_t *ss, const char *source)
{
    if (ss->count >= ss->cap) {
        int new_cap = ss->cap ? ss->cap * 2 : 64;
        char **tmp = realloc(ss->sources, (size_t)new_cap * sizeof(char *));
        if (!tmp) return;
        ss->sources = tmp;
        ss->cap = new_cap;
    }
    ss->sources[ss->count++] = sc_strdup(source);
}

static void source_set_remove(source_set_t *ss, const char *source)
{
    for (int i = 0; i < ss->count; i++) {
        if (ss->sources[i] && strcmp(ss->sources[i], source) == 0) {
            free(ss->sources[i]);
            ss->sources[i] = NULL;
            return;
        }
    }
}

static void source_set_free(source_set_t *ss)
{
    for (int i = 0; i < ss->count; i++)
        free(ss->sources[i]);
    free(ss->sources);
}

/* Recursively scan directory, index with content hashing */
static int scan_dir_incremental(sc_memory_index_t *idx, const char *dir_path,
                                const char *prefix,
                                const char **extensions, int ext_count,
                                source_set_t *seen, int *unchanged, int *removed)
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
                count += scan_dir_incremental(idx, path, prefix,
                                              extensions, ext_count,
                                              seen, unchanged, removed);
            } else if (S_ISREG(st.st_mode)) {
                int match = 0;
                if (extensions && ext_count > 0) {
                    match = has_extension(ent->d_name, extensions, ext_count);
                } else {
                    /* Default: .md files only */
                    size_t nlen = strlen(ent->d_name);
                    match = (nlen > 3 && strcmp(ent->d_name + nlen - 3, ".md") == 0);
                }

                if (match) {
                    char *source;
                    if (prefix && prefix[0]) {
                        source = source_from_filename_prefix(ent->d_name, prefix);
                    } else {
                        source = source_from_filename(ent->d_name);
                    }

                    if (source) {
                        /* Mark as seen */
                        source_set_remove(seen, source);

                        char *content = read_file(path);
                        if (content) {
                            if (needs_reindex(idx, source, content,
                                              (long)st.st_mtime)) {
                                sc_memory_index_put_chunked(idx, source, content);
                                update_hash(idx, source, content,
                                            (long)st.st_mtime);
                                count++;
                            } else {
                                (*unchanged)++;
                            }
                            free(content);
                        }
                        free(source);
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

    static const char *md_ext[] = { ".md" };
    return sc_memory_index_rebuild_dir(idx, memory_dir, NULL, md_ext, 1);
}

int sc_memory_index_rebuild_dir(sc_memory_index_t *idx, const char *dir,
                                const char *prefix,
                                const char **extensions, int ext_count)
{
    if (!idx || !dir) return -1;

    /* Collect existing sources from hash table to detect deletions */
    source_set_t known;
    source_set_init(&known);

    sqlite3_reset(idx->stmt_hash_list);
    while (sqlite3_step(idx->stmt_hash_list) == SQLITE_ROW) {
        const char *src = (const char *)sqlite3_column_text(idx->stmt_hash_list, 0);
        if (src) {
            /* Only track sources matching our prefix */
            if (prefix && prefix[0]) {
                if (strncmp(src, prefix, strlen(prefix)) == 0)
                    source_set_add(&known, src);
            } else {
                /* No prefix: track sources that don't have any known prefix */
                if (strncmp(src, "ctx:", 4) != 0)
                    source_set_add(&known, src);
            }
        }
    }

    sqlite3_exec(idx->db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    int unchanged = 0;
    int removed_count = 0;
    int indexed = scan_dir_incremental(idx, dir, prefix,
                                       extensions, ext_count,
                                       &known, &unchanged, &removed_count);

    /* Remove stale entries (files that were deleted) */
    for (int i = 0; i < known.count; i++) {
        if (known.sources[i]) {
            sc_memory_index_remove_chunked(idx, known.sources[i]);
            sqlite3_reset(idx->stmt_hash_remove);
            sqlite3_bind_text(idx->stmt_hash_remove, 1, known.sources[i],
                              -1, SQLITE_TRANSIENT);
            sqlite3_step(idx->stmt_hash_remove);
            removed_count++;
        }
    }

    sqlite3_exec(idx->db, "COMMIT", NULL, NULL, NULL);

    source_set_free(&known);

    SC_LOG_INFO(LOG_TAG, "Memory index: %d indexed, %d unchanged, %d removed (%s)",
                indexed, unchanged, removed_count, dir);
    return indexed;
}

/* ========== Search ========== */

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

/* RRF (Reciprocal Rank Fusion) constant — standard value from literature */
#define RRF_K 60

/* Internal search implementation shared by search and search_prefix */
static sc_memory_search_result_t *do_search(sc_memory_index_t *idx,
                                             const char *query,
                                             sqlite3_stmt *stmt_bm25,
                                             sqlite3_stmt *stmt_recency,
                                             const char *prefix_like,
                                             int max_results,
                                             int *out_count)
{
    if (!idx || !query || !out_count) return NULL;
    *out_count = 0;

    if (max_results <= 0) max_results = 10;
    if (max_results > 50) max_results = 50;

    /* Prepare query string */
    int use_raw = has_fts5_syntax(query);
    char *safe_query = use_raw ? NULL : simple_quote_query(query);
    const char *bound = safe_query ? safe_query : query;

    /* Pool for RRF fusion: fetch 3x candidates from each ranking */
    int pool_limit = max_results * 3;
    if (pool_limit > 50) pool_limit = 50;
    int pool_cap = pool_limit * 2;

    struct rrf_entry {
        char *source;
        char *snippet;
        int bm25_pos;    /* 1-based position, 0 = absent */
        int recency_pos;
    };
    struct rrf_entry *pool = calloc((size_t)pool_cap, sizeof(*pool));
    if (!pool) { free(safe_query); return NULL; }
    int pool_count = 0;

    /* 1. BM25-ranked results */
    sqlite3_reset(stmt_bm25);
    sqlite3_bind_text(stmt_bm25, 1, bound, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt_bm25, 2, pool_limit);
    if (prefix_like)
        sqlite3_bind_text(stmt_bm25, 3, prefix_like, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt_bm25);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE && use_raw) {
        char *fb = simple_quote_query(query);
        if (fb) {
            free(safe_query);
            safe_query = fb;
            bound = safe_query;
            sqlite3_reset(stmt_bm25);
            sqlite3_bind_text(stmt_bm25, 1, bound, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt_bm25, 2, pool_limit);
            if (prefix_like)
                sqlite3_bind_text(stmt_bm25, 3, prefix_like, -1, SQLITE_TRANSIENT);
            rc = sqlite3_step(stmt_bm25);
        }
    }

    int pos = 0;
    while (rc == SQLITE_ROW && pool_count < pool_cap) {
        pos++;
        const char *src = (const char *)sqlite3_column_text(stmt_bm25, 0);
        const char *snip = (const char *)sqlite3_column_text(stmt_bm25, 1);
        pool[pool_count].source = sc_strdup(src ? src : "");
        pool[pool_count].snippet = sc_strdup(snip ? snip : "");
        pool[pool_count].bm25_pos = pos;
        pool[pool_count].recency_pos = 0;
        pool_count++;
        rc = sqlite3_step(stmt_bm25);
    }

    /* 2. Recency-ranked results (fused via RRF) */
    if (stmt_recency && pool_count > 0) {
        sqlite3_reset(stmt_recency);
        sqlite3_bind_text(stmt_recency, 1, bound, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt_recency, 2, pool_limit);
        if (prefix_like)
            sqlite3_bind_text(stmt_recency, 3, prefix_like, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt_recency);
        pos = 0;
        while (rc == SQLITE_ROW) {
            pos++;
            const char *src = (const char *)sqlite3_column_text(stmt_recency, 0);
            const char *s = src ? src : "";
            int found = -1;
            for (int i = 0; i < pool_count; i++) {
                if (strcmp(pool[i].source, s) == 0) { found = i; break; }
            }
            if (found >= 0) {
                pool[found].recency_pos = pos;
            } else if (pool_count < pool_cap) {
                const char *snip = (const char *)sqlite3_column_text(stmt_recency, 1);
                pool[pool_count].source = sc_strdup(s);
                pool[pool_count].snippet = sc_strdup(snip ? snip : "");
                pool[pool_count].bm25_pos = 0;
                pool[pool_count].recency_pos = pos;
                pool_count++;
            }
            rc = sqlite3_step(stmt_recency);
        }
    }

    free(safe_query);

    if (pool_count == 0) {
        free(pool);
        return NULL;
    }

    /* 3. Compute RRF scores: 1/(k+bm25_pos) + 1/(k+recency_pos) */
    double *scores = calloc((size_t)pool_count, sizeof(double));
    for (int i = 0; i < pool_count; i++) {
        if (pool[i].bm25_pos > 0)
            scores[i] += 1.0 / (RRF_K + pool[i].bm25_pos);
        if (pool[i].recency_pos > 0)
            scores[i] += 1.0 / (RRF_K + pool[i].recency_pos);
    }

    /* 4. Select top max_results by RRF score */
    sc_memory_search_result_t *results = calloc((size_t)max_results, sizeof(*results));
    int count = 0;
    for (int r = 0; r < max_results; r++) {
        int best = -1;
        for (int i = 0; i < pool_count; i++) {
            if (scores[i] > 0 && (best < 0 || scores[i] > scores[best]))
                best = i;
        }
        if (best < 0) break;
        results[count].source = pool[best].source;
        results[count].snippet = pool[best].snippet;
        results[count].rank = scores[best];
        pool[best].source = NULL;
        pool[best].snippet = NULL;
        scores[best] = -1.0;
        count++;
    }

    for (int i = 0; i < pool_count; i++) {
        free(pool[i].source);
        free(pool[i].snippet);
    }
    free(pool);
    free(scores);

    *out_count = count;
    if (count == 0) { free(results); return NULL; }
    return results;
}

sc_memory_search_result_t *sc_memory_index_search(sc_memory_index_t *idx,
                                                   const char *query,
                                                   int max_results,
                                                   int *out_count)
{
    if (!idx) { if (out_count) *out_count = 0; return NULL; }
    return do_search(idx, query, idx->stmt_search, idx->stmt_search_recency,
                     NULL, max_results, out_count);
}

sc_memory_search_result_t *sc_memory_index_search_prefix(
    sc_memory_index_t *idx, const char *query, const char *prefix,
    int max_results, int *out_count)
{
    if (!prefix || !prefix[0])
        return sc_memory_index_search(idx, query, max_results, out_count);

    /* Build LIKE pattern: "ctx:%" */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s%%", prefix);
    char *like = sc_strbuf_finish(&sb);

    sc_memory_search_result_t *results = do_search(
        idx, query, idx->stmt_search_prefix, idx->stmt_search_prefix_recency,
        like, max_results, out_count);

    free(like);
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
