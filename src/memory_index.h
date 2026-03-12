#ifndef SC_MEMORY_INDEX_H
#define SC_MEMORY_INDEX_H

/* SQLite FTS5 search index for memory files.
 * Markdown files remain source of truth — this is a search overlay. */

typedef struct sc_memory_index sc_memory_index_t;

/* Search result entry */
typedef struct {
    char *source;   /* "long_term" or YYYYMMDD date */
    char *snippet;  /* FTS5 snippet with context */
    double rank;    /* BM25 relevance score */
} sc_memory_search_result_t;

/* Create/destroy index. db_path is the SQLite database file. */
sc_memory_index_t *sc_memory_index_new(const char *db_path);
void sc_memory_index_free(sc_memory_index_t *idx);

/* Index a document (insert or replace). source is the key. */
int sc_memory_index_put(sc_memory_index_t *idx, const char *source,
                        const char *content);

/* Remove a document by source key. */
int sc_memory_index_remove(sc_memory_index_t *idx, const char *source);

/* Rebuild entire index from memory directory. Scans all .md files.
 * Uses content hashing to skip unchanged files (incremental). */
int sc_memory_index_rebuild(sc_memory_index_t *idx, const char *memory_dir);

/* Rebuild index from an arbitrary directory with a source prefix.
 * Only indexes files with extensions in the given list.
 * Source keys are prefixed: e.g. "ctx:filename" for prefix "ctx:". */
int sc_memory_index_rebuild_dir(sc_memory_index_t *idx, const char *dir,
                                const char *prefix,
                                const char **extensions, int ext_count);

/* Search. Returns array of results (caller owns). Sets *out_count. */
sc_memory_search_result_t *sc_memory_index_search(sc_memory_index_t *idx,
                                                   const char *query,
                                                   int max_results,
                                                   int *out_count);

/* Search with source prefix filter (e.g. "ctx:" to match only context docs). */
sc_memory_search_result_t *sc_memory_index_search_prefix(
    sc_memory_index_t *idx, const char *query, const char *prefix,
    int max_results, int *out_count);

/* Index a large document as overlapping chunks for better snippet quality.
 * Files <= CHUNK_THRESHOLD_LINES are indexed as-is.
 * Larger files are split into CHUNK_SIZE_LINES chunks with CHUNK_OVERLAP_LINES overlap. */
int sc_memory_index_put_chunked(sc_memory_index_t *idx, const char *source,
                                const char *content);

/* Remove a document and all its chunks. */
int sc_memory_index_remove_chunked(sc_memory_index_t *idx, const char *source);

/* Free search results array */
void sc_memory_search_results_free(sc_memory_search_result_t *results, int count);

#endif /* SC_MEMORY_INDEX_H */
