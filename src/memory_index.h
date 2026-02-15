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

/* Rebuild entire index from memory directory. Scans all .md files. */
int sc_memory_index_rebuild(sc_memory_index_t *idx, const char *memory_dir);

/* Search. Returns array of results (caller owns). Sets *out_count. */
sc_memory_search_result_t *sc_memory_index_search(sc_memory_index_t *idx,
                                                   const char *query,
                                                   int max_results,
                                                   int *out_count);

/* Free search results array */
void sc_memory_search_results_free(sc_memory_search_result_t *results, int count);

#endif /* SC_MEMORY_INDEX_H */
