#ifndef SC_PROJECT_MEMORY_H
#define SC_PROJECT_MEMORY_H

#include <stddef.h>

/*
 * Task 4.5: project memory + repo_search (SC_ENABLE_PROJECT_MEMORY, default n).
 *
 * A per-workspace code index stored at {SMOLCLAW_HOME}/indexes/<hash>.json
 * (Q2: never inside the user's repo). Each source file contributes a record:
 * path, language, size, mtime, sha256, and lightweight term/symbol/import
 * extraction (Q7: v1 has its own extraction; shares with code_graph in v2).
 * repo_search ranks files against a query over those tokens.
 */

/* ---- pure helpers (unit-tested) ---- */

/* First 16 hex chars of sha256(abspath). Caller frees. NULL on bad input. */
char *sc_pm_workspace_hash(const char *abspath);

/* Language label for a path by extension ("c", "python", ...), or NULL if the
 * extension is unknown / not a source file we index. Static string. */
const char *sc_pm_language_for(const char *path);

/* Tokenize `text` into lowercased identifier-ish terms (>= 3 chars). Returns a
 * malloc'd array of malloc'd strings (caller frees with sc_pm_free_terms), sets
 * *count. De-duplicates. Returns NULL with *count 0 when empty. */
char **sc_pm_tokenize(const char *text, int *count);
void sc_pm_free_terms(char **terms, int count);

/* Score a document blob (space-joined lowercased tokens) against a raw query.
 * Returns the number of distinct query tokens found as whole tokens in the
 * blob. 0 when either side is empty. Pure. */
int sc_pm_match_score(const char *doc_blob, const char *query);

/* ---- index + search ---- */

/* Path to the index file for `workspace` ({SMOLCLAW_HOME}/indexes/<hash>.json).
 * Caller frees. NULL on error. */
char *sc_pm_index_path(const char *workspace);

/* Build (or incrementally refresh) the index for `workspace`. When incremental
 * is non-zero, unchanged files (same size+mtime+sha256) are kept. Returns the
 * number of files indexed, or -1 on error. */
int sc_pm_build(const char *workspace, int incremental);

/* A ranked search hit. */
typedef struct {
    char  *path;       /* workspace-relative path */
    char  *language;
    int    score;
} sc_pm_hit_t;

/* Search the (already-built) index for `query`. Returns up to `max` ranked hits
 * (caller frees with sc_pm_hits_free), sets *count. NULL/0 if no index or no
 * match. */
sc_pm_hit_t *sc_pm_search(const char *workspace, const char *query,
                          int max, int *count);
void sc_pm_hits_free(sc_pm_hit_t *hits, int count);

/* Human-readable status line for the index (file count, age), or a "not built"
 * message. Caller frees. */
char *sc_pm_status(const char *workspace);

#endif /* SC_PROJECT_MEMORY_H */
