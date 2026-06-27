#ifndef SC_TOOL_SESSION_SEARCH_H
#define SC_TOOL_SESSION_SEARCH_H

#include "tools/types.h"

/*
 * Task 4.11: global session search (SC_ENABLE_SESSION_SEARCH, default n).
 *
 * Full-text search across all stored session transcripts under `sessions_dir`
 * (e.g. "did we discuss X last week?") plus a recent-session list. Reuses the
 * SQLite FTS5 index from memory search; the index is built lazily on the first
 * `search` call (deferred). Distinct from memory_search — long-term facts vs
 * conversation recall.
 *
 * `sessions_dir` is copied. Returns NULL on OOM or NULL dir.
 */
sc_tool_t *sc_tool_session_search_new(const char *sessions_dir);

#endif /* SC_TOOL_SESSION_SEARCH_H */
