#ifndef SC_SESSION_H
#define SC_SESSION_H

#include "providers/types.h"

/* Opaque session types (struct bodies in session.c) */
typedef struct sc_session sc_session_t;

/*
 * Thread safety: NOT thread-safe. All access must be serialized by the caller.
 * Currently guaranteed by the single-threaded agent loop (sc_agent_run /
 * run_agent_loop). Async summarization (L-15) accesses sessions from a worker
 * thread, but only after the main loop has finished with that session for the
 * current turn, so no concurrent access occurs. If multi-threaded message
 * processing is added, per-session or manager-level locking will be required.
 *
 * Storage format: JSONL tree.
 * Each message is a node with an integer id and parent_id (-1 for root).
 * The "active branch" is the path from root to the current leaf node.
 * get_history() returns this path as a linear array (backward compatible).
 * branch(from_node_id) sets the active parent so the next append forks.
 * On disk: one JSON object per line (.jsonl files).
 */
typedef struct sc_session_manager sc_session_manager_t;

/* Create/destroy session manager */
sc_session_manager_t *sc_session_manager_new(const char *storage_dir);
void sc_session_manager_free(sc_session_manager_t *sm);

/* Get or create session */
sc_session_t *sc_session_get_or_create(sc_session_manager_t *sm, const char *key);

/* Add message to session (appends to active branch) */
void sc_session_add_message(sc_session_manager_t *sm, const char *key,
                            const char *role, const char *content);
void sc_session_add_full_message(sc_session_manager_t *sm, const char *key,
                                  const sc_llm_message_t *msg);

/* Get active branch history (returns pointer to internal cache + count;
 * do not free — valid until next add/branch/truncate on this session). */
sc_llm_message_t *sc_session_get_history(sc_session_manager_t *sm, const char *key,
                                          int *out_count);

/* Summary */
const char *sc_session_get_summary(sc_session_manager_t *sm, const char *key);
void sc_session_set_summary(sc_session_manager_t *sm, const char *key,
                            const char *summary);

/* Truncate active branch, keeping last N messages.
 * Removes ancestor nodes from the branch (they remain in the tree). */
void sc_session_truncate(sc_session_manager_t *sm, const char *key, int keep_last);

/* Persist session to JSONL file */
int sc_session_save(sc_session_manager_t *sm, const char *key);

/* Clear a session: drop all nodes and the summary, then persist the empty
 * session (so a restart won't resurrect it). Returns 0 on success (including
 * when the key was never stored), -1 on error. */
int sc_session_reset(sc_session_manager_t *sm, const char *key);

/* Branch: set the active parent to the given node id.
 * The next message appended will fork from that point.
 * Returns 0 on success, -1 if node_id not found. */
int sc_session_branch(sc_session_manager_t *sm, const char *key, int node_id);

/* Get the number of leaf nodes (branch tips) in the session tree. */
int sc_session_branch_count(sc_session_manager_t *sm, const char *key);

/* Get the current active leaf node id, or -1 if session is empty. */
int sc_session_active_leaf(sc_session_manager_t *sm, const char *key);

#endif /* SC_SESSION_H */
