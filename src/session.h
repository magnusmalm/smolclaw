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

/* Last-activity unix time of a session (its `updated` field), or 0 if the
 * session isn't loaded. */
long sc_session_get_updated(sc_session_manager_t *sm, const char *key);

/* Automatic session-reset policy (task 3.7). */
typedef enum {
    SC_SESSION_RESET_NONE  = 0,
    SC_SESSION_RESET_DAILY = 1,
    SC_SESSION_RESET_IDLE  = 2,
    SC_SESSION_RESET_BOTH  = 3,
} sc_session_reset_mode_t;

/* Decide whether a session whose last activity was `last_updated` should be
 * reset at time `now`. `daily_reset_hour` is local-time hour [0,23];
 * `idle_minutes` is the idle threshold. Pure (no I/O) — `now`/`last_updated`
 * are passed in for testability. Returns 1 if a reset is due. */
int sc_session_reset_due(int mode, int daily_reset_hour, int idle_minutes,
                         long last_updated, long now);

/* Audit M-4: async summarization can fail repeatedly (e.g. provider down),
 * leaving the soft summary threshold permanently exceeded and the history
 * growing every turn without bound. This decides whether a synchronous
 * fail-safe prune should fire: returns 1 when `count` has reached the hard
 * ceiling `summary_threshold * SC_SESSION_FORCE_PRUNE_MULT` (the ceiling is
 * well above the normal summarization point, so it only triggers when
 * summarization is clearly not keeping up). Returns 0 when summarization is
 * disabled (summary_threshold <= 0) or the count is below the ceiling. Pure. */
#define SC_SESSION_FORCE_PRUNE_MULT 4
int sc_session_force_prune_due(int count, int summary_threshold);

/* Branch: set the active parent to the given node id.
 * The next message appended will fork from that point.
 * Returns 0 on success, -1 if node_id not found. */
int sc_session_branch(sc_session_manager_t *sm, const char *key, int node_id);

/* Get the number of leaf nodes (branch tips) in the session tree. */
int sc_session_branch_count(sc_session_manager_t *sm, const char *key);

/* Get the current active leaf node id, or -1 if session is empty. */
int sc_session_active_leaf(sc_session_manager_t *sm, const char *key);

#endif /* SC_SESSION_H */
