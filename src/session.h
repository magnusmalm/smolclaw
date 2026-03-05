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
 */
typedef struct sc_session_manager sc_session_manager_t;

/* Create/destroy session manager */
sc_session_manager_t *sc_session_manager_new(const char *storage_dir);
void sc_session_manager_free(sc_session_manager_t *sm);

/* Get or create session */
sc_session_t *sc_session_get_or_create(sc_session_manager_t *sm, const char *key);

/* Add message to session */
void sc_session_add_message(sc_session_manager_t *sm, const char *key,
                            const char *role, const char *content);
void sc_session_add_full_message(sc_session_manager_t *sm, const char *key,
                                  const sc_llm_message_t *msg);

/* Get history (returns pointer to internal array + count; do not free) */
sc_llm_message_t *sc_session_get_history(sc_session_manager_t *sm, const char *key,
                                          int *out_count);

/* Summary */
const char *sc_session_get_summary(sc_session_manager_t *sm, const char *key);
void sc_session_set_summary(sc_session_manager_t *sm, const char *key,
                            const char *summary);

/* Truncate history, keeping last N messages */
void sc_session_truncate(sc_session_manager_t *sm, const char *key, int keep_last);

/* Persist session to JSON file */
int sc_session_save(sc_session_manager_t *sm, const char *key);

#endif /* SC_SESSION_H */
