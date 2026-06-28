#ifndef SC_MEMORY_H
#define SC_MEMORY_H

#include <stddef.h>  /* size_t */

/* Index update callback: called after successful writes */
typedef void (*sc_memory_index_cb)(const char *source, const char *content,
                                   void *ctx);

/* Memory store for long-term memory and daily notes.
 *
 * Two modes:
 *  - Shared (sc_memory_new): workspace-wide. Reads MEMORY.md and dated
 *    notes from {workspace}/memory/. The "long-running self" of the agent.
 *  - Namespaced (sc_memory_new_namespaced): per-session. Reads/writes go
 *    under {workspace}/memory/_sessions/<namespace_id>/. Long-term reads
 *    return NULL; long-term writes are no-ops. Designed for ephemeral
 *    delegate sessions where shared memory would cause cross-contamination
 *    (see docs/design/session-isolation-plan.md).
 */
typedef struct sc_memory {
    char *workspace;
    char *memory_dir;       /* {workspace}/memory/ */
    char *memory_file;      /* {workspace}/memory/MEMORY.md (shared mode only) */
    char *namespace_id;     /* NULL = shared; non-NULL = namespaced */
    char *session_dir;      /* {workspace}/memory/_sessions/<ns>/ (namespaced only) */
    sc_memory_index_cb index_cb;
    void *index_ctx;
    int write_approval;     /* task 4.14: 1 = stage writes to pending/ */
} sc_memory_t;

/* Task 4.14: soft cap used for the system-prompt memory capacity header. */
#define SC_MEMORY_SOFT_MAX_BYTES 8192

/* Create/destroy */
sc_memory_t *sc_memory_new(const char *workspace);

/* Namespaced constructor for ephemeral sessions. The namespace_id must be
 * non-empty and contain only [A-Za-z0-9_-]; otherwise returns NULL. The
 * resulting store reads/writes only under the per-session directory and
 * never touches workspace-wide memory. */
sc_memory_t *sc_memory_new_namespaced(const char *workspace,
                                       const char *namespace_id);

void sc_memory_free(sc_memory_t *mem);

/* Long-term memory.
 * In namespaced mode read returns NULL and write is a no-op (returns 0). */
char *sc_memory_read_long_term(const sc_memory_t *mem);
/* Replace the whole MEMORY.md with `content` (caller supplies full file). */
int sc_memory_write_long_term(const sc_memory_t *mem, const char *content);
/* Append a single entry as a bullet to MEMORY.md (read-modify-write; never
 * overwrites existing content). Returns 0 on success, -1 on error, and 0 as a
 * silent no-op in namespaced/isolated mode. When write_approval is set, the
 * entry is staged to pending/ instead (see sc_memory_stage). Duplicate entries
 * (already present in MEMORY.md) are skipped as a success no-op. */
int sc_memory_append_long_term(const sc_memory_t *mem, const char *entry);

/* Task 4.14: staged writes + capacity + dedup. */

/* Enable/disable write-approval (staging) mode on this handle. */
void sc_memory_set_write_approval(sc_memory_t *mem, int enabled);

/* Stage `content` as a new pending entry under {memory_dir}/pending/. Returns 0
 * on success. Used internally when write_approval is on; also callable directly. */
int sc_memory_stage(const sc_memory_t *mem, const char *content);

/* Return a malloc'd path to the pending dir ({memory_dir}/pending), or NULL. */
char *sc_memory_pending_dir_dup(const sc_memory_t *mem);

/* Pure: 1 if `entry` (trimmed) already appears as a line in `existing`. */
int sc_memory_is_duplicate(const char *existing, const char *entry);

/* Pure: percent of `max` used by `used`, clamped to [0,100]; 0 when max <= 0. */
int sc_memory_capacity_pct(size_t used, size_t max);

/* Daily notes.
 * Namespaced mode writes to a single today.md per session (no date suffix). */
char *sc_memory_read_today(const sc_memory_t *mem);
int sc_memory_append_today(const sc_memory_t *mem, const char *content);

/* Get recent daily notes (last N days). Caller owns result.
 * In namespaced mode the session is ephemeral and has no historical depth,
 * so this returns today's content only (the `days` parameter is ignored). */
char *sc_memory_get_recent_notes(const sc_memory_t *mem, int days);

/* Build memory context for system prompt. Caller owns result.
 * In namespaced mode the long-term block is omitted entirely. */
char *sc_memory_get_context(const sc_memory_t *mem);

/* Set index update callback (called after write_long_term / append_today) */
void sc_memory_set_index_cb(sc_memory_t *mem, sc_memory_index_cb cb, void *ctx);

/* Remove namespaced session directories under {workspace}/memory/_sessions/
 * whose last_access timestamp is older than max_age_secs (or whose
 * last_access file is missing and dir mtime is older than max_age_secs).
 *
 * Safe to call from a periodic tick. Returns the count of session
 * directories removed, or -1 on failure to open the parent _sessions/ dir
 * (no _sessions/ at all returns 0, not -1). */
int sc_memory_cleanup_sessions(const char *workspace, int max_age_secs);

#endif /* SC_MEMORY_H */
