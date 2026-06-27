#ifndef SC_SESSION_MAINT_H
#define SC_SESSION_MAINT_H

#include <stddef.h>

/*
 * Session maintenance helpers backing the `smolclaw session compact|prune`
 * CLI subcommands. These operate directly on the on-disk JSONL session files
 * (storage format documented in session.h) rather than the in-memory manager,
 * so they can run as one-shot maintenance commands without loading the agent.
 */

/* Default oversized-field threshold for `session compact` (bytes). */
#define SC_COMPACT_DEFAULT_MAX 4096

/* Compact one session JSONL file: truncate oversized tool-result `content`
 * fields, keeping head + tail + a "...[truncated N bytes]..." marker.
 * Atomic: writes to a temp file, validates it re-parses as a session
 * (header + valid JSON lines), copies the original to "<path>.bak", then
 * renames the temp over the original.
 *
 * The full tool output remains in the workspace audit log, so trimming the
 * session file is non-lossy from an observability standpoint.
 *
 * out_fields / out_saved_bytes (optional) receive the number of fields
 * truncated and the total bytes removed.
 *
 * Returns 0 if the file was compacted, 1 if nothing needed truncating (file
 * left untouched, no .bak written), -1 on error (original left intact). */
int sc_session_compact_file(const char *path, size_t max_field_bytes,
                            int *out_fields, long *out_saved_bytes);

/* Return a malloc'd array of malloc'd file paths for the sessions beyond the
 * newest `keep` (ranked by mtime, newest first) — i.e. the prune candidates.
 * *out_count is set to the number returned (0 → returns NULL). Caller frees
 * each element and the array. */
char **sc_session_prune_candidates(const char *sessions_dir, int keep,
                                   int *out_count);

/* Acquire an exclusive advisory run-lock on "<workspace>/.gateway.lock"
 * (created if absent). Returns the held fd — keep it open for the gateway's
 * lifetime; closing it (or process exit) releases the lock. Returns -1 on
 * failure (the caller should continue without the lock). */
int sc_gateway_lock_acquire(const char *workspace);

/* Non-destructive probe: returns 1 if some process currently holds the
 * gateway run-lock for `workspace`, 0 otherwise. */
int sc_gateway_is_running(const char *workspace);

#endif /* SC_SESSION_MAINT_H */
