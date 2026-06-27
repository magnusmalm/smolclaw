#ifndef SC_CONSTANTS_LIMITS_H
#define SC_CONSTANTS_LIMITS_H

/* Default config values */
#define SC_DEFAULT_WORKSPACE    "~/.smolclaw/workspace"
#define SC_DEFAULT_MODEL        "claude-sonnet-4-5-20250929"
#define SC_DEFAULT_MAX_TOKENS   8192
#define SC_DEFAULT_CONTEXT_WINDOW 0  /* 0 = use provider default */
#define SC_DEFAULT_TEMPERATURE  0.7
#define SC_DEFAULT_MAX_ITERATIONS 20
#define SC_DEFAULT_HEARTBEAT_INTERVAL 30 /* minutes */
#define SC_DEFAULT_WEB_PORT 8080

/* Pairing */
#define SC_PAIRING_EXPIRY_MS   3600000   /* 1 hour */
#define SC_PAIRING_MAX_PENDING 3
#define SC_PAIRING_CODE_LEN    12

/* Background processes */
#define SC_BG_MAX_PROCS         8

/* Limits */
#define SC_MAX_OUTPUT_CHARS     10000
#define SC_MAX_FETCH_CHARS      50000
#define SC_MAX_SEARCH_RESULTS   5
#define SC_SESSION_SUMMARY_THRESHOLD 20
#define SC_SESSION_KEEP_LAST    4
#define SC_SUMMARY_MAX_TOKENS   256
#define SC_SUMMARY_MAX_TRANSCRIPT 4000
#define SC_CONSOLIDATION_MAX_TOKENS  256
#define SC_DEFAULT_EXEC_TIMEOUT 60 /* seconds, 0 = no timeout */

/* Per-turn resource limits */
#define SC_DEFAULT_MAX_TOOL_CALLS_PER_TURN 50
#define SC_DEFAULT_MAX_TURN_SECS           300  /* 5 minutes */
#define SC_DEFAULT_MAX_OUTPUT_TOTAL         500000  /* 500 KB cumulative tool output */
#define SC_DEFAULT_MAX_TOOL_RESULT_CHARS    50000   /* spill single result to disk above this */
#define SC_DEFAULT_TOOL_RESULT_PREVIEW_CHARS 2000   /* preview kept inline after spill */
#define SC_DEFAULT_MAX_TOOL_CALLS_PER_HOUR 200
#define SC_DEFAULT_MAX_TOKENS_PER_HOUR    0  /* 0 = unlimited */

/* Session-isolation maintenance (Phase 4):
 *   TTL: stale isolated session dirs older than this get reaped.
 *   TICK: how often the agent checks for staleness.
 * Both can be overridden per-agent for tests via sc_agent_t fields. */
#define SC_ISOLATION_TTL_SECS_DEFAULT          (24 * 60 * 60)   /* 24 hours */
#define SC_ISOLATION_CLEANUP_TICK_SECS_DEFAULT (60 * 60)        /* 1 hour */

/* Gateway rate limiting */
#define SC_DEFAULT_RATE_LIMIT_PER_MINUTE   20

/* File read limit */
#define SC_MAX_READ_FILE_SIZE  (10 * 1024 * 1024)  /* 10 MB */

/* Secret file reference limit */
#define SC_MAX_SECRET_FILE_SIZE  (4 * 1024)  /* 4 KB max for file-referenced secrets */

/* Audit log rotation */
#define SC_AUDIT_MAX_LOG_SIZE  (10 * 1024 * 1024)  /* 10 MB */

/* Spawn depth limit */
#define SC_MAX_SPAWN_DEPTH 3

/* Self-updater */
#define SC_DEFAULT_UPDATE_CHECK_HOURS  24
#define SC_UPDATE_MANIFEST_TIMEOUT     30    /* seconds */
#define SC_UPDATE_DOWNLOAD_TIMEOUT     600   /* seconds */
#define SC_UPDATE_MAX_BINARY_SIZE      (50 * 1024 * 1024)

#endif /* SC_CONSTANTS_LIMITS_H */
