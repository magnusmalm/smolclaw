#ifndef SC_CONSTANTS_H
#define SC_CONSTANTS_H

#include <string.h>

#include "sc_version.h"
#define SC_NAME    "smolclaw"
#define SC_LOGO    "\xF0\x9F\xA6\x9E" /* lobster emoji */

/* Channel name constants */
#define SC_CHANNEL_CLI      "cli"
#define SC_CHANNEL_TELEGRAM "telegram"
#define SC_CHANNEL_DISCORD  "discord"
#define SC_CHANNEL_IRC      "irc"
#define SC_CHANNEL_SLACK    "slack"
#define SC_CHANNEL_WEB      "web"
#define SC_CHANNEL_SYSTEM   "system"

/* Internal channels that don't route to external users */
static inline int sc_is_internal_channel(const char *channel) {
    if (!channel) return 1;
    return (strcmp(channel, SC_CHANNEL_CLI) == 0 ||
            strcmp(channel, SC_CHANNEL_SYSTEM) == 0);
}

/* Default config values */
#define SC_DEFAULT_WORKSPACE    "~/.smolclaw/workspace"
#define SC_DEFAULT_MODEL        "claude-sonnet-4-5-20250929"
#define SC_DEFAULT_MAX_TOKENS   8192
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
#define SC_DEFAULT_MAX_TOOL_CALLS_PER_HOUR 200

/* Gateway rate limiting */
#define SC_DEFAULT_RATE_LIMIT_PER_MINUTE   20

/* MCP (Model Context Protocol) */
#define SC_MCP_INIT_TIMEOUT_MS   5000
#define SC_MCP_CALL_TIMEOUT_MS   30000
#define SC_MCP_SHUTDOWN_WAIT_MS  2000
#define SC_MCP_PROTOCOL_VERSION  "2024-11-05"
#define SC_MCP_MAX_RESPONSE_SIZE (10 * 1024 * 1024)  /* 10 MB */

/* WebSocket */
#define SC_WS_MAX_PAYLOAD        (16 * 1024 * 1024)  /* 16 MB */

/* Web fetch */
#define SC_WEB_MAX_REDIRECTS     5
#define SC_WEB_FETCH_RETRIES     2  /* retry once on transient failure */
#define SC_WEB_FETCH_RETRY_DELAY 1  /* seconds between retries */

/* Graceful shutdown — strong definition in main.c, weak fallback in logger.c */
int sc_shutdown_requested(void);

/* Curl response limits */
#define SC_CURL_MAX_RESPONSE  (50 * 1024 * 1024)  /* 50 MB general cap */
#define SC_SSE_MAX_LINE       (1 * 1024 * 1024)    /* 1 MB per SSE line */
#define SC_DOWNLOAD_MAX_SIZE  (25 * 1024 * 1024)    /* 25 MB for audio downloads */

/* File read limit */
#define SC_MAX_READ_FILE_SIZE  (10 * 1024 * 1024)  /* 10 MB */

/* Secret file reference limit */
#define SC_MAX_SECRET_FILE_SIZE  (4 * 1024)  /* 4 KB max for file-referenced secrets */

/* LLM retry with backoff */
#define SC_LLM_MAX_RETRIES          3
#define SC_LLM_RETRY_INITIAL_MS  1000  /* 1 second */
#define SC_LLM_RETRY_MAX_MS     30000  /* 30 seconds */

/* Telegram reconnect backoff */
#define SC_TELEGRAM_RECONNECT_DELAY     5    /* initial backoff seconds */
#define SC_TELEGRAM_RECONNECT_MAX_DELAY 300  /* cap at 5 minutes */

/* Spawn depth limit */
#define SC_MAX_SPAWN_DEPTH 3

/* Self-updater */
#define SC_DEFAULT_UPDATE_CHECK_HOURS  24
#define SC_UPDATE_MANIFEST_TIMEOUT     30    /* seconds */
#define SC_UPDATE_DOWNLOAD_TIMEOUT     600   /* seconds */
#define SC_UPDATE_MAX_BINARY_SIZE      (50 * 1024 * 1024)

#endif /* SC_CONSTANTS_H */
