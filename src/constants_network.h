#ifndef SC_CONSTANTS_NETWORK_H
#define SC_CONSTANTS_NETWORK_H

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

/* Curl response limits */
#define SC_CURL_MAX_RESPONSE  (50 * 1024 * 1024)  /* 50 MB general cap */
#define SC_SSE_MAX_LINE       (1 * 1024 * 1024)    /* 1 MB per SSE line */
#define SC_DOWNLOAD_MAX_SIZE  (25 * 1024 * 1024)    /* 25 MB for audio downloads */

/* LLM retry with backoff */
#define SC_LLM_MAX_RETRIES          3
#define SC_LLM_RETRY_INITIAL_MS  1000  /* 1 second */
#define SC_LLM_RETRY_MAX_MS     30000  /* 30 seconds */

/* Telegram reconnect backoff */
#define SC_TELEGRAM_RECONNECT_DELAY     5    /* initial backoff seconds */
#define SC_TELEGRAM_RECONNECT_MAX_DELAY 300  /* cap at 5 minutes */

/* X (Twitter) reconnect backoff */
#define SC_X_RECONNECT_DELAY     5    /* initial backoff seconds */
#define SC_X_RECONNECT_MAX_DELAY 300  /* cap at 5 minutes */

#endif /* SC_CONSTANTS_NETWORK_H */
