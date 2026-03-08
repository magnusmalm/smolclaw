#ifndef SC_CONFIG_H
#define SC_CONFIG_H

#include "cJSON.h"

/* Provider config (API key + base URL) */
typedef struct {
    char *api_key;
    char *api_base;
    char *proxy;
} sc_provider_config_t;

/* Telegram channel config */
typedef struct {
    int enabled;
    char *token;
    char *api_base;   /* default: "https://api.telegram.org" */
    char *proxy;
    char *dm_policy;
    char **allow_from;
    int allow_from_count;
} sc_telegram_config_t;

/* Discord channel config */
typedef struct {
    int enabled;
    char *token;
    char *api_base;   /* default: "https://discord.com/api/v10" */
    char *dm_policy;
    char **allow_from;
    int allow_from_count;
} sc_discord_config_t;

/* IRC channel config */
typedef struct {
    int enabled;
    char *hostname;
    int port;              /* default 6667, or 6697 for TLS */
    char *nick;
    char *username;        /* IRC USER field, defaults to nick */
    char *password;        /* PASS or NickServ password, optional */
    char **join_channels;  /* channels to auto-join */
    int join_channel_count;
    int use_tls;
    char *group_trigger;   /* shared trigger word (e.g. "claws"), optional */
    char *dm_policy;
    char **allow_from;
    int allow_from_count;
} sc_irc_config_t;

/* Slack channel config */
typedef struct {
    int enabled;
    char *bot_token;     /* xoxb-... for Web API */
    char *app_token;     /* xapp-... for Socket Mode WSS */
    char *dm_policy;
    char **allow_from;
    int allow_from_count;
} sc_slack_config_t;

/* X (Twitter) channel config */
typedef struct {
    int enabled;
    char *consumer_key;        /* OAuth 1.0a API Key */
    char *consumer_secret;     /* OAuth 1.0a API Key Secret */
    char *access_token;        /* OAuth 1.0a Access Token */
    char *access_token_secret; /* OAuth 1.0a Access Token Secret */
    char *api_base;            /* default: "https://api.x.com" (override for testing) */
    char *dm_policy;
    char **allow_from;
    int allow_from_count;
    int poll_interval_sec;     /* default: 60 */
    int enable_dms;            /* default: 0 (DMs require Pro tier) */
    int read_only;             /* default: 1 — poll only, block all outbound */
} sc_x_config_t;

/* Web channel config */
typedef struct {
    int enabled;
    char *bind_addr;       /* default "127.0.0.1" */
    int port;              /* default 8080 */
    int auto_port;         /* try next ports on bind failure */
    char *bearer_token;    /* required for API auth */
    char *tls_cert;        /* PEM certificate path (enables HTTPS) */
    char *tls_key;         /* PEM private key path */
    char *dm_policy;
    char **allow_from;
    int allow_from_count;
} sc_web_config_t;

/* Web tools config */
typedef struct {
    int brave_enabled;
    char *brave_api_key;
    char *brave_base_url;      /* default: "https://api.search.brave.com" */
    int brave_max_results;
    int searxng_enabled;
    char *searxng_base_url;
    int searxng_max_results;
    int duckduckgo_enabled;
    int duckduckgo_max_results;
} sc_web_tools_config_t;

/* Heartbeat config */
typedef struct {
    int enabled;
    int interval; /* minutes */
} sc_heartbeat_config_t;

/* MCP server config */
typedef struct {
    char *name;
    char **command;       /* argv array */
    int command_count;
    char **env_keys;
    char **env_values;
    int env_count;
} sc_mcp_server_config_t;

/* MCP config */
typedef struct {
    int enabled;
    sc_mcp_server_config_t *servers;
    int server_count;
} sc_mcp_config_t;

/* Updater config */
typedef struct {
    int enabled;
    char *manifest_url;
    int check_interval_hours;  /* 0 = manual only, default 24 */
    int auto_apply;            /* default 0 */
} sc_updater_config_t;

/* Main config struct */
typedef struct {
    /* Agent defaults */
    char *workspace;
    int restrict_to_workspace;
    char *provider;
    char *model;
    char **fallback_models;
    int fallback_model_count;
    int max_tokens;
    double temperature;
    int max_tool_iterations;
    int session_summary_threshold;
    int session_keep_last;
    int max_output_chars;
    int max_fetch_chars;
    int max_background_procs;
    int summary_max_transcript;
    int exec_timeout_secs;

    /* Per-turn resource limits */
    int max_tool_calls_per_turn;
    int max_turn_secs;
    int max_output_total;

    /* Cross-turn rate limiting */
    int max_tool_calls_per_hour;

    /* Gateway rate limiting */
    int rate_limit_per_minute;

    /* Security */
    char **allowed_tools;
    int allowed_tool_count;
    int restrict_message_tool;

    /* Exec security: allowlist mode */
    int exec_use_allowlist;          /* 0 = denylist (default), 1 = allowlist */
    char **exec_allowed_commands;    /* e.g., ["ls", "cat", "grep", ...] */
    int exec_allowed_command_count;

    /* OS-level sandbox for exec children (Landlock + seccomp-bpf) */
    int sandbox_enabled;

    /* Tee-on-truncation: save full output to disk when truncated */
    int tee_enabled;           /* default 1 */
    int tee_max_files;         /* default 50 */
    int tee_max_file_size;     /* default 10*1024*1024 */

    /* Persistent log file (NULL = stderr only) */
    char *log_path;

    /* Auto-extract facts from session summaries into daily notes */
    int memory_consolidation;

    /* Model aliases for in-prompt override */
    char **model_alias_names;
    char **model_alias_models;
    int model_alias_count;

    /* Providers */
    sc_provider_config_t anthropic;
    sc_provider_config_t openai;
    sc_provider_config_t openrouter;
    sc_provider_config_t groq;
    sc_provider_config_t zhipu;
    sc_provider_config_t vllm;
    sc_provider_config_t gemini;
    sc_provider_config_t deepseek;
    sc_provider_config_t ollama;
    sc_provider_config_t xai;

    /* Channels */
    sc_telegram_config_t telegram;
    sc_discord_config_t discord;
    sc_irc_config_t irc;
    sc_slack_config_t slack;
    sc_web_config_t web;
    sc_x_config_t x;

    /* Tools */
    sc_web_tools_config_t web_tools;

    /* Heartbeat */
    sc_heartbeat_config_t heartbeat;

    /* MCP */
    sc_mcp_config_t mcp;

    /* Updater */
    sc_updater_config_t updater;

    /* Raw JSON for round-trip preservation */
    cJSON *raw;
} sc_config_t;

/* Create default config */
sc_config_t *sc_config_default(void);

/* Load config from JSON file + env var overrides. Returns NULL on error. */
sc_config_t *sc_config_load(const char *path);

/* Save config to JSON file. Returns 0 on success. */
int sc_config_save(const char *path, const sc_config_t *cfg);

/* Get resolved workspace path (with ~ expanded) */
char *sc_config_workspace_path(const sc_config_t *cfg);

/* Get config file path (~/.smolclaw/config.json) */
char *sc_config_get_path(void);

/* Free config */
void sc_config_free(sc_config_t *cfg);

#endif /* SC_CONFIG_H */
