#ifndef SC_CONFIG_H
#define SC_CONFIG_H

#include "cJSON.h"
#include "sc_features.h"

/* Provider config (API key + base URL) */
typedef struct {
    char *api_key;
    char *api_base;
    char *proxy;
} sc_provider_config_t;

/* Automatic session-reset policy (task 3.7). mode matches
 * sc_session_reset_mode_t: 0 none, 1 daily, 2 idle, 3 both. */
typedef struct {
    int mode;
    int daily_reset_hour;   /* local hour [0,23], default 4 */
    int idle_minutes;       /* default 1440 (24h) */
} sc_session_reset_config_t;

#if SC_ENABLE_MOA
/* Mixture of Agents (MoA-lite) — task 2.13. See docs/design/mixture-of-agents.md */
#define SC_MOA_MAX_REFS    3
#define SC_MOA_MAX_PRESETS 8

typedef struct {
    char *provider;   /* e.g. "ollama", "openrouter", "anthropic" */
    char *model;      /* bare model name passed to that provider */
} sc_moa_slot_cfg_t;

typedef struct {
    char *name;
    int   enabled;                 /* default 1 */
    int   local_only;              /* default 0 — reject cloud slots */
    sc_moa_slot_cfg_t reference_models[SC_MOA_MAX_REFS];
    int   reference_count;
    sc_moa_slot_cfg_t aggregator;
    double reference_temperature;  /* default 0.6 */
    double aggregator_temperature; /* default 0 = inherit turn options */
    int   reference_max_tokens;    /* default 1024 */
    int   aggregator_max_tokens;   /* default 0 = inherit turn options */
} sc_moa_preset_cfg_t;

typedef struct {
    char *default_preset;
    sc_moa_preset_cfg_t presets[SC_MOA_MAX_PRESETS];
    int   preset_count;
} sc_moa_config_t;
#endif /* SC_ENABLE_MOA */

/* Telegram channel config */
typedef struct {
    int enabled;
    char *token;
    char *api_base;   /* default: "https://api.telegram.org" */
    char *proxy;
    char *dm_policy;
    char **allow_from;
    int allow_from_count;
    char **tools;           /* per-channel tool allowlist (NULL = all) */
    int tool_count;
} sc_telegram_config_t;

/* Discord channel config */
typedef struct {
    int enabled;
    char *token;
    char *api_base;   /* default: "https://discord.com/api/v10" */
    char *dm_policy;
    char **allow_from;
    int allow_from_count;
    char **tools;           /* per-channel tool allowlist (NULL = all) */
    int tool_count;
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
    char **tools;           /* per-channel tool allowlist (NULL = all) */
    int tool_count;
} sc_irc_config_t;

/* Slack channel config */
typedef struct {
    int enabled;
    char *bot_token;     /* xoxb-... for Web API */
    char *app_token;     /* xapp-... for Socket Mode WSS */
    char *dm_policy;
    char **allow_from;
    int allow_from_count;
    char **tools;           /* per-channel tool allowlist (NULL = all) */
    int tool_count;
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
    char **tools;              /* per-channel tool allowlist (NULL = all) */
    int tool_count;
} sc_x_config_t;

/* Signal channel config (task 3.1). Talks JSON-RPC to an external signal-cli
 * daemon — smolclaw does not implement the Signal protocol. The field is named
 * `signal_` in sc_config_t to avoid shadowing the libc signal() function. */
typedef struct {
    int enabled;
    char *account;          /* E.164 bot number, e.g. "+15551234567" */
    char *http_host;        /* daemon host, default "127.0.0.1" */
    int http_port;          /* daemon port, default 7583 */
    char *http_url;         /* full base URL override (wins over host/port) */
    char *proxy;
    char *group_trigger;    /* substring that must appear to act in groups */
    char *dm_policy;
    char **allow_from;
    int allow_from_count;
    char **tools;           /* per-channel tool allowlist (NULL = all) */
    int tool_count;
} sc_signal_config_t;

#if SC_ENABLE_COMPANION
/* Scoped companion bearer (defense-in-depth; see companion/auth.h). */
typedef struct {
    char *token;
    char **scopes;
    int scope_count;
} sc_companion_token_entry_t;
#endif

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
    char **tools;           /* per-channel tool allowlist (NULL = all) */
    int tool_count;
    /* Per-request server-side timeout (seconds) for /api/message.
     * 0 = derive from agents.defaults.max_turn_secs (+30s grace);
     * if max_turn_secs is also unset, falls back to a legacy 600s constant.
     * Must be >= max_turn_secs or the HTTP request will 504 mid-turn. */
    int request_timeout_secs;
    /* Session-isolation glob (Phase 4). If a request's `session` field
     * matches this pattern, the inbound message is marked isolated and
     * the agent runs it in a per-session memory namespace. NULL or empty
     * disables isolation. Default in config.c initialization: "wf-*"
     * (a common orchestrator delegate convention). See
     * docs/design/session-isolation-plan.md §6.4-§6.5. */
    char *isolation_pattern;
    /* Optional live-stream URL (e.g. a motion-daemon MJPEG stream).
     * If set, the embedded chat UI shows a "live view" toggle that
     * embeds this URL. The channel is agnostic about what it points
     * at; auth/exposure of the stream is the operator's concern. */
    char *embed_stream_url;
#if SC_ENABLE_COMPANION
    sc_companion_token_entry_t *companion_tokens;
    int companion_token_count;
#endif
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

/* MCP server capabilities — fine-grained sandbox per-server.
 * If fs_read_count > 0 or fs_write_count > 0, replaces the blanket
 * workspace sandbox with per-path rules. NULL/0 = default sandbox. */
typedef struct {
    char **fs_read;       /* paths with read-only access */
    int    fs_read_count;
    char **fs_write;      /* paths with read-write access */
    int    fs_write_count;
    int    no_process;    /* 1 = block execve/fork/clone in seccomp */
    int    no_network;    /* 1 = block socket/connect in seccomp */
    int    no_sandbox;    /* 1 = run the server with NO Landlock/seccomp at all
                           * (capabilities.sandbox=false). Explicit opt-in for
                           * trusted servers — e.g. npx/node packages whose
                           * multi-process startup the sandbox cannot host. */
} sc_mcp_capabilities_t;

/* MCP server config */
typedef struct {
    char *name;
    char **command;       /* argv array */
    int command_count;
    char **env_keys;
    char **env_values;
    int env_count;
    sc_mcp_capabilities_t caps;
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

/* Delegation target config */
typedef struct {
    char *name;           /* "researcher" */
    char *url;            /* "http://192.0.2.10:8082/api/message" */
    char *bearer_token;   /* supports vault:// */
    int   timeout_secs;   /* default 120 */
} sc_delegate_target_t;

/* Delegation config */
typedef struct {
    sc_delegate_target_t *targets;
    int target_count;
} sc_delegation_config_t;

/* Main config struct */
typedef struct {
    /* Agent defaults */
    char *workspace;
    int restrict_to_workspace;
    int workspace_per_session;   /* Create per-session subdirs under workspace/tasks/ */
    char *provider;
    char *model;
    char *summary_model;       /* model for summarization (NULL = use primary) */
    char **fallback_models;
    int fallback_model_count;
    int max_tokens;
    int context_window;        /* provider context window (e.g. Ollama num_ctx), 0 = default */
    double temperature;
    cJSON *response_format;    /* structured output schema (NULL = disabled) */
    int max_tool_iterations;
    int session_summary_threshold;
    int session_keep_last;
    /* Task 4.4: context transform that compresses old tool results to a
     * metadata placeholder before the LLM call. Defaults preserve the prior
     * hardcoded behavior; set compress_tool_results=0 to disable. */
    int compress_tool_results;   /* 1 = on (default), 0 = off */
    int compress_keep_recent;    /* keep this many most-recent messages verbatim */
    int compress_min_bytes;      /* only compress tool results larger than this */
    /* Task 4.7: `smolclaw context` warns when estimated prompt tokens reach
     * this percent of the model context window (0 = never warn). */
    int context_warn_pct;
    /* Task 4.12: minimum seconds between agent-initiated `compact` tool calls
     * (0 = no cooldown). Default 300 (5 min). */
    int compact_cooldown_secs;
    int max_output_chars;
    int max_tool_result_chars;     /* spill a single tool result to disk above this (0 = default) */
    int tool_result_preview_chars; /* preview kept inline after spill */
    int tool_selection;            /* 0 = fixed (all tools), 1 = auto (keyword heuristic) */
    int warmup;                    /* prompt-prefix warmup for local providers (default 0) */
    char **warmup_providers;       /* provider names eligible for warmup (default ollama, vllm) */
    int warmup_provider_count;
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
    int max_tokens_per_hour;  /* 0 = unlimited */

    /* Gateway rate limiting */
    int rate_limit_per_minute;

    /* Automatic session reset (task 3.7) */
    sc_session_reset_config_t session_reset;

    /* Busy-input mode (task 3.8): 0 = interrupt (sequential, default),
     * 1 = queue (coalesce a burst of same-chat messages into one turn). */
    int busy_input_mode;

    /* Silent delivery tokens (task 3.9): when 1 (default), a final response
     * that is exactly a silence token ([SILENT]/SILENT/NO_REPLY/NO REPLY,
     * trimmed + case-folded) suppresses outbound delivery; the turn is still
     * stored in the transcript. 0 disables (deliver the literal token). */
    int silent_tokens_enabled;

    /* Security */
    char **allowed_tools;
    int allowed_tool_count;
    int restrict_message_tool;

    /* Exec security: allowlist mode */
    int exec_use_allowlist;          /* 0 = denylist (default), 1 = allowlist */
    char **exec_allowed_commands;    /* e.g., ["ls", "cat", "grep", ...] */
    int exec_allowed_command_count;

    /* Network scope for outbound tool requests (SC_NET_SCOPE_*) */
    int network_scope;           /* 0=none, 1=local, 2=public (default), 3=any */

    /* OS-level sandbox for exec children (Landlock + seccomp-bpf) */
    int sandbox_enabled;

    /* Tee-on-truncation: save full output to disk when truncated */
    int tee_enabled;           /* default 1 */
    int tee_max_files;         /* default 50 */
    int tee_max_file_size;     /* default 10*1024*1024 */

    /* Pricing overrides: {"model": {"prompt": rate, "completion": rate}} ($/M tokens).
     * Borrowed pointer from parsed config JSON, not owned. */
    struct cJSON *pricing_overrides;

    /* Persistent log file (NULL = stderr only) */
    char *log_path;

    /* Auto-extract facts from session summaries into daily notes */
    int memory_consolidation;

    /* Task 4.13: post-turn memory review (opt-in, default off). */
    int memory_background_review;
    char *memory_review_model;   /* optional cheaper model override (NULL = summary/main) */
    int memory_notifications;    /* 0 off, 1 on, 2 verbose */

    /* Task 4.14: stage memory writes to pending/ for approval (default off). */
    int memory_write_approval;

    /* Send version/feature info to channels on join */
    int announce_on_join;

    /* Send progress updates (LLM calls, tool calls) to the channel */
    int verbose;

    /* Auto-approve tool confirmations (for headless/autonomous operation) */
    int auto_confirm;

    /* Allow channel dm_policy=open with empty allow_from (lab only; default 0).
     * Without this, open+empty channels are not started (SML-001). */
    int accept_open_dms;

    /* Gateway only: allow exec/exec_background without exec allowlist (lab only).
     * Default 0 — gateway refuses to start when exec tools are available unless
     * exec_mode=allowlist with non-empty exec_allowed_commands (SML-002). */
    int allow_unrestricted_exec;

    /* Tool confirmation policy (task 3.3): sc_approval_policy_t —
     * 0 dangerous-only (default), 1 always, 2 never. */
    int approval_policy;

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

    /* Custom/named providers (for non-builtin names like "ollama-cloud") */
    struct {
        char *name;
        sc_provider_config_t config;
    } custom_providers[8];
    int custom_provider_count;

#if SC_ENABLE_MOA
    sc_moa_config_t moa;
#endif

    /* Channels */
    sc_telegram_config_t telegram;
    sc_discord_config_t discord;
    sc_irc_config_t irc;
    sc_slack_config_t slack;
    sc_web_config_t web;
    sc_x_config_t x;
    sc_signal_config_t signal_;

    /* Tools */
    sc_web_tools_config_t web_tools;

    /* Git tool settings */
    struct {
        char **push_allowed_remotes;  /* URL substrings for push allowlist */
        int push_allowed_remote_count;
    } git;

    /* Gitea */
    struct {
        char *url;          /* Base URL, e.g. "https://gitea.example.com" */
        char *token;        /* API token (vault:// supported) */
        char *default_org;  /* Default org for repo creation */
    } gitea;

    /* Camera tool */
    struct {
        char *snap_command;  /* argv prefix; output path appended */
        char *events_dir;    /* motion captures dir, workspace-relative */
        char *vision_url;    /* ollama-compatible vision endpoint */
        char *vision_model;  /* e.g. "gemma4:e4b" */
        int   vision_timeout_secs;  /* default 120 */
    } camera;

    /* Heartbeat */
    sc_heartbeat_config_t heartbeat;

    /* MCP */
    sc_mcp_config_t mcp;

    /* Updater */
    sc_updater_config_t updater;

    /* Delegation */
    sc_delegation_config_t delegation;

    /* Notifications (Apprise-compatible URLs) */
    char *notify_urls;  /* comma-separated, e.g. "discord://id/tok,tg://bot/chat" */

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

/* Apply an operator-mode preset (task 3.2): sets approval_policy and clamps
 * max_tool_iterations for "explore"/"edit"/"review"/"ship". "custom", NULL, or
 * an unknown mode is a no-op (explicit config preserved). Pure / testable. */
void sc_config_apply_operator_mode(sc_config_t *cfg, const char *mode);

/* Get config file path (~/.smolclaw/config.json) */
char *sc_config_get_path(void);

/* Free config */
void sc_config_free(sc_config_t *cfg);

#if SC_ENABLE_VAULT
/* Collect vault:// reference key names from raw config JSON.
 * Returns count of keys found. Sets *keys to malloc'd array of strings.
 * Caller owns the array and its strings. Returns 0 if none found. */
int sc_config_collect_vault_keys(const sc_config_t *cfg, char ***keys);
#endif

#endif /* SC_CONFIG_H */
