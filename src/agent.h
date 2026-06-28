#ifndef SC_AGENT_H
#define SC_AGENT_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include "bus.h"
#include "skill.h"
#include "util/arena.h"
#include "util/task.h"
#include "config.h"
#include "context.h"
#include "session.h"
#include "state.h"
#include "tools/registry.h"
#include "providers/types.h"

typedef struct sc_mcp_bridge sc_mcp_bridge_t;

/* Per-channel tool allowlist entry */
#define SC_MAX_CHANNEL_TOOL_ENTRIES 8
typedef struct {
    char *channel;          /* channel name (e.g. "irc", "web") */
    char **tools;           /* tool name list (NULL = all) */
    int tool_count;
} sc_channel_tools_t;

typedef struct sc_agent {
    sc_bus_t *bus;
    sc_provider_t *provider;
    char *workspace;
    char *model;
    char *summary_model;        /* model for summarization (NULL = use primary) */
    int max_tokens;             /* max output tokens per LLM call */
    int context_window;
    int provider_ctx_window;   /* provider-level context window (e.g. Ollama num_ctx), 0 = default */
    double temperature;
    cJSON *response_format;     /* structured output schema (NULL = disabled) */
    int max_iterations;
    int session_summary_threshold;
    int session_keep_last;
    /* Task 4.4: old-tool-result compression transform (configurable). */
    int compress_tool_results;
    int compress_keep_recent;
    int compress_min_bytes;
    /* Task 4.12: agent-initiated compact tool. active_session_key is the
     * borrowed session key of the in-flight turn (set by run_agent_loop) so the
     * tool can target it; last_compact_time + compact_cooldown_secs rate-limit
     * agent-requested compactions. */
    const char *active_session_key;
    long last_compact_time;
    int compact_cooldown_secs;
    /* Task 4.13: post-turn memory review (opt-in, default off). */
    int memory_background_review;
    char *memory_review_model;      /* optional cheaper model; NULL = summary/main */
    int memory_notifications;       /* 0 off, 1 on, 2 verbose */
    sc_task_t *review_task;         /* in-flight async review, or NULL */
    int memory_write_approval;      /* task 4.14: stage memory writes to pending/ */
    /* Automatic session reset policy (task 3.7) */
    int session_reset_mode;        /* sc_session_reset_mode_t */
    int session_reset_daily_hour;
    int session_reset_idle_min;
    /* Busy-input mode (task 3.8): 0 interrupt (default), 1 queue */
    int busy_input_mode;
    /* Silent delivery tokens (task 3.9): 1 = suppress silence-token replies */
    int silent_tokens_enabled;
    int max_output_chars;
    int max_fetch_chars;
    int tool_selection;         /* 0 = fixed (all tools), 1 = auto (keyword heuristic) */
    int warmup;                 /* prompt-prefix warmup for local providers (default 0) */
    char **warmup_providers;    /* provider names eligible for warmup (owned) */
    int warmup_provider_count;
    uint32_t last_warmup_fingerprint;  /* skip warmup if (provider+model+sys+tools) unchanged */
    int max_background_procs;
    int summary_max_transcript;
    int exec_timeout_secs;
    int max_tool_calls_per_turn;
    int max_turn_secs;
    int max_output_total;
    int max_tool_calls_per_hour;
    int max_tokens_per_hour;
    int memory_consolidation;
    int workspace_per_session;
    int verbose;
    sc_session_manager_t *sessions;
    sc_state_t *state;
    sc_context_builder_t *context_builder;
    sc_tool_registry_t *tools;
    volatile int running;
    sc_stream_cb stream_cb;   /* Optional: called with text deltas during LLM response */
    void *stream_ctx;
    sc_provider_t **fallback_providers;
    char **fallback_models;
    int fallback_count;
    /* In-prompt model override aliases */
    sc_provider_t **alias_providers;
    char **alias_names;
    char **alias_models;
    int alias_count;
    /* Per-channel tool allowlists */
    sc_channel_tools_t channel_tools[SC_MAX_CHANNEL_TOOL_ENTRIES];
    int channel_tools_count;
    /* MCP bridge (external tool servers) */
    sc_mcp_bridge_t *mcp_bridge;
    /* Memory search index (owned, NULL when SC_ENABLE_MEMORY_SEARCH is off) */
    void *memory_index;
    /* Cost tracking (owned, NULL if workspace unavailable) */
    void *cost_tracker;
    /* Tee config (owned, NULL when SC_ENABLE_TEE is off) */
    void *tee_cfg;
    /* Analytics (owned, NULL when SC_ENABLE_ANALYTICS is off) */
    void *analytics;
    /* Cross-turn hourly rate tracking (defined in agent_internal.h) */
    void *hourly_slots;
    /* Async summarization task (NULL when idle) */
    sc_task_t *summarize_task;
    /* Per-turn arena allocator (reset between turns) */
    sc_arena_t *arena;
    /* Compaction circuit breaker: disable after consecutive failures */
    int compact_consecutive_failures;
    /* Skills registry (user-defined prompt templates) */
    sc_skill_registry_t *skills;
    /* Context transform chain (invoked between context build and LLM call) */
    sc_context_transform_t *transforms;
    int transform_count;
    int transform_cap;
    /* Phase 4 isolation maintenance: epoch of the last sc_memory_cleanup_sessions
     * tick. Checked on every inbound message; if more than
     * isolation_cleanup_tick_secs has elapsed, the cleanup runs and this is
     * refreshed. Both fields default to 0 (cleanup runs on first message after
     * agent start). isolation_cleanup_tick_secs / isolation_ttl_secs can be
     * overridden by tests; the production defaults are
     * SC_ISOLATION_CLEANUP_TICK_SECS_DEFAULT and SC_ISOLATION_TTL_SECS_DEFAULT
     * (constants_limits.h). */
    time_t last_isolation_cleanup;
    int isolation_cleanup_tick_secs;
    int isolation_ttl_secs;
} sc_agent_t;

/* Create agent loop */
sc_agent_t *sc_agent_new(sc_config_t *cfg, sc_bus_t *bus, sc_provider_t *provider);
void sc_agent_free(sc_agent_t *agent);

/* Run agent loop (blocks, processes inbound messages) */
int sc_agent_run(sc_agent_t *agent);
void sc_agent_stop(sc_agent_t *agent);

/* Direct message processing (for CLI mode) */
char *sc_agent_process_direct(sc_agent_t *agent, const char *content,
                               const char *session_key);

/* Channel message processing (for gateway mode — preserves channel/chat_id) */
char *sc_agent_process_channel(sc_agent_t *agent, const char *content,
                                const char *session_key,
                                const char *channel, const char *chat_id);

/* Heartbeat processing (no session history) */
char *sc_agent_process_heartbeat(sc_agent_t *agent, const char *content,
                                  const char *channel, const char *chat_id);

/* Isolated session processing (Phase 4). Runs the message in an ephemeral
 * memory namespace keyed by namespace_id, so per-session consolidation
 * and post-compact scratchpad never touch the agent's shared workspace
 * memory. See docs/design/session-isolation-plan.md. namespace_id must
 * be non-empty [A-Za-z0-9_-]; otherwise the call falls back to shared
 * behavior with a logged warning. */
char *sc_agent_process_isolated(sc_agent_t *agent, const char *content,
                                 const char *session_key,
                                 const char *channel, const char *chat_id,
                                 const char *namespace_id);

/* Register additional tool */
void sc_agent_register_tool(sc_agent_t *agent, sc_tool_t *tool);

/* Parse "Use <alias>: <msg>" or "@<alias> <msg>" prefix from user content.
 * Returns alias name or NULL. Sets *rest to the message after the prefix. */
char *sc_parse_model_override(const char *content, const char **rest);

/* Enable streaming: agent will call stream_cb with text deltas during LLM calls */
void sc_agent_set_stream_cb(sc_agent_t *agent, sc_stream_cb cb, void *ctx);

/* Wait for any pending async summarization to complete */
void sc_agent_wait_summarize(sc_agent_t *agent);

/* Register a context transform hook.
 * Transforms are invoked in registration order between context building
 * and the LLM call. name is borrowed (not copied). */
void sc_agent_add_transform(sc_agent_t *agent, const char *name,
                             sc_context_transform_fn fn, void *userdata);

/* Task 4.4: pure decision for the old-tool-result compression transform.
 * Returns 1 iff the message at `index` (of `count` total) is old enough
 * (index < count - keep_recent) and its tool-result content is larger than
 * `min_bytes`. Pure — unit-tested in test_agent.c. */
int sc_mask_should_compress(int index, int count, int keep_recent,
                            size_t len, int min_bytes);

/* Task 4.12: force-compact a session now (same path as the /compress slash
 * command): lower the summary threshold for one call so summarization fires
 * regardless of size, then restore it. Returns 0 if compaction was scheduled,
 * -1 if the session is already at/below keep_last (nothing to compact). */
int sc_agent_compact_session(sc_agent_t *agent, const char *session_key);

/* Pure cooldown decision for the agent-initiated compact tool: returns 1 if a
 * compaction is allowed at `now` given the `last` compaction time and the
 * `cooldown_secs` minimum interval. A non-positive `last` (never compacted) or
 * `cooldown_secs <= 0` always allows. Unit-tested. */
int sc_compact_cooldown_ok(long now, long last, int cooldown_secs);

/* Hot-reload safe config fields (limits, allowlist, rate limits) */
void sc_agent_reload_config(sc_agent_t *agent, const sc_config_t *cfg);

/* Register standalone tools (no agent dependency) into a registry.
 * Used by MCP server mode for headless tool exposure. */
void sc_register_tools_standalone(sc_tool_registry_t *reg, sc_config_t *cfg,
                                   const char *workspace);

/* Names of the read-only tools an external MCP client may use by default
 * (no write/exec/escalation). Returns a static, NULL-free array; *count is
 * set. Used to lock down `mcp-server` unless the operator opts out. */
const char **sc_tools_readonly_names(int *count);

#endif /* SC_AGENT_H */
