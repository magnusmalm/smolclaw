#ifndef SC_AGENT_H
#define SC_AGENT_H

#include <pthread.h>
#include <stdatomic.h>
#include "bus.h"
#include "config.h"
#include "context.h"
#include "session.h"
#include "state.h"
#include "tools/registry.h"
#include "providers/types.h"

typedef struct sc_mcp_bridge sc_mcp_bridge_t;

typedef struct sc_agent {
    sc_bus_t *bus;
    sc_provider_t *provider;
    char *workspace;
    char *model;
    int context_window;
    double temperature;
    int max_iterations;
    int session_summary_threshold;
    int session_keep_last;
    int max_output_chars;
    int max_fetch_chars;
    int max_background_procs;
    int summary_max_transcript;
    int exec_timeout_secs;
    int max_tool_calls_per_turn;
    int max_turn_secs;
    int max_output_total;
    int max_tool_calls_per_hour;
    int memory_consolidation;
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
    /* Async summarization thread */
    pthread_t summarize_thread;
    atomic_int summarize_thread_active;
    void *summarize_pending_args;  /* sc_summarize_args_t *, written by thread */
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

/* Register additional tool */
void sc_agent_register_tool(sc_agent_t *agent, sc_tool_t *tool);

/* Parse "Use <alias>: <msg>" or "@<alias> <msg>" prefix from user content.
 * Returns alias name or NULL. Sets *rest to the message after the prefix. */
char *sc_parse_model_override(const char *content, const char **rest);

/* Enable streaming: agent will call stream_cb with text deltas during LLM calls */
void sc_agent_set_stream_cb(sc_agent_t *agent, sc_stream_cb cb, void *ctx);

/* Wait for any pending async summarization to complete */
void sc_agent_wait_summarize(sc_agent_t *agent);

/* Hot-reload safe config fields (limits, allowlist, rate limits) */
void sc_agent_reload_config(sc_agent_t *agent, const sc_config_t *cfg);

/* Register standalone tools (no agent dependency) into a registry.
 * Used by MCP server mode for headless tool exposure. */
void sc_register_tools_standalone(sc_tool_registry_t *reg, sc_config_t *cfg,
                                   const char *workspace);

#endif /* SC_AGENT_H */
