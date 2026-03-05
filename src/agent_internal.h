/*
 * agent_internal.h - Shared types and functions across agent_*.c files
 *
 * Not part of the public API. Only included by agent.c, agent_turn.c,
 * and agent_session.c.
 */

#ifndef SC_AGENT_INTERNAL_H
#define SC_AGENT_INTERNAL_H

#include "agent.h"
#include "providers/types.h"
#include "tools/registry.h"

#include <stdint.h>
#include <time.h>

/* ---------- Turn context ---------- */

#define SC_MAX_RECENT_CALLS 10
typedef struct { uint32_t hash; int count; } sc_recent_call_t;

/* Per-turn mutable state shared across LLM iteration helpers */
typedef struct {
    const char *session_key;
    const char *channel;
    const char *chat_id;

    /* Message buffer (growable) */
    sc_llm_message_t *msgs;
    int msgs_len;
    int msgs_cap;

    /* Turn tracking */
    int total_tool_calls;
    size_t total_output_bytes;
    int prompt_tokens;
    int completion_tokens;
    time_t turn_start;

    /* Stuck-loop detection */
    sc_recent_call_t recent_calls[SC_MAX_RECENT_CALLS];
    int recent_count;
} sc_turn_ctx_t;

/* ---------- agent_turn.c ---------- */

/* Run the LLM iteration loop (tool calls + fallbacks). Returns final content. */
char *sc_run_llm_iteration(sc_agent_t *agent, sc_provider_t *provider,
                           const char *model, sc_llm_message_t *messages,
                           int msg_count, const char *session_key,
                           const char *channel, const char *chat_id,
                           int *out_iterations);

/* ---------- agent_session.c ---------- */

/* Summarize session if over threshold, then consolidate to long-term memory */
void sc_maybe_summarize(sc_agent_t *agent, const char *session_key);

#endif /* SC_AGENT_INTERNAL_H */
