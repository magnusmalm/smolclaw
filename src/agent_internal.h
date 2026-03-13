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

/* ---------- Cross-turn hourly rate tracking ---------- */

#define SC_HOURLY_SLOTS 64

typedef struct {
    uint32_t key_hash;
    char key_prefix[32];  /* collision detection */
    int tool_calls;
    time_t window_start;
} sc_hourly_slot_t;

/* ---------- Turn context ---------- */

#define SC_MAX_RECENT_CALLS 10
#define SC_TOOL_CACHE_MAX 32

typedef struct { uint32_t hash; int count; } sc_recent_call_t;
typedef struct { uint32_t key; char *result_for_llm; } sc_cache_entry_t;

/* Per-turn mutable state shared across LLM iteration helpers */
typedef struct {
    const char *session_key;
    const char *root_session_key;  /* parent session key for rate limiting */
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

    /* Intent threading: original user question (borrowed, not owned) */
    const char *user_intent;

    /* Per-turn tool result cache for read-only tools */
    sc_cache_entry_t tool_cache[SC_TOOL_CACHE_MAX];
    int tool_cache_count;

    /* LLM failure tracking — populated when all providers fail */
    char *failure_reason;  /* malloc'd, freed by caller */
} sc_turn_ctx_t;

/* ---------- agent_turn.c ---------- */

/* Run the LLM iteration loop (tool calls + fallbacks). Returns final content.
 * If out_failure_reason is non-NULL and the LLM fails, a human-readable
 * error string is returned (caller must free). */
char *sc_run_llm_iteration(sc_agent_t *agent, sc_provider_t *provider,
                           const char *model, sc_llm_message_t *messages,
                           int msg_count, const char *session_key,
                           const char *channel, const char *chat_id,
                           int *out_iterations, char **out_failure_reason);

/* ---------- agent_session.c ---------- */

/* Summarize session if over threshold, then consolidate to long-term memory */
void sc_maybe_summarize(sc_agent_t *agent, const char *session_key);

/* Drain any pending async summarization thread and apply its result.
 * Safe to call when no thread is active (no-op). */
void sc_drain_summarize(sc_agent_t *agent);

#endif /* SC_AGENT_INTERNAL_H */
