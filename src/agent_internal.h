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
    int token_count;      /* total tokens consumed in this window */
    time_t window_start;
} sc_hourly_slot_t;

/* ---------- Turn context ---------- */

#define SC_MAX_RECENT_CALLS 10
#define SC_TOOL_CACHE_MAX 32

typedef struct { uint32_t hash; int count; } sc_recent_call_t;
typedef struct { uint32_t key; char *result_for_llm; } sc_cache_entry_t;

/* Checkpoint for rewind recovery */
#define SC_MAX_CHECKPOINTS 2

typedef struct {
    sc_llm_message_t *msgs;
    int msgs_len;
    int iteration;
    int total_tool_calls;
} sc_checkpoint_t;

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
    int prompt_tokens;         /* cumulative across all iterations */
    int completion_tokens;     /* cumulative across all iterations */
    int last_prompt_tokens;    /* from most recent LLM call (post-transform) */
    /* Cumulative provider-reported actual cost across all iterations of
     * this turn. -1 means no provider has reported a cost (e.g. all calls
     * went through Anthropic, which doesn't return usage.cost). When >= 0,
     * the cost tracker prefers this over the rate-table estimate. */
    double actual_cost_usd;
    time_t turn_start;

    /* Stuck-loop detection */
    sc_recent_call_t recent_calls[SC_MAX_RECENT_CALLS];
    int recent_count;

    /* Error tracking — tool failures per turn */
    int tool_error_count;
    int tool_name_error_counts[SC_MAX_RECENT_CALLS]; /* per-tool error count */
    uint32_t tool_name_hashes[SC_MAX_RECENT_CALLS];
    int tool_name_count;

    /* Intent threading: original user question (borrowed, not owned) */
    const char *user_intent;

    /* Per-turn tool result cache for read-only tools */
    sc_cache_entry_t tool_cache[SC_TOOL_CACHE_MAX];
    int tool_cache_count;

    /* Checkpoint & rewind */
    sc_checkpoint_t checkpoints[SC_MAX_CHECKPOINTS];
    int checkpoint_slot;    /* next slot to write (ring buffer) */
    int checkpoint_count;   /* how many valid checkpoints we have */
    int rewind_count;       /* how many rewinds this turn (max 2) */

    /* Continuation nudge — prevent premature turn end */
    int nudge_count;        /* how many nudges this turn (max 1) */

    /* Adaptive timeout: grace seconds added for transient errors.
     * HTTP 0 (connection failure) and 429 (rate limit) don't consume
     * tokens, so waiting costs nothing. Cap at 300s extra. */
    int grace_secs;         /* accumulated grace time */

    /* LLM failure tracking — populated when all providers fail */
    char *failure_reason;  /* malloc'd, freed by caller */

    /* Per-channel tool allowlist (borrowed, not owned) */
    char **ch_tools;
    int ch_tool_count;
} sc_turn_ctx_t;

/* ---------- agent_turn.c ---------- */

/* Run the LLM iteration loop (tool calls + fallbacks). Returns final content.
 * If out_failure_reason is non-NULL and the LLM fails, a human-readable
 * error string is returned (caller must free).
 * If out_thinking is non-NULL, the final response's thinking text is returned
 * (caller must free). NULL if no thinking. */
char *sc_run_llm_iteration(sc_agent_t *agent, sc_provider_t *provider,
                           const char *model, sc_llm_message_t *messages,
                           int msg_count, const char *session_key,
                           const char *channel, const char *chat_id,
                           int *out_iterations, char **out_failure_reason,
                           char **out_thinking);

/* ---------- agent_session.c ---------- */

/* Summarize session if over threshold, then consolidate to long-term memory */
void sc_maybe_summarize(sc_agent_t *agent, const char *session_key);

/* Drain any pending async summarization thread and apply its result.
 * Safe to call when no thread is active (no-op). */
void sc_drain_summarize(sc_agent_t *agent);

#endif /* SC_AGENT_INTERNAL_H */
