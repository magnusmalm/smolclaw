#ifndef SC_CONTEXT_H
#define SC_CONTEXT_H

#include "providers/types.h"
#include "tools/types.h"
#include "memory.h"

/* Forward declarations */
typedef struct sc_tool_registry sc_tool_registry_t;

/* Opaque context builder */
typedef struct sc_context_builder sc_context_builder_t;

/*
 * Context transform — a hook that can modify the message array
 * after context building but before the LLM call.
 *
 * The callback receives a mutable snapshot of the context:
 *   - msgs/msg_count: message array (system + history + user).
 *     The transform may modify in-place, append, or reallocate.
 *     If reallocated, set *msgs and *msg_count accordingly.
 *   - channel/session_key: current session context (read-only).
 *   - userdata: opaque pointer passed at registration.
 *
 * Return 0 on success. Non-zero skips subsequent transforms.
 */
typedef struct sc_arena sc_arena_t;  /* forward decl */

typedef struct {
    sc_llm_message_t **msgs;   /* pointer to message array (mutable) */
    int *msg_count;            /* pointer to count (mutable) */
    int *msg_cap;              /* pointer to capacity (mutable) */
    const char *channel;
    const char *session_key;
    sc_arena_t *arena;         /* per-turn arena (optional, may be NULL) */
} sc_context_snap_t;

typedef int (*sc_context_transform_fn)(sc_context_snap_t *snap, void *userdata);

/* A registered transform */
typedef struct {
    sc_context_transform_fn fn;
    void *userdata;
    const char *name;          /* for logging (borrowed, not freed) */
} sc_context_transform_t;

/* Create/destroy */
sc_context_builder_t *sc_context_builder_new(const char *workspace);

/* Isolated constructor for ephemeral delegate sessions. Creates a
 * context builder whose memory is namespaced (sc_memory_new_namespaced)
 * and whose system prompt omits the shared "# Memory" block entirely.
 * The agent's identity, bootstrap files, skills, and tool list are still
 * included — those are part of the agent's persistent self.
 *
 * See docs/design/session-isolation-plan.md §6.3. Returns NULL if
 * namespace_id is invalid (must be non-empty [A-Za-z0-9_-]). */
sc_context_builder_t *sc_context_builder_new_isolated(const char *workspace,
                                                       const char *namespace_id);

/* Returns 1 if the builder was created via the isolated constructor. */
int sc_context_builder_is_isolated(const sc_context_builder_t *cb);

void sc_context_builder_free(sc_context_builder_t *cb);

/* Set tools registry for dynamic tool summaries */
void sc_context_builder_set_tools(sc_context_builder_t *cb, sc_tool_registry_t *tools);

/* Set skills registry for system prompt listing (pass sc_skill_registry_t *) */
void sc_context_builder_set_skills(sc_context_builder_t *cb, void *skills);

/* Build complete system prompt. Caller owns result. */
char *sc_context_build_system_prompt(const sc_context_builder_t *cb);

/* Build full message array for LLM call.
 * Returns array of messages, sets *out_count.
 * Caller owns the returned array and its contents. */
sc_llm_message_t *sc_context_build_messages(const sc_context_builder_t *cb,
                                             sc_llm_message_t *history, int history_count,
                                             const char *summary,
                                             const char *current_msg,
                                             const char *channel, const char *chat_id,
                                             int *out_count);

/* Load bootstrap files (AGENTS.md, SOUL.md, etc). Caller owns result. */
char *sc_context_load_bootstrap(const sc_context_builder_t *cb);

/* Task 4.7: prompt-budget helpers (pure, unit-tested).
 *
 * sc_context_estimate_tokens — rough token estimate from a byte count using
 * the common ~4-chars-per-token heuristic (rounded up). This is an estimate,
 * not a tokenizer; good enough for a budget overview.
 *
 * sc_context_budget_warn — returns 1 when `used_tokens` reaches `warn_pct`
 * percent of `window` (the model's context window). Returns 0 when the inputs
 * make a warning meaningless (window <= 0 or warn_pct <= 0). */
int sc_context_estimate_tokens(size_t bytes);
int sc_context_budget_warn(int used_tokens, int window, int warn_pct);

#endif /* SC_CONTEXT_H */
