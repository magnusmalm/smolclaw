#ifndef SC_MEMORY_REVIEW_H
#define SC_MEMORY_REVIEW_H

/*
 * Task 4.13: post-turn memory review (Tier 4, opt-in, default off).
 *
 * After a successful turn, optionally spawn a background task (reusing the
 * summarization sc_task_t pattern) that asks an LLM to propose 0-2 durable
 * memory entries from a compact digest of the turn, then writes them via the
 * normal memory path. No extra runtime deps; uses the agent's provider (with an
 * optional cheaper model override). Distinct from summary-time consolidation —
 * this reviews individual turns as they happen.
 */

/* Forward declaration */
typedef struct sc_agent sc_agent_t;

/* Pure: should a post-turn review run? Only when the turn succeeded AND the
 * feature is enabled. */
int sc_memory_review_should_run(int turn_succeeded, int enabled);

/* Pure: parse an LLM response into up to `max` proposed memory entries. The
 * model is asked for a JSON array of strings; this tolerates a leading/trailing
 * ```json fence and an "NONE"/empty reply. Returns a malloc'd array of malloc'd
 * strings (caller frees with sc_memory_review_entries_free) and sets *count, or
 * NULL with *count = 0 when there is nothing to add. */
char **sc_memory_review_parse(const char *llm_content, int max, int *count);

void sc_memory_review_entries_free(char **entries, int count);

/* Spawn the async post-turn review for the just-completed turn. No-op if the
 * feature is disabled, a review is already in flight, the provider can't be
 * cloned, or the inputs are empty. Polls/reaps any finished prior review
 * first. Safe to call every turn. */
void sc_memory_review_maybe_spawn(sc_agent_t *agent, const char *user_msg,
                                  const char *final_response);

/* Reap a finished review task (join + free the slot). Called from the main
 * thread; safe when no task is pending. */
void sc_memory_review_reap(sc_agent_t *agent);

#endif /* SC_MEMORY_REVIEW_H */
