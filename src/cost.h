#ifndef SC_COST_H
#define SC_COST_H

struct cJSON;

/* Opaque cost tracker */
typedef struct sc_cost_tracker sc_cost_tracker_t;

/* Create cost tracker, loading existing data from workspace/state/costs.json */
sc_cost_tracker_t *sc_cost_tracker_new(const char *workspace);

/* Set pricing overrides from config (borrowed pointer, not owned).
 * Format: {"model-name": {"prompt": rate, "completion": rate}} ($/M tokens) */
void sc_cost_tracker_set_pricing(sc_cost_tracker_t *ct,
                                  struct cJSON *overrides);

/* Record tokens for a turn (uses rate-table estimate for cost). */
void sc_cost_tracker_record(sc_cost_tracker_t *ct, const char *model,
                             const char *session_key,
                             int prompt_tokens, int completion_tokens);

/* Record tokens with a provider-reported actual USD billed for this turn.
 * Pass actual_cost_usd < 0 to skip (defaults to estimate). When supplied,
 * accumulates actual_cost_usd into the model's cumulative actual_cost_usd
 * field and tags cost_source as "provider"/"mixed" depending on history.
 * The estimated_cost_usd field is also maintained for comparison. */
void sc_cost_tracker_record_actual(sc_cost_tracker_t *ct, const char *model,
                                    const char *session_key,
                                    int prompt_tokens, int completion_tokens,
                                    double actual_cost_usd);

/* Print summary table to stdout */
void sc_cost_tracker_print_summary(sc_cost_tracker_t *ct);

/* Print per-session breakdown to stdout */
void sc_cost_tracker_print_sessions(sc_cost_tracker_t *ct);

/* Reset all tracked data */
void sc_cost_tracker_reset(sc_cost_tracker_t *ct);

/* Estimate USD for one turn using the tracker's pricing (config
 * overrides + built-in table; local models — ollama ':' tags and
 * local-inference prefixes — are $0). NULL tracker uses defaults only.
 * This is THE pricing function: anything reporting cost externally
 * (e.g. the smolchat ledger) must use it, never its own table. */
double sc_cost_tracker_estimate(const sc_cost_tracker_t *ct,
                                 const char *model,
                                 int prompt_tokens, int completion_tokens);

/* Recompute every model's estimated_cost_usd against the current pricing
 * table (DEFAULT_PRICING + any pricing_overrides). Returns the number of
 * entries changed, or -1 on error. Use after rate updates to retroactively
 * correct stored costs. */
int sc_cost_tracker_recompute(sc_cost_tracker_t *ct);

/* Free tracker */
void sc_cost_tracker_free(sc_cost_tracker_t *ct);

#endif /* SC_COST_H */
