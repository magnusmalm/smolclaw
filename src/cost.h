#ifndef SC_COST_H
#define SC_COST_H

#include "cJSON.h"

typedef struct sc_cost_tracker {
    char *state_path;  /* {workspace}/state/costs.json */
    cJSON *data;       /* {"models":{...}, "total_turns":N} */
} sc_cost_tracker_t;

/* Create cost tracker, loading existing data from workspace/state/costs.json */
sc_cost_tracker_t *sc_cost_tracker_new(const char *workspace);

/* Record tokens for a turn */
void sc_cost_tracker_record(sc_cost_tracker_t *ct, const char *model,
                             const char *session_key,
                             int prompt_tokens, int completion_tokens);

/* Print summary table to stdout */
void sc_cost_tracker_print_summary(sc_cost_tracker_t *ct);

/* Reset all tracked data */
void sc_cost_tracker_reset(sc_cost_tracker_t *ct);

/* Free tracker */
void sc_cost_tracker_free(sc_cost_tracker_t *ct);

#endif /* SC_COST_H */
