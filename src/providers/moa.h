#ifndef SC_PROVIDER_MOA_H
#define SC_PROVIDER_MOA_H

/*
 * Mixture of Agents (MoA-lite) virtual provider — task 2.13.
 * See docs/design/mixture-of-agents.md.
 *
 * On each main LLM call, reference models run first (no tools, trimmed
 * context); their outputs are injected on the tail of the latest user message;
 * an aggregator model then runs with the full context + tool schema and acts
 * as the real model for that iteration.
 */

#include "providers/types.h"
#include "config.h"

/* A resolved slot: an owned provider handle + the bare model to pass to it. */
typedef struct {
    sc_provider_t *provider;  /* owned; NULL if it failed to resolve */
    char *model;              /* bare model name (owned) */
    char *label;              /* "provider/model" for the injection header */
} sc_moa_slot_t;

typedef struct {
    char *name;
    int   enabled;
    int   local_only;
    sc_moa_slot_t refs[SC_MOA_MAX_REFS];
    int   ref_count;
    sc_moa_slot_t agg;
    double ref_temp;
    double agg_temp;       /* 0 = inherit turn options */
    int    ref_max_tokens;
    int    agg_max_tokens; /* 0 = inherit turn options */
} sc_moa_preset_t;

/* Build an ephemeral message array for reference models: user + assistant
 * *text* only (no system, no tool rows, no assistant tool_calls). Order is
 * preserved; the source array is not mutated. Caller frees via
 * sc_llm_message_array_free. */
sc_llm_message_t *sc_msgs_reference_view(const sc_llm_message_t *msgs, int count,
                                         int *out_count);

/* Deep-copy `msgs` and inject the reference blocks onto the last user message
 * (or as a synthetic trailing user message if the last message isn't a user
 * turn). Never mutates the source. Caller frees via sc_llm_message_array_free. */
sc_llm_message_t *sc_msgs_inject_moa_refs(const sc_llm_message_t *msgs, int count,
                                          char *const *labels, char *const *texts,
                                          int ref_count, int *out_count);

/* True if a slot provider is eligible under a `local_only` preset: ollama/vllm,
 * or a custom provider whose api_base host is loopback / RFC1918. */
int sc_moa_provider_is_local(const char *provider_name, const char *api_base);

/* Run one MoA iteration with already-resolved slots (references in parallel →
 * inject → aggregator). Returns the aggregator response (caller frees), or NULL
 * if the preset has no aggregator. Exposed for tests. */
sc_llm_response_t *sc_moa_run(const sc_moa_preset_t *preset,
                              sc_llm_message_t *msgs, int msg_count,
                              sc_tool_definition_t *tools, int tool_count,
                              cJSON *options,
                              sc_stream_cb stream_cb, void *stream_ctx);

/* Create the virtual `moa` provider from config. `default_preset` (may be NULL)
 * selects the preset used when the turn's model is empty. Returns NULL if no
 * usable preset resolves. */
sc_provider_t *sc_provider_moa_new(const sc_config_t *cfg, const char *default_preset);

#endif /* SC_PROVIDER_MOA_H */
