/*
 * smolclaw - prompt prefix warmup (Phase 1.8)
 *
 * Primes a local model's prefix cache (llama.cpp / Ollama) with a single
 * non-streaming max_tokens=1 request so the first real call is faster. Only
 * runs for providers in the agent's warmup allowlist, and only when the
 * (provider, model, system prompt, tool set) fingerprint has changed — so it
 * fires once per agent session, not per message.
 */
#ifndef SC_WARMUP_H
#define SC_WARMUP_H

#include "providers/types.h"

struct sc_agent;

/* Returns 1 if a warmup request was sent, 0 if skipped (disabled, provider not
 * allowlisted, or fingerprint unchanged). */
int sc_warmup_maybe(struct sc_agent *agent, sc_provider_t *provider,
                    const char *model, sc_llm_message_t *msgs, int msg_count,
                    sc_tool_definition_t *tools, int tool_count);

#endif /* SC_WARMUP_H */
