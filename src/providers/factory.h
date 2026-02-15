#ifndef SC_PROVIDER_FACTORY_H
#define SC_PROVIDER_FACTORY_H

#include "providers/types.h"
#include "config.h"

/* Create appropriate provider from config.
 * Returns NULL on error (logged). */
sc_provider_t *sc_provider_create(const sc_config_t *cfg);

/* Create provider for a specific model name (for fallback chains).
 * Model name may contain a provider prefix (e.g. "groq/llama-3.3-70b").
 * Returns NULL on error (logged). */
sc_provider_t *sc_provider_create_for_model(const sc_config_t *cfg, const char *model);

/* Strip provider routing prefix from model name if present.
 * E.g. "openrouter/qwen/qwen3-8b" → "qwen/qwen3-8b"
 * Returns pointer into the original string (no allocation needed). */
const char *sc_model_strip_prefix(const char *model);

#endif /* SC_PROVIDER_FACTORY_H */
