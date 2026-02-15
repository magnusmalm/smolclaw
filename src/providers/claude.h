#ifndef SC_PROVIDER_CLAUDE_H
#define SC_PROVIDER_CLAUDE_H

#include "providers/types.h"

/* Create Anthropic Messages API provider (native format) */
sc_provider_t *sc_provider_claude_new(const char *api_key, const char *api_base);

#endif /* SC_PROVIDER_CLAUDE_H */
