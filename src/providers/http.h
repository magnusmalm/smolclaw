#ifndef SC_PROVIDER_HTTP_H
#define SC_PROVIDER_HTTP_H

#include "providers/types.h"

/* Create generic HTTP provider (OpenAI-compatible APIs) */
sc_provider_t *sc_provider_http_new(const char *api_key, const char *api_base,
                                     const char *proxy);

#endif /* SC_PROVIDER_HTTP_H */
