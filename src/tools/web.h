#ifndef SC_TOOL_WEB_H
#define SC_TOOL_WEB_H

#include "tools/types.h"

typedef struct {
    int brave_enabled;
    const char *brave_api_key;
    const char *brave_base_url;
    int brave_max_results;
    int searxng_enabled;
    const char *searxng_base_url;
    int searxng_max_results;
    int duckduckgo_enabled;
    int duckduckgo_max_results;
} sc_web_search_opts_t;

/* Returns NULL if no search provider is available */
sc_tool_t *sc_tool_web_search_new(sc_web_search_opts_t opts);
sc_tool_t *sc_tool_web_fetch_new(int max_chars);

/* Test-only: bypass SSRF checks for mock servers on localhost.
 * NOT settable via environment — must be called explicitly from test code. */
void sc_web_set_ssrf_bypass(int enabled);

#endif /* SC_TOOL_WEB_H */
