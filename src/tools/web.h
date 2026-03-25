#ifndef SC_TOOL_WEB_H
#define SC_TOOL_WEB_H

#include "tools/types.h"

/* Network scope levels for SSRF policy */
#define SC_NET_SCOPE_NONE   0  /* no outbound network from tools */
#define SC_NET_SCOPE_LOCAL  1  /* allow private/LAN IPs only */
#define SC_NET_SCOPE_PUBLIC 2  /* allow public IPs, block private (default) */
#define SC_NET_SCOPE_ANY    3  /* unrestricted */

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

/* Set network scope policy (SC_NET_SCOPE_*). Default: SC_NET_SCOPE_PUBLIC. */
void sc_web_set_network_scope(int scope);

/* Test-only: bypass SSRF checks for mock servers on localhost.
 * NOT settable via environment — must be called explicitly from test code. */
void sc_web_set_ssrf_bypass(int enabled);

#endif /* SC_TOOL_WEB_H */
