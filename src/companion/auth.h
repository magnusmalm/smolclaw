#ifndef SC_COMPANION_AUTH_H
#define SC_COMPANION_AUTH_H

#include "config.h"

/* Route scopes for companion_tokens[] (PR 4 defense-in-depth).
 * Primary security boundary remains channels.web.tools allowlist. */

#define SC_COMP_SCOPE_CHAT           "chat"
#define SC_COMP_SCOPE_PROGRESS       "progress"
#define SC_COMP_SCOPE_MEMORY_PENDING "memory_pending"
#define SC_COMP_SCOPE_SNAP_UPLOAD    "snap_upload"
#define SC_COMP_SCOPE_AUDIT_READ     "audit_read"
#define SC_COMP_SCOPE_LIBRARY        "library"

/* Returns 1 if Authorization header is valid for required_scope.
 * required_scope NULL = any authenticated caller (main bearer or any companion token).
 * Main bearer_token always has full access. */
int sc_companion_check_auth(const sc_web_config_t *web,
                             const char *authorization_header,
                             const char *required_scope);

/* True if token string matches a configured companion entry (timing-safe). */
int sc_companion_token_matches(const sc_web_config_t *web, const char *token);

#endif /* SC_COMPANION_AUTH_H */