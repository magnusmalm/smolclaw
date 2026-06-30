/*
 * companion/auth.c — scoped companion bearer tokens (defense-in-depth).
 *
 * Route scopes limit which HTTP endpoints a companion token may call.
 * They do NOT restrict which tools /api/message can invoke — that boundary
 * is channels.web.tools (see docs/plans/companion-android-v1.md §6).
 */

#include "companion/auth.h"
#include "util/str.h"

#include <stdio.h>
#include <string.h>

static int scope_allowed(const char *const *scopes, int scope_count,
                          const char *required)
{
    if (!required || !required[0]) return 1;
    if (!scopes || scope_count <= 0) return 0;
    for (int i = 0; i < scope_count; i++) {
        if (scopes[i] && strcmp(scopes[i], required) == 0)
            return 1;
    }
    return 0;
}

static int bearer_token_value(const char *authorization_header, char *out,
                               size_t out_len)
{
    if (!authorization_header || strncmp(authorization_header, "Bearer ", 7) != 0)
        return -1;
    const char *tok = authorization_header + 7;
    if (!tok[0]) return -1;
    if (strlen(tok) >= out_len) return -1;
    snprintf(out, out_len, "%s", tok);
    return 0;
}

int sc_companion_token_matches(const sc_web_config_t *web, const char *token)
{
    if (!web || !token || !token[0]) return 0;
    for (int i = 0; i < web->companion_token_count; i++) {
        const sc_companion_token_entry_t *e = &web->companion_tokens[i];
        if (e->token && sc_timing_safe_cmp(e->token, token) == 0)
            return 1;
    }
    return 0;
}

int sc_companion_check_auth(const sc_web_config_t *web,
                             const char *authorization_header,
                             const char *required_scope)
{
    if (!web || !web->bearer_token || !web->bearer_token[0])
        return 0;

    char tok[512];
    if (bearer_token_value(authorization_header, tok, sizeof(tok)) != 0)
        return 0;

    /* Main admin bearer has full route access. */
    if (sc_timing_safe_cmp(web->bearer_token, tok) == 0)
        return 1;

    for (int i = 0; i < web->companion_token_count; i++) {
        const sc_companion_token_entry_t *e = &web->companion_tokens[i];
        if (!e->token || sc_timing_safe_cmp(e->token, tok) != 0)
            continue;
        return scope_allowed((const char *const *)e->scopes,
                             e->scope_count, required_scope);
    }
    return 0;
}