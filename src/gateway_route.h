#ifndef SC_GATEWAY_ROUTE_H
#define SC_GATEWAY_ROUTE_H

#include <ctype.h>
#include <string.h>

#include "bus.h"

/* Decide whether an inbound message should be routed to the isolated agent
 * path (sc_agent_process_isolated) instead of the shared path
 * (sc_agent_process_channel).
 *
 * Returns 1 iff msg->isolated is set AND msg->namespace_id is non-NULL and
 * non-empty. Returns 0 in all other cases, including for NULL msg.
 *
 * The empty/NULL-namespace guard is the safety net: isolation without a
 * namespace is meaningless, and the shared path is the safe fallback.
 *
 * Exposed in a header so tests/test_gateway_routing.c can exercise the
 * decision without needing to invoke gateway_process_message (which pulls
 * in the full agent, channels, and typing-thread machinery). The Stage-4
 * follow-up bug (gateway dropping the isolated flag, fixed in 7226204)
 * slipped past test_session_isolation.c precisely because the decision
 * lived inline in main.c with no test surface.
 */
static inline int sc_gateway_should_isolate(const sc_inbound_msg_t *msg)
{
    return msg && msg->isolated
        && msg->namespace_id && msg->namespace_id[0];
}

/* Validate a per-turn run_repo_dir override (Phase 5). Returns 1 iff `p`
 * is a non-empty workspace-relative path safe to resolve against the
 * agent's workspace:
 *   - not NULL or empty
 *   - not absolute (no leading "/")
 *   - no ".." segment (split on "/", reject if any segment is exactly "..")
 *   - length under 1024 bytes
 *
 * Returns 0 otherwise. The path-traversal check is segment-aware so legit
 * names like "runs/abc..def" pass — only a bare ".." segment is rejected.
 *
 * Does NOT check whether the resolved path exists on disk; the caller
 * stat()s after resolving against agent->workspace. */
static inline int sc_gateway_run_repo_dir_safe(const char *p)
{
    if (!p || !p[0] || p[0] == '/') return 0;
    if (strlen(p) > 1024) return 0;
    const char *seg = p;
    while (*seg) {
        const char *slash = strchr(seg, '/');
        size_t len = slash ? (size_t)(slash - seg) : strlen(seg);
        if (len == 2 && seg[0] == '.' && seg[1] == '.') return 0;
        if (!slash) break;
        seg = slash + 1;
    }
    return 1;
}

/* Task 3.9 — Silent delivery tokens.
 *
 * Returns 1 iff the agent's final response, after trimming leading/trailing
 * ASCII whitespace and case-folding, equals exactly one of the intentional-
 * silence tokens: "[SILENT]", "SILENT", "NO_REPLY", "NO REPLY". The gateway
 * uses this to suppress outbound delivery (e.g. in group chats / automations
 * where the model decides not to speak) while the turn is still stored in the
 * session transcript by run_agent_loop, so alternation is preserved.
 *
 * The match is on the WHOLE trimmed response, not a substring: a real reply
 * that merely mentions "no reply" is delivered normally. Error strings (which
 * begin with "Error: ...") never equal a token, so failed turns still surface
 * — silence never swallows an error.
 *
 * NULL or empty input returns 0 (nothing to suppress; let the caller's own
 * empty-response handling run).
 *
 * Pure and header-inline so tests/test_gateway_routing.c can exercise the
 * truth table without the gateway/agent/channel machinery.
 */
static inline int sc_gateway_is_silent_token(const char *response)
{
    if (!response) return 0;

    /* Trim leading whitespace. */
    const char *s = response;
    while (*s && isspace((unsigned char)*s)) s++;

    /* Trim trailing whitespace. */
    const char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)*(e - 1))) e--;

    size_t len = (size_t)(e - s);
    if (len == 0) return 0;

    static const char *const tokens[] = {
        "[SILENT]", "SILENT", "NO_REPLY", "NO REPLY",
    };
    for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++) {
        const char *t = tokens[i];
        if (strlen(t) != len) continue;
        size_t j = 0;
        for (; j < len; j++) {
            if (toupper((unsigned char)s[j]) != toupper((unsigned char)t[j]))
                break;
        }
        if (j == len) return 1;
    }
    return 0;
}

#endif /* SC_GATEWAY_ROUTE_H */
