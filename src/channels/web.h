#ifndef SC_CHANNEL_WEB_H
#define SC_CHANNEL_WEB_H

#include "channels/base.h"
#include "config.h"
#include "rate_limit.h"

struct evhttp_request;

/* Create Web channel (HTTP REST API + embedded chat UI) */
sc_channel_t *sc_channel_web_new(sc_web_config_t *cfg, sc_bus_t *bus,
                                  const char *workspace);

/* Phase 4 isolation helper, exposed for unit testing.
 *
 * Decides whether a given inbound web request should run with isolated
 * session memory. If `pattern` is non-empty and `session_name` matches
 * the glob, computes a stable namespace_id from `session_key` (SHA-256
 * truncated to 16 hex digits, plus terminator — out_ns_id must be at
 * least 17 bytes) and returns 1. Otherwise returns 0 and leaves out_ns_id
 * as an empty string. See docs/design/session-isolation-plan.md §6.5. */
int sc_web_compute_isolation(const char *pattern,
                              const char *session_name,
                              const char *session_key,
                              char out_ns_id[17]);

/* Bearer auth helper (unit-tested). configured_token must be non-empty when
 * the web channel is running. Returns 1 if authorized, 0 if denied.
 * Fail-closed policy: missing/empty configured token always denies (audit
 * 4298ba13 / PR-1). authorization_header is the raw Authorization value. */
int sc_web_check_bearer_auth(const char *configured_token,
                              const char *authorization_header);

/* Build rate-limit key for POST /api/message: web:msg:<ip>:<token-hash>.
 * authorization_header may be NULL (uses "anon" token suffix). Exposed for
 * unit tests (audit 4298ba13 / PR-6 / P1-4). */
int sc_web_build_message_rate_key(const char *client_ip,
                                   const char *authorization_header,
                                   char *out, size_t out_len);

/* Check /api/message rate limit for client_ip + Authorization header.
 * Returns 1 if allowed, 0 if rate-limited. rl NULL or disabled → allowed. */
int sc_web_check_message_rate_limit(sc_rate_limiter_t *rl,
                                     const char *client_ip,
                                     const char *authorization_header);

/* Snap upload rate limit: web:snap:<ip>:<token-hash> (plan §13.1 D3). */
int sc_web_build_snap_rate_key(const char *client_ip,
                                const char *authorization_header,
                                char *out, size_t out_len);
int sc_web_check_snap_rate_limit(sc_rate_limiter_t *rl,
                                  const char *client_ip,
                                  const char *authorization_header);

void sc_web_send_json_error(struct evhttp_request *req, int code,
                             const char *msg);
char *sc_web_confine_image(const char *workspace, const char *path);
void sc_web_client_ip(struct evhttp_request *req, char *buf, size_t buflen);
const char *sc_web_channel_workspace(sc_channel_t *ch);
int sc_web_channel_port(const sc_channel_t *ch);

#if SC_ENABLE_COMPANION
/* required_scope NULL = any authenticated bearer (main or companion). */
int sc_web_companion_check_auth(sc_channel_t *ch,
                                 const char *authorization_header,
                                 const char *required_scope);
#endif

#endif /* SC_CHANNEL_WEB_H */
