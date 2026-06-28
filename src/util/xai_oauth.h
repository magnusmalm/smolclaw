#ifndef SC_XAI_OAUTH_H
#define SC_XAI_OAUTH_H

/*
 * util/xai_oauth.h - xAI Grok OAuth (SuperGrok subscription) provider
 * (tasks 2.1 / 2.2). Authoritative spec: docs/design/xai-grok-oauth.md.
 *
 * One-time browser-based OAuth 2.0 PKCE login lets a Grok subscriber use the
 * xAI HTTP provider with a short-lived bearer token instead of an XAI_API_KEY.
 * Tokens live in {SMOLCLAW_HOME}/auth.json (0600, atomic replace) and refresh
 * automatically before expiry. The fresh access token is handed to the existing
 * OpenAI-compatible provider as its api_key — no change to the chat path.
 *
 * The pure helpers (PKCE, JWT exp, URL build, refresh decision, endpoint
 * validation, store (de)serialization) and the HTTP steps (discovery, token
 * exchange, refresh — each takes its endpoint URL, so tests point them at a mock
 * server) are split from the interactive login orchestration. The login flow's
 * loopback callback server + browser launch + live consent are a human gate.
 *
 * NOTE (stale-constant risk): the client_id, issuer, scope, and plan/referrer
 * params below are from the 2026-05 spec and may drift. They are defined in one
 * place (xai_oauth.c) and must be re-verified against a live SuperGrok login.
 */

#include <stddef.h>

/* Tokens + discovery metadata for one OAuth provider (the auth.json record). */
typedef struct {
    char *access_token;
    char *refresh_token;
    char *id_token;
    char *token_type;             /* usually "Bearer" */
    long  expires_in;             /* seconds, as returned by the token endpoint */
    char *authorization_endpoint; /* from discovery */
    char *token_endpoint;         /* from discovery */
    char *redirect_uri;           /* loopback URI used at login */
    char *last_refresh;           /* ISO-8601, informational */
} sc_xai_store_t;

void sc_xai_store_free(sc_xai_store_t *s);

/* --- Pure helpers (no I/O; unit-tested directly) --- */

/* Generate a PKCE verifier (43-char base64url of 32 random bytes) and the
 * matching S256 challenge = base64url(sha256(verifier)). Both malloc'd; caller
 * frees. Returns 1 on success, 0 on failure. */
int sc_xai_pkce_generate(char **verifier, char **challenge);

/* Parse the `exp` claim (unix seconds) from a JWT without verifying the
 * signature. Returns the exp, or -1 if absent/malformed. */
long sc_xai_jwt_get_exp(const char *jwt);

/* Refresh decision: 1 if the token expires within `skew` seconds of `now`.
 * exp <= 0 (unknown) returns 0 — a garbage/missing exp is treated as "not
 * expiring soon" so we don't refresh-loop on a token xAI still accepts. */
int sc_xai_oauth_should_refresh(long exp, long now, int skew);

/* Build the PKCE authorize URL with all required params (response_type=code,
 * client_id, redirect_uri, scope, state, code_challenge[_method=S256],
 * plan=generic, referrer=smolclaw). All values URL-escaped. Caller frees. */
char *sc_xai_oauth_build_authorize_url(const char *auth_endpoint,
                                       const char *redirect_uri,
                                       const char *challenge,
                                       const char *state);

/* Validate that a token/authorization endpoint URL is https and its host is
 * x.ai or *.x.ai. Defends against poisoned discovery. Returns 1 if allowed. */
int sc_xai_oauth_validate_endpoint(const char *url);

/* --- Store (de)serialization + persistence --- */

/* Path to {SMOLCLAW_HOME}/auth.json (caller frees), or NULL. */
char *sc_xai_oauth_store_path(void);

/* Serialize the xai-oauth record into the auth.json document shape
 * (caller frees), or NULL. */
char *sc_xai_oauth_to_json(const sc_xai_store_t *s);

/* Parse the xai-oauth record out of an auth.json document. Returns 1 on
 * success (out filled, caller frees with sc_xai_store_free), 0 otherwise. */
int sc_xai_oauth_from_json(const char *json, sc_xai_store_t *out);

/* Atomic 0600 write of the xai-oauth record to the store path. Returns 0 on
 * success. */
int sc_xai_oauth_save(const sc_xai_store_t *s);

/* Load the xai-oauth record from the store path. Returns 1 on success. */
int sc_xai_oauth_load(sc_xai_store_t *out);

/* Remove the store file (logout). Returns 0 on success (or if absent). */
int sc_xai_oauth_logout(void);

/* --- HTTP steps (endpoint URL is a parameter → mockable) --- */

/* OIDC discovery: GET {issuer}/.well-known/openid-configuration, fill the two
 * endpoints (caller frees). Returns 0 on success. */
int sc_xai_oauth_discover(const char *issuer, char **auth_ep, char **token_ep);

/* Exchange an authorization code (PKCE) at the token endpoint. Fills *out
 * (caller frees). Returns 0 on success, non-zero on error. */
int sc_xai_oauth_exchange_code(const char *token_ep, const char *code,
                               const char *verifier, const char *redirect_uri,
                               sc_xai_store_t *out);

/* Refresh using a refresh_token at the token endpoint. Fills *out (caller
 * frees; out->refresh_token falls back to the supplied one if the server omits
 * it). Returns 0 on success, 1 on transport error, 2 on invalid_grant/relogin. */
int sc_xai_oauth_refresh(const char *token_ep, const char *refresh_token,
                         sc_xai_store_t *out);

/* --- Runtime + CLI --- */

/* Load the stored token, refresh if it is near expiry (re-validating the
 * token endpoint origin), persist any refresh, and return a fresh access token
 * (caller frees), or NULL if no valid credential is available. Called by the
 * provider factory for the `xai-oauth` provider. */
char *sc_xai_oauth_ensure_fresh_token(void);

/* `smolclaw auth <login|status|logout|refresh> [xai] [--no-browser] [--timeout N]`.
 * Returns process exit code. */
int sc_cmd_auth(int argc, char **argv);

#endif /* SC_XAI_OAUTH_H */
