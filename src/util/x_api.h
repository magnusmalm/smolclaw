/*
 * util/x_api.h - Shared X (Twitter) API layer
 *
 * OAuth 1.0a signing and authenticated HTTP helpers for X API v2.
 * Used by both the X channel (polling) and X tools (on-demand queries).
 */

#ifndef SC_X_API_H
#define SC_X_API_H

#include "cJSON.h"

/* Credentials handle (auth only, no polling state) */
typedef struct {
    char *consumer_key;
    char *consumer_secret;
    char *access_token;
    char *access_token_secret;
    char *api_base;
} sc_x_creds_t;

/* Query parameter for OAuth signing and URL building */
typedef struct {
    char *key;
    char *val;
} sc_x_param_t;

/* Create credentials (copies all strings). Returns NULL on alloc failure. */
sc_x_creds_t *sc_x_creds_new(const char *consumer_key,
                               const char *consumer_secret,
                               const char *access_token,
                               const char *access_token_secret,
                               const char *api_base);

/* Free credentials */
void sc_x_creds_free(sc_x_creds_t *creds);

/* Authenticated GET — returns parsed JSON or NULL. Caller owns result.
 * path: API path (e.g. "/2/tweets/123")
 * params: query parameters (can be NULL if param_count is 0) */
cJSON *sc_x_api_get(const sc_x_creds_t *creds, const char *path,
                     const sc_x_param_t *params, int param_count);

/* Authenticated POST — returns parsed JSON or NULL. Caller owns result.
 * path: API path, payload: JSON body (not consumed) */
cJSON *sc_x_api_post(const sc_x_creds_t *creds, const char *path,
                      cJSON *payload);

#endif /* SC_X_API_H */
