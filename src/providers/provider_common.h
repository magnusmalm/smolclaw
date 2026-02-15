/*
 * providers/provider_common.h - Shared curl callbacks and helpers
 *
 * Common code shared between claude.c and http.c providers:
 * write callback, progress callback, header parsing, URL trimming, curl init.
 */

#ifndef SC_PROVIDER_COMMON_H
#define SC_PROVIDER_COMMON_H

#include <curl/curl.h>
#include "util/str.h"
#include "providers/types.h"

/* Header callback context: extract Retry-After value */
typedef struct sc_header_ctx {
    int retry_after;
} sc_header_ctx_t;

/* curl progress callback: abort transfer on shutdown */
int sc_curl_progress_cb(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
                        curl_off_t ultotal, curl_off_t ulnow);

/* curl write callback: append to sc_strbuf_t with size limit */
size_t sc_curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata);

/* Header callback: extract Retry-After value */
size_t sc_header_cb(char *buffer, size_t size, size_t nitems, void *userdata);

/* Return an error response with the given HTTP status and retry_after */
sc_llm_response_t *sc_provider_make_error_response(int http_status,
                                                    int retry_after);

/* Trim trailing slashes from a URL string in-place */
void sc_provider_trim_base_url(char *url);

/* Initialize a CURL handle with protocol restrictions */
CURL *sc_provider_init_curl(void);

/* Reset curl handle and configure common options. Returns header slist (caller frees).
 * auth_prefix: e.g. "Authorization: Bearer " or "x-api-key: ".
 * extra_headers: NULL-terminated array of additional header strings, or NULL. */
struct curl_slist *sc_provider_setup_curl(CURL *curl, const char *url,
                                           const char *api_key,
                                           const char *auth_prefix,
                                           const char *body_str,
                                           const char *proxy,
                                           sc_header_ctx_t *hdr_ctx,
                                           curl_write_callback write_fn,
                                           void *write_data, long timeout,
                                           const char **extra_headers);

#endif /* SC_PROVIDER_COMMON_H */
