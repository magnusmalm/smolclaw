/*
 * util/curl_common.h - Centralized curl handle initialization
 *
 * All curl handles should be created via sc_curl_init() to ensure
 * consistent protocol restrictions and CA certificate configuration.
 * After curl_easy_reset(), call sc_curl_apply_defaults() to restore.
 */

#ifndef SC_CURL_COMMON_H
#define SC_CURL_COMMON_H

#include <curl/curl.h>

/* Create a curl handle with protocol restrictions and CA bundle configured.
 * Use this instead of curl_easy_init() everywhere. */
CURL *sc_curl_init(void);

/* Re-apply protocol restrictions and CA bundle after curl_easy_reset(). */
void sc_curl_apply_defaults(CURL *curl);

#endif /* SC_CURL_COMMON_H */
