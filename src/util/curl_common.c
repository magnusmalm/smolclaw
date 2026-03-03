/*
 * util/curl_common.c - Centralized curl handle initialization
 *
 * Every curl handle gets protocol restrictions (http/https only) and
 * a CA certificate bundle for TLS verification. The CA path is probed
 * on each call — a few access() syscalls are negligible vs an HTTPS
 * round-trip, and this allows hot-swapping via CURL_CA_BUNDLE env var.
 */

#include <unistd.h>
#include <stdlib.h>

#include "util/curl_common.h"

static const char *known_ca_paths[] = {
    "/etc/ssl/certs/ca-certificates.crt",  /* Debian/Ubuntu */
    "/etc/pki/tls/certs/ca-bundle.crt",    /* RHEL/Fedora */
    "/etc/ssl/cert.pem",                    /* Alpine/macOS */
    "/etc/ssl/certs/ca-bundle.crt",         /* openSUSE */
    NULL
};

const char *sc_curl_find_ca_bundle(void)
{
    const char *env = getenv("CURL_CA_BUNDLE");
    if (env && access(env, R_OK) == 0) return env;

    env = getenv("SSL_CERT_FILE");
    if (env && access(env, R_OK) == 0) return env;

    for (const char **p = known_ca_paths; *p; p++) {
        if (access(*p, R_OK) == 0) return *p;
    }
    return NULL;
}

void sc_curl_apply_defaults(CURL *curl)
{
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
    const char *ca = sc_curl_find_ca_bundle();
    if (ca)
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca);
}

CURL *sc_curl_init(void)
{
    CURL *curl = curl_easy_init();
    if (curl)
        sc_curl_apply_defaults(curl);
    return curl;
}
