/*
 * providers/provider_common.c - Shared curl callbacks and helpers
 *
 * Common code shared between claude.c and http.c providers.
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "providers/provider_common.h"
#include "util/curl_common.h"
#include "constants.h"

int sc_curl_progress_cb(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
                        curl_off_t ultotal, curl_off_t ulnow)
{
    (void)clientp; (void)dltotal; (void)dlnow; (void)ultotal; (void)ulnow;
    return sc_shutdown_requested() ? 1 : 0;
}

size_t sc_curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    sc_strbuf_t *sb = userdata;
    size_t total = size * nmemb;
    if (sb->len + total > SC_CURL_MAX_RESPONSE) return 0;
    char *tmp = malloc(total + 1);
    memcpy(tmp, ptr, total);
    tmp[total] = '\0';
    sc_strbuf_append(sb, tmp);
    free(tmp);
    return total;
}

size_t sc_header_cb(char *buffer, size_t size, size_t nitems, void *userdata)
{
    size_t total = size * nitems;
    sc_header_ctx_t *ctx = userdata;
    if (total > 13 && strncasecmp(buffer, "retry-after:", 12) == 0) {
        const char *val = buffer + 12;
        while (*val == ' ') val++;
        int secs = atoi(val);
        if (secs > 0 && secs <= 3600) ctx->retry_after = secs;
    }
    return total;
}

sc_llm_response_t *sc_provider_make_error_response(int http_status,
                                                    int retry_after)
{
    sc_llm_response_t *err = calloc(1, sizeof(*err));
    if (err) {
        err->http_status = http_status;
        err->retry_after_secs = retry_after;
    }
    return err;
}

void sc_provider_trim_base_url(char *url)
{
    if (!url) return;
    size_t len = strlen(url);
    while (len > 0 && url[len - 1] == '/') {
        url[--len] = '\0';
    }
}

CURL *sc_provider_init_curl(void)
{
    return sc_curl_init();
}

struct curl_slist *sc_provider_setup_curl(CURL *curl, const char *url,
                                           const char *api_key,
                                           const char *auth_prefix,
                                           const char *body_str,
                                           const char *proxy,
                                           sc_header_ctx_t *hdr_ctx,
                                           curl_write_callback write_fn,
                                           void *write_data, long timeout,
                                           const char **extra_headers)
{
    curl_easy_reset(curl);
    sc_curl_apply_defaults(curl);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    if (api_key && api_key[0] != '\0') {
        sc_strbuf_t auth;
        sc_strbuf_init(&auth);
        sc_strbuf_append(&auth, auth_prefix);
        sc_strbuf_append(&auth, api_key);
        char *auth_hdr = sc_strbuf_finish(&auth);
        headers = curl_slist_append(headers, auth_hdr);
        free(auth_hdr);
    }

    if (extra_headers) {
        for (const char **h = extra_headers; *h; h++)
            headers = curl_slist_append(headers, *h);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_fn);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, write_data);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, sc_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, hdr_ctx);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, sc_curl_progress_cb);

    if (proxy && proxy[0] != '\0')
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy);

    return headers;
}
