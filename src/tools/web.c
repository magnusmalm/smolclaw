/*
 * tools/web.c - Web search and fetch tools
 *
 * web_search: Brave API (JSON) or DuckDuckGo (HTML scraping)
 * web_fetch: GET URL, strip HTML, return text
 *
 * Uses libcurl for HTTP.
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <ctype.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <curl/curl.h>

#include "util/curl_common.h"
#include "tools/web.h"
#include "audit.h"
#include "tools/types.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "logger.h"
#include "constants.h"
#include "cJSON.h"

/* Test-only SSRF bypass flag — not settable via environment (H-1 hardening) */
static int ssrf_bypass_enabled = 0;

void sc_web_set_ssrf_bypass(int enabled)
{
    ssrf_bypass_enabled = enabled;
}

/* ---------- realistic browser headers ---------- */

/* Rotate through recent Chrome UAs to avoid fingerprinting on a stale version */
static const char *const BROWSER_UAS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
};
#define NUM_UAS (sizeof(BROWSER_UAS) / sizeof(BROWSER_UAS[0]))

static const char *get_browser_ua(void)
{
    static _Atomic unsigned idx = 0;
    return BROWSER_UAS[idx++ % NUM_UAS];
}

/* Standard browser headers that real Chrome sends */
static struct curl_slist *append_browser_headers(struct curl_slist *list)
{
    list = curl_slist_append(list, "Accept: text/html,application/xhtml+xml,"
        "application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8");
    list = curl_slist_append(list, "Accept-Language: en-US,en;q=0.9");
    list = curl_slist_append(list, "Accept-Encoding: gzip, deflate, br");
    list = curl_slist_append(list, "Sec-Fetch-Dest: document");
    list = curl_slist_append(list, "Sec-Fetch-Mode: navigate");
    list = curl_slist_append(list, "Sec-Fetch-Site: none");
    list = curl_slist_append(list, "Sec-Fetch-User: ?1");
    list = curl_slist_append(list, "Upgrade-Insecure-Requests: 1");
    return list;
}

/* Build a Google search referer from a URL's domain.
 * Returns static "" for IPs/localhost, or an allocated string. Caller frees. */
static char *generate_referer(const char *url)
{
    const char *start = strstr(url, "://");
    if (!start) return NULL;
    start += 3;
    /* Skip userinfo */
    const char *at = strchr(start, '@');
    const char *slash = strchr(start, '/');
    if (at && (!slash || at < slash)) start = at + 1;
    if (*start == '[') return NULL; /* IPv6 literal */

    const char *end = start;
    while (*end && *end != '/' && *end != ':' && *end != '?') end++;
    size_t len = (size_t)(end - start);
    if (len == 0) return NULL;

    /* Skip IP addresses and localhost */
    int all_digits_dots = 1;
    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)start[i]) && start[i] != '.')
            { all_digits_dots = 0; break; }
    }
    if (all_digits_dots) return NULL;
    if (len == 9 && strncmp(start, "localhost", 9) == 0) return NULL;

    /* Extract the main domain (strip subdomain, keep TLD).
     * For "www.example.com" → "example", "sub.deep.example.co.uk" → "example" */
    char host[256];
    if (len >= sizeof(host)) return NULL;
    memcpy(host, start, len);
    host[len] = '\0';

    /* Find second-to-last dot to get domain name */
    const char *last_dot = strrchr(host, '.');
    if (!last_dot || last_dot == host) {
        /* No TLD (e.g. "localhost") — use as-is */
        char buf[512];
        snprintf(buf, sizeof(buf), "https://www.google.com/search?q=%s", host);
        return sc_strdup(buf);
    }
    const char *domain_start = host;
    for (const char *p = last_dot - 1; p >= host; p--) {
        if (*p == '.') { domain_start = p + 1; break; }
    }
    /* domain_start now points to "example.com" or similar — extract just the name */
    size_t dlen = (size_t)(last_dot - domain_start);
    if (dlen == 0 || dlen >= 128) return NULL;
    char domain[128];
    memcpy(domain, domain_start, dlen);
    domain[dlen] = '\0';

    char buf[512];
    snprintf(buf, sizeof(buf), "https://www.google.com/search?q=%s", domain);
    return sc_strdup(buf);
}

/* ---------- curl write callback ---------- */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} curl_buf_t;

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    curl_buf_t *buf = userdata;
    if (nmemb > 0 && size > SIZE_MAX / nmemb) return 0;
    size_t total = size * nmemb;
    if (buf->len + total > SC_CURL_MAX_RESPONSE) return 0;

    if (buf->len + total >= buf->cap) {
        size_t new_cap = (buf->cap + total) * 2;
        char *tmp = realloc(buf->data, new_cap);
        if (!tmp) return 0;
        buf->data = tmp;
        buf->cap = new_cap;
    }

    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

static void curl_buf_init(curl_buf_t *buf)
{
    buf->cap = 4096;
    buf->data = malloc(buf->cap);
    buf->len = 0;
    if (buf->data) buf->data[0] = '\0';
}

static void curl_buf_free(curl_buf_t *buf)
{
    free(buf->data);
    buf->data = NULL;
    buf->len = buf->cap = 0;
}

/* Perform a GET request. pin_host/pin_ip: if both non-NULL, set CURLOPT_RESOLVE
 * to pin DNS resolution (prevents DNS rebinding). Returns allocated body or NULL.
 * NOTE: Follows redirects without SSRF re-check — only use for trusted URLs
 * (e.g. search API endpoints). For untrusted URLs, use http_get_no_follow()
 * with per-hop SSRF validation (as web_fetch does). */
static char *http_get(const char *url, const char *const *headers, int header_count,
                      long *status_out, const char *pin_host, const char *pin_ip)
{
    CURL *curl = sc_curl_init();
    if (!curl) return NULL;

    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");

    curl_buf_t buf;
    curl_buf_init(&buf);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, get_browser_ua());
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, ""); /* let curl handle */

    /* Pin DNS resolution to prevent rebinding between check and fetch */
    struct curl_slist *resolve_list = NULL;
    if (pin_host && pin_ip) {
        /* Extract port from URL, default to 80/443 */
        int port = 80;
        if (strncmp(url, "https://", 8) == 0) port = 443;
        /* Check for explicit port in URL */
        const char *host_start = strstr(url, "://");
        if (host_start) {
            host_start += 3;
            const char *colon = strchr(host_start, ':');
            const char *slash = strchr(host_start, '/');
            const char *bracket = strchr(host_start, ']');
            /* Skip IPv6 bracket colons */
            if (bracket && colon && colon > bracket) {
                colon = strchr(bracket, ':');
            }
            if (colon && (!slash || colon < slash)) {
                int p = atoi(colon + 1);
                if (p > 0 && p <= 65535) port = p;
            }
        }
        char resolve_entry[512];
        snprintf(resolve_entry, sizeof(resolve_entry), "%s:%d:%s",
                 pin_host, port, pin_ip);
        resolve_list = curl_slist_append(resolve_list, resolve_entry);
        curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve_list);
    }

    struct curl_slist *hlist = NULL;
    for (int i = 0; i < header_count; i++)
        hlist = curl_slist_append(hlist, headers[i]);
    if (hlist)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hlist);

    CURLcode res = curl_easy_perform(curl);

    if (status_out) {
        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        *status_out = code;
    }

    curl_slist_free_all(hlist);
    curl_slist_free_all(resolve_list);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        curl_buf_free(&buf);
        return NULL;
    }

    return buf.data; /* caller owns */
}

/* Like http_get() but with CURLOPT_FOLLOWLOCATION disabled.
 * Used for web_fetch to manually follow redirects with SSRF re-checks.
 * redirect_url_out: if non-NULL and response is a redirect, receives the Location URL. */
static char *http_get_no_follow(const char *url, const char *const *headers, int header_count,
                                 long *status_out, const char *pin_host, const char *pin_ip,
                                 char **redirect_url_out)
{
    CURL *curl = sc_curl_init();
    if (!curl) return NULL;

    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");

    curl_buf_t buf;
    curl_buf_init(&buf);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, get_browser_ua());
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    /* Pin DNS resolution to prevent rebinding between check and fetch */
    struct curl_slist *resolve_list = NULL;
    if (pin_host && pin_ip) {
        int port = 80;
        if (strncmp(url, "https://", 8) == 0) port = 443;
        const char *host_start = strstr(url, "://");
        if (host_start) {
            host_start += 3;
            const char *colon = strchr(host_start, ':');
            const char *slash = strchr(host_start, '/');
            const char *bracket = strchr(host_start, ']');
            if (bracket && colon && colon > bracket)
                colon = strchr(bracket, ':');
            if (colon && (!slash || colon < slash)) {
                int p = atoi(colon + 1);
                if (p > 0 && p <= 65535) port = p;
            }
        }
        char resolve_entry[512];
        snprintf(resolve_entry, sizeof(resolve_entry), "%s:%d:%s",
                 pin_host, port, pin_ip);
        resolve_list = curl_slist_append(resolve_list, resolve_entry);
        curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve_list);
    }

    /* Browser-like headers: Accept, Sec-Fetch-*, etc. */
    struct curl_slist *hlist = append_browser_headers(NULL);
    /* Google search referer for organic-looking traffic */
    char *referer = generate_referer(url);
    if (referer) {
        char refhdr[600];
        snprintf(refhdr, sizeof(refhdr), "Referer: %s", referer);
        hlist = curl_slist_append(hlist, refhdr);
        free(referer);
    }
    for (int i = 0; i < header_count; i++)
        hlist = curl_slist_append(hlist, headers[i]);
    if (hlist)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hlist);

    CURLcode res = curl_easy_perform(curl);

    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (status_out) *status_out = code;

    /* Extract redirect URL if this is a redirect response */
    if (redirect_url_out) {
        *redirect_url_out = NULL;
        if (code >= 301 && code <= 308 && code != 304) {
            char *redir = NULL;
            curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redir);
            if (redir)
                *redirect_url_out = sc_strdup(redir);
        }
    }

    curl_slist_free_all(hlist);
    curl_slist_free_all(resolve_list);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        curl_buf_free(&buf);
        return NULL;
    }

    return buf.data;
}

/* URL-encode a string. Caller owns result. */
static char *url_encode(const char *str)
{
    CURL *curl = sc_curl_init();
    if (!curl) return sc_strdup(str);
    char *encoded = curl_easy_escape(curl, str, 0);
    char *result = sc_strdup(encoded);
    curl_free(encoded);
    curl_easy_cleanup(curl);
    return result;
}

/* Strip all HTML tags from text. Also removes <script> and <style> blocks. */
static char *strip_html(const char *html)
{
    if (!html) return sc_strdup("");

    size_t len = strlen(html);
    char *out = malloc(len + 1);
    if (!out) return sc_strdup("");

    size_t j = 0;
    int in_tag = 0;
    int in_script = 0;
    int in_style = 0;

    for (size_t i = 0; i < len; i++) {
        /* Check for <script or <style opening tags */
        if (html[i] == '<') {
            if (i + 7 < len && strncasecmp(html + i, "<script", 7) == 0) {
                in_script = 1;
                in_tag = 1;
                continue;
            }
            if (i + 6 < len && strncasecmp(html + i, "<style", 6) == 0) {
                in_style = 1;
                in_tag = 1;
                continue;
            }
            /* Check for closing script/style */
            if (i + 8 < len && strncasecmp(html + i, "</script", 8) == 0) {
                in_script = 0;
                in_tag = 1;
                continue;
            }
            if (i + 7 < len && strncasecmp(html + i, "</style", 7) == 0) {
                in_style = 0;
                in_tag = 1;
                continue;
            }
            in_tag = 1;
            continue;
        }

        if (html[i] == '>') {
            in_tag = 0;
            continue;
        }

        if (!in_tag && !in_script && !in_style)
            out[j++] = html[i];
    }
    out[j] = '\0';

    /* Collapse whitespace */
    char *clean = malloc(j + 1);
    if (!clean) { free(out); return sc_strdup(""); }
    size_t k = 0;
    int last_space = 0;
    for (size_t i = 0; i < j; i++) {
        if (isspace((unsigned char)out[i])) {
            if (out[i] == '\n') {
                if (k > 0 && clean[k - 1] != '\n')
                    clean[k++] = '\n';
                last_space = 1;
            } else if (!last_space) {
                clean[k++] = ' ';
                last_space = 1;
            }
        } else {
            clean[k++] = out[i];
            last_space = 0;
        }
    }
    clean[k] = '\0';
    free(out);
    return clean;
}

/* ========== web_search ========== */

typedef struct {
    int brave_enabled;
    char *brave_api_key;
    char *brave_base_url;
    int brave_max_results;
    int searxng_enabled;
    char *searxng_base_url;
    int searxng_max_results;
    int duckduckgo_enabled;
    int duckduckgo_max_results;
} web_search_data_t;

static void web_search_destroy(sc_tool_t *self)
{
    if (!self) return;
    web_search_data_t *d = self->data;
    if (d) {
        free(d->brave_api_key);
        free(d->brave_base_url);
        free(d->searxng_base_url);
        free(d);
    }
    free(self);
}

static cJSON *web_search_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");

    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *query = cJSON_AddObjectToObject(props, "query");
    cJSON_AddStringToObject(query, "type", "string");
    cJSON_AddStringToObject(query, "description", "Search query");

    cJSON *count = cJSON_AddObjectToObject(props, "count");
    cJSON_AddStringToObject(count, "type", "integer");
    cJSON_AddStringToObject(count, "description", "Number of results (1-10)");
    cJSON_AddNumberToObject(count, "minimum", 1);
    cJSON_AddNumberToObject(count, "maximum", 10);

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("query"));
    return schema;
}

/* Parse Brave search JSON response */
static char *parse_brave_results(const char *json_body, const char *query, int max_results)
{
    cJSON *root = cJSON_Parse(json_body);
    if (!root)
        return sc_strdup("Failed to parse search results");

    cJSON *web = cJSON_GetObjectItem(root, "web");
    cJSON *results = web ? cJSON_GetObjectItem(web, "results") : NULL;

    if (!results || cJSON_GetArraySize(results) == 0) {
        cJSON_Delete(root);
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "No results for: %s", query);
        return sc_strbuf_finish(&sb);
    }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Results for: %s\n", query);

    int count = cJSON_GetArraySize(results);
    if (count > max_results) count = max_results;

    for (int i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(results, i);
        const char *title = sc_json_get_string(item, "title", "");
        const char *url = sc_json_get_string(item, "url", "");
        const char *desc = sc_json_get_string(item, "description", "");

        sc_strbuf_appendf(&sb, "%d. %s\n   %s\n", i + 1, title, url);
        if (desc[0])
            sc_strbuf_appendf(&sb, "   %s\n", desc);
    }

    cJSON_Delete(root);
    return sc_strbuf_finish(&sb);
}

/* Parse SearXNG JSON response */
static char *parse_searxng_results(const char *json_body, const char *query, int max_results)
{
    cJSON *root = cJSON_Parse(json_body);
    if (!root)
        return sc_strdup("Failed to parse SearXNG results");

    cJSON *results = cJSON_GetObjectItem(root, "results");

    if (!results || cJSON_GetArraySize(results) == 0) {
        cJSON_Delete(root);
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "No results for: %s", query);
        return sc_strbuf_finish(&sb);
    }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Results for: %s\n", query);

    int count = cJSON_GetArraySize(results);
    if (count > max_results) count = max_results;

    for (int i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(results, i);
        const char *title = sc_json_get_string(item, "title", "");
        const char *url = sc_json_get_string(item, "url", "");
        const char *content = sc_json_get_string(item, "content", "");

        sc_strbuf_appendf(&sb, "%d. %s\n   %s\n", i + 1, title, url);
        if (content[0])
            sc_strbuf_appendf(&sb, "   %s\n", content);
    }

    cJSON_Delete(root);
    return sc_strbuf_finish(&sb);
}

/* Extract results from DuckDuckGo HTML. Simple string-based extraction. */
static char *parse_ddg_results(const char *html, const char *query, int max_results)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Results for: %s (via DuckDuckGo)\n", query);

    /* Look for result__a links: <a ... class="result__a" ... href="...">title</a> */
    const char *pos = html;
    int found = 0;

    while (found < max_results && pos && *pos) {
        /* Find class="result__a" */
        const char *class_pos = strstr(pos, "result__a");
        if (!class_pos) break;

        /* Find the enclosing <a tag by searching backwards for '<a' */
        const char *a_start = class_pos;
        while (a_start > html && !(a_start[0] == '<' && (a_start[1] == 'a' || a_start[1] == 'A')))
            a_start--;
        if (a_start <= html) { pos = class_pos + 9; continue; }

        /* Extract href */
        const char *href = strstr(a_start, "href=\"");
        if (!href || href > class_pos + 200) { pos = class_pos + 9; continue; }
        href += 6;
        const char *href_end = strchr(href, '"');
        if (!href_end) { pos = class_pos + 9; continue; }

        size_t href_len = (size_t)(href_end - href);
        char *url_str = malloc(href_len + 1);
        if (!url_str) break;
        memcpy(url_str, href, href_len);
        url_str[href_len] = '\0';

        /* Extract title: text between > and </a> */
        const char *tag_close = strchr(class_pos, '>');
        if (!tag_close) { free(url_str); pos = class_pos + 9; continue; }
        tag_close++;
        const char *a_end = strstr(tag_close, "</a>");
        if (!a_end) { free(url_str); pos = class_pos + 9; continue; }

        size_t title_html_len = (size_t)(a_end - tag_close);
        char *title_html = malloc(title_html_len + 1);
        if (!title_html) { free(url_str); break; }
        memcpy(title_html, tag_close, title_html_len);
        title_html[title_html_len] = '\0';

        char *title = strip_html(title_html);
        free(title_html);

        /* Decode DDG redirect URL (contains uddg= parameter) */
        char *actual_url = url_str;
        char *uddg = strstr(url_str, "uddg=");
        if (uddg) {
            CURL *dec = sc_curl_init();
            if (dec) {
                int out_len = 0;
                char *decoded = curl_easy_unescape(dec, uddg + 5, 0, &out_len);
                if (decoded) {
                    /* Find end (next & or end of string) */
                    char *amp = strchr(decoded, '&');
                    if (amp) *amp = '\0';
                    free(url_str);
                    actual_url = sc_strdup(decoded);
                    curl_free(decoded);
                }
                curl_easy_cleanup(dec);
            }
        }

        found++;
        sc_strbuf_appendf(&sb, "%d. %s\n   %s\n", found,
                          title ? title : "(no title)",
                          actual_url ? actual_url : "");

        free(title);
        free(actual_url);
        pos = a_end + 4;
    }

    if (found == 0)
        sc_strbuf_appendf(&sb, "No results found for: %s", query);

    return sc_strbuf_finish(&sb);
}

static sc_tool_result_t *web_search_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    web_search_data_t *d = self->data;

    const char *query = sc_json_get_string(args, "query", NULL);
    if (!query)
        return sc_tool_result_error("query is required");

    int count = sc_json_get_int(args, "count", 0);

    char *result_text = NULL;

    if (d->brave_enabled && d->brave_api_key && d->brave_api_key[0]) {
        int max = (count > 0 && count <= 10) ? count : d->brave_max_results;
        if (max <= 0) max = SC_MAX_SEARCH_RESULTS;

        /* Build URL */
        char *encoded_q = url_encode(query);
        const char *base = (d->brave_base_url && d->brave_base_url[0])
            ? d->brave_base_url : "https://api.search.brave.com";
        sc_strbuf_t urlbuf;
        sc_strbuf_init(&urlbuf);
        sc_strbuf_appendf(&urlbuf,
            "%s/res/v1/web/search?q=%s&count=%d",
            base, encoded_q, max);
        char *url = sc_strbuf_finish(&urlbuf);
        free(encoded_q);

        /* Headers */
        sc_strbuf_t hdr;
        sc_strbuf_init(&hdr);
        sc_strbuf_appendf(&hdr, "X-Subscription-Token: %s", d->brave_api_key);
        char *token_hdr = sc_strbuf_finish(&hdr);
        const char *headers[] = {
            "Accept: application/json",
            token_hdr
        };

        long status = 0;
        char *body = http_get(url, headers, 2, &status, NULL, NULL);
        free(url);
        free(token_hdr);

        if (body) {
            result_text = parse_brave_results(body, query, max);
            free(body);
        } else {
            result_text = sc_strdup("Brave search request failed");
        }
    } else if (d->searxng_enabled && d->searxng_base_url && d->searxng_base_url[0]) {
        int max = (count > 0 && count <= 10) ? count : d->searxng_max_results;
        if (max <= 0) max = SC_MAX_SEARCH_RESULTS;

        char *encoded_q = url_encode(query);
        sc_strbuf_t urlbuf;
        sc_strbuf_init(&urlbuf);
        sc_strbuf_appendf(&urlbuf, "%s/search?q=%s&format=json&pageno=1",
                          d->searxng_base_url, encoded_q);
        char *url = sc_strbuf_finish(&urlbuf);
        free(encoded_q);

        long status = 0;
        char *body = http_get(url, NULL, 0, &status, NULL, NULL);
        free(url);

        if (body) {
            result_text = parse_searxng_results(body, query, max);
            free(body);
        } else {
            result_text = sc_strdup("SearXNG search request failed");
        }
    } else if (d->duckduckgo_enabled) {
        int max = (count > 0 && count <= 10) ? count : d->duckduckgo_max_results;
        if (max <= 0) max = SC_MAX_SEARCH_RESULTS;

        char *encoded_q = url_encode(query);
        sc_strbuf_t urlbuf;
        sc_strbuf_init(&urlbuf);
        sc_strbuf_appendf(&urlbuf, "https://html.duckduckgo.com/html/?q=%s", encoded_q);
        char *url = sc_strbuf_finish(&urlbuf);
        free(encoded_q);

        long status = 0;
        char *body = http_get(url, NULL, 0, &status, NULL, NULL);
        free(url);

        if (body) {
            result_text = parse_ddg_results(body, query, max);
            free(body);
        } else {
            result_text = sc_strdup("DuckDuckGo search request failed");
        }
    } else {
        return sc_tool_result_error("No search provider configured");
    }

    sc_tool_result_t *result = sc_tool_result_user(result_text);
    free(result_text);
    return result;
}

sc_tool_t *sc_tool_web_search_new(sc_web_search_opts_t opts)
{
    /* Disable providers with missing credentials/config */
    if (opts.brave_enabled && (!opts.brave_api_key || !opts.brave_api_key[0]))
        opts.brave_enabled = 0;
    if (opts.searxng_enabled && (!opts.searxng_base_url || !opts.searxng_base_url[0]))
        opts.searxng_enabled = 0;

    /* Must have at least one provider */
    if (!opts.brave_enabled && !opts.searxng_enabled && !opts.duckduckgo_enabled)
        return NULL;

    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    web_search_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(t); return NULL; }

    d->brave_enabled = opts.brave_enabled;
    d->brave_api_key = sc_strdup(opts.brave_api_key);
    d->brave_base_url = sc_strdup(opts.brave_base_url);
    d->brave_max_results = opts.brave_max_results > 0 ? opts.brave_max_results : SC_MAX_SEARCH_RESULTS;
    d->searxng_enabled = opts.searxng_enabled;
    d->searxng_base_url = sc_strdup(opts.searxng_base_url);
    d->searxng_max_results = opts.searxng_max_results > 0 ? opts.searxng_max_results : SC_MAX_SEARCH_RESULTS;
    d->duckduckgo_enabled = opts.duckduckgo_enabled;
    d->duckduckgo_max_results = opts.duckduckgo_max_results > 0 ? opts.duckduckgo_max_results : SC_MAX_SEARCH_RESULTS;

    t->name = "web_search";
    t->description = "Search the web for current information. Returns titles, URLs, and snippets.";
    t->parameters = web_search_parameters;
    t->execute = web_search_execute;
    t->destroy = web_search_destroy;
    t->data = d;
    return t;
}

/* ---------- SSRF protection ---------- */

/* Check if an IPv4 address is in a private/reserved range */
static int is_private_ipv4(const struct in_addr *addr)
{
    uint32_t ip = ntohl(addr->s_addr);
    /* 127.0.0.0/8 */
    if ((ip >> 24) == 127) return 1;
    /* 10.0.0.0/8 */
    if ((ip >> 24) == 10) return 1;
    /* 172.16.0.0/12 */
    if ((ip >> 20) == (172 << 4 | 1)) return 1;
    /* 192.168.0.0/16 */
    if ((ip >> 16) == (192 << 8 | 168)) return 1;
    /* 169.254.0.0/16 (link-local / cloud metadata) */
    if ((ip >> 16) == (169 << 8 | 254)) return 1;
    /* 0.0.0.0 */
    if (ip == 0) return 1;
    /* 100.64.0.0/10 (CGNAT, RFC 6598) */
    if ((ip >> 22) == (100 << 2 | 1)) return 1;
    /* 198.51.100.0/24 (TEST-NET-2) */
    if ((ip >> 8) == (198 << 16 | 51 << 8 | 100)) return 1;
    /* 203.0.113.0/24 (TEST-NET-3) */
    if ((ip >> 8) == (203 << 16 | 0 << 8 | 113)) return 1;
    /* 240.0.0.0/4 (reserved/future) */
    if ((ip >> 28) == 15) return 1;
    /* 255.255.255.255 (broadcast) */
    if (ip == 0xFFFFFFFF) return 1;
    return 0;
}

/* Check if an IPv6 address is private/reserved */
static int is_private_ipv6(const struct in6_addr *addr)
{
    const uint8_t *b = addr->s6_addr;

    /* ::1 (loopback) */
    static const uint8_t lo[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (memcmp(b, lo, 16) == 0) return 1;

    /* :: (unspecified) */
    static const uint8_t zero[16] = {0};
    if (memcmp(b, zero, 16) == 0) return 1;

    /* ::ffff:x.x.x.x (IPv4-mapped) — delegate to IPv4 check */
    if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 &&
        b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
        b[8] == 0 && b[9] == 0 && b[10] == 0xff && b[11] == 0xff) {
        struct in_addr v4;
        memcpy(&v4.s_addr, &b[12], 4);
        return is_private_ipv4(&v4);
    }

    /* fe80::/10 (link-local) */
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return 1;

    /* fc00::/7 (unique local address) */
    if ((b[0] & 0xfe) == 0xfc) return 1;

    return 0;
}

/* Extract hostname from URL (between :// and next / or :)
 * Handles IPv6 bracket notation: http://[::1]:8080/path */
static char *extract_hostname(const char *url)
{
    const char *start = strstr(url, "://");
    if (!start) return NULL;
    start += 3;
    /* Skip any userinfo@ */
    const char *at = strchr(start, '@');
    const char *slash = strchr(start, '/');
    if (at && (!slash || at < slash)) start = at + 1;

    /* IPv6 bracket notation */
    if (*start == '[') {
        const char *bracket_end = strchr(start, ']');
        if (!bracket_end) return NULL;
        size_t len = (size_t)(bracket_end - start - 1);
        if (len == 0) return NULL;
        char *host = malloc(len + 1);
        if (!host) return NULL;
        memcpy(host, start + 1, len);
        host[len] = '\0';
        return host;
    }

    const char *end = start;
    while (*end && *end != '/' && *end != ':' && *end != '?')
        end++;

    size_t len = (size_t)(end - start);
    if (len == 0) return NULL;
    char *host = malloc(len + 1);
    if (!host) return NULL;
    memcpy(host, start, len);
    host[len] = '\0';
    return host;
}

/* SSRF result: error message (NULL if ok), resolved IP for DNS pinning */
typedef struct {
    const char *error;   /* static string or NULL */
    char resolved_ip[64]; /* first valid resolved IP for CURLOPT_RESOLVE */
    char hostname[256];   /* extracted hostname for CURLOPT_RESOLVE */
} ssrf_result_t;

/* Check URL for SSRF. Populates result with error or resolved IP for pinning. */
static ssrf_result_t check_ssrf(const char *url)
{
    ssrf_result_t res = { .error = NULL };
    res.resolved_ip[0] = '\0';
    res.hostname[0] = '\0';

    /* Allow tests to bypass SSRF checks for mock server on localhost.
     * Uses internal flag (not env var) to prevent injection (H-1). */
    if (ssrf_bypass_enabled) return res;

    char *host = extract_hostname(url);
    if (!host) { res.error = "could not parse hostname from URL"; return res; }

    /* Save hostname for DNS pinning */
    size_t hlen = strlen(host);
    if (hlen < sizeof(res.hostname))
        memcpy(res.hostname, host, hlen + 1);

    /* Block known metadata hostnames */
    if (strcasecmp(host, "metadata.google.internal") == 0 ||
        strcasecmp(host, "metadata") == 0) {
        free(host);
        res.error = "blocked: cloud metadata endpoint";
        return res;
    }

    /* Resolve with AF_UNSPEC to check both IPv4 and IPv6 */
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    struct addrinfo *result = NULL;
    int rc = getaddrinfo(host, NULL, &hints, &result);
    if (rc != 0) {
        free(host);
        res.error = "could not resolve hostname";
        return res;
    }

    int blocked = 0;
    int got_ip = 0;
    for (struct addrinfo *rp = result; rp; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)rp->ai_addr;
            if (is_private_ipv4(&sin->sin_addr)) { blocked = 1; break; }
            if (!got_ip) {
                inet_ntop(AF_INET, &sin->sin_addr, res.resolved_ip,
                          sizeof(res.resolved_ip));
                got_ip = 1;
            }
        } else if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)rp->ai_addr;
            if (is_private_ipv6(&sin6->sin6_addr)) { blocked = 1; break; }
            if (!got_ip) {
                inet_ntop(AF_INET6, &sin6->sin6_addr, res.resolved_ip,
                          sizeof(res.resolved_ip));
                got_ip = 1;
            }
        }
    }
    freeaddrinfo(result);
    free(host);

    if (blocked)
        res.error = "blocked: URL resolves to private/reserved IP (SSRF protection)";
    return res;
}

/* ========== web_fetch ========== */

typedef struct {
    int max_chars;
} web_fetch_data_t;

static void web_fetch_destroy(sc_tool_t *self)
{
    if (!self) return;
    free(self->data);
    free(self);
}

static cJSON *web_fetch_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");

    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *url = cJSON_AddObjectToObject(props, "url");
    cJSON_AddStringToObject(url, "type", "string");
    cJSON_AddStringToObject(url, "description", "URL to fetch");

    cJSON *max = cJSON_AddObjectToObject(props, "maxChars");
    cJSON_AddStringToObject(max, "type", "integer");
    cJSON_AddStringToObject(max, "description", "Maximum characters to extract");
    cJSON_AddNumberToObject(max, "minimum", 100);

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("url"));
    return schema;
}

static sc_tool_result_t *web_fetch_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    web_fetch_data_t *d = self->data;

    const char *url_str = sc_json_get_string(args, "url", NULL);
    if (!url_str)
        return sc_tool_result_error("url is required");

    /* Validate URL scheme */
    if (strncmp(url_str, "http://", 7) != 0 && strncmp(url_str, "https://", 8) != 0)
        return sc_tool_result_error("only http/https URLs are allowed");

    /* SSRF check — block private/reserved IPs (IPv4 + IPv6) */
    ssrf_result_t ssrf = check_ssrf(url_str);
    if (ssrf.error) {
        sc_audit_log("web_fetch", ssrf.error, 1, 0);
        return sc_tool_result_error(ssrf.error);
    }

    int max_chars = sc_json_get_int(args, "maxChars", d->max_chars);
    if (max_chars < 100) max_chars = d->max_chars;

    /* Retry loop with redirect following and SSRF re-check at each hop */
    char *body = NULL;
    long status = 0;

    for (int attempt = 0; attempt <= SC_WEB_FETCH_RETRIES; attempt++) {
        if (attempt > 0)
            sleep(SC_WEB_FETCH_RETRY_DELAY);

        char *current_url = sc_strdup(url_str);
        int fetch_ok = 0;

        for (int hop = 0; hop <= SC_WEB_MAX_REDIRECTS; hop++) {
            ssrf_result_t hop_ssrf = (hop == 0) ? ssrf : check_ssrf(current_url);
            if (hop_ssrf.error) {
                sc_audit_log_ext("web_fetch", hop_ssrf.error, 1, 0,
                                 NULL, NULL, "ssrf_redirect");
                free(current_url);
                return sc_tool_result_error(hop_ssrf.error);
            }

            const char *pin_host = hop_ssrf.hostname[0] ? hop_ssrf.hostname : NULL;
            const char *pin_ip = hop_ssrf.resolved_ip[0] ? hop_ssrf.resolved_ip : NULL;

            char *redirect_url = NULL;
            body = http_get_no_follow(current_url, NULL, 0, &status,
                                       pin_host, pin_ip, &redirect_url);

            if (!body && !redirect_url) {
                /* Transient failure — break to retry loop */
                break;
            }

            if (redirect_url) {
                free(body);
                body = NULL;
                free(current_url);
                current_url = redirect_url;
                continue;
            }

            fetch_ok = 1;
            break; /* Not a redirect — we have the body */
        }

        free(current_url);

        if (fetch_ok && body)
            break;

        /* Clean up before retry */
        free(body);
        body = NULL;

        if (attempt < SC_WEB_FETCH_RETRIES)
            SC_LOG_WARN("web_fetch", "attempt %d failed, retrying...",
                        attempt + 1);
    }

    if (!body)
        return sc_tool_result_error("request failed after retries");

    /* Determine content type heuristically and extract text */
    char *text;
    const char *extractor;

    /* Try JSON first */
    cJSON *json = cJSON_Parse(body);
    if (json) {
        text = cJSON_Print(json);
        cJSON_Delete(json);
        extractor = "json";
    } else if (strstr(body, "<!DOCTYPE") || strstr(body, "<html") || strstr(body, "<HTML")) {
        text = strip_html(body);
        extractor = "text";
    } else {
        text = sc_strdup(body);
        extractor = "raw";
    }
    free(body);

    int truncated = 0;
    size_t text_len = text ? strlen(text) : 0;
    if ((int)text_len > max_chars) {
        text[max_chars] = '\0';
        text_len = (size_t)max_chars;
        truncated = 1;
    }

    /* Build result for LLM */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Fetched %zu bytes from %s (extractor: %s, truncated: %s)\n\n%s",
                      text_len, url_str, extractor,
                      truncated ? "true" : "false",
                      text ? text : "");
    char *result_str = sc_strbuf_finish(&sb);
    free(text);

    sc_tool_result_t *result = sc_tool_result_user(result_str);
    free(result_str);
    return result;
}

sc_tool_t *sc_tool_web_fetch_new(int max_chars)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    web_fetch_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(t); return NULL; }

    d->max_chars = max_chars > 0 ? max_chars : SC_MAX_FETCH_CHARS;

    t->name = "web_fetch";
    t->description = "Fetch a URL and extract readable content (HTML to text).";
    t->parameters = web_fetch_parameters;
    t->execute = web_fetch_execute;
    t->destroy = web_fetch_destroy;
    t->data = d;
    return t;
}
