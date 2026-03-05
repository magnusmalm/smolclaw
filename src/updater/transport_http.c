/*
 * updater/transport_http.c — HTTP transport for self-update
 *
 * Fetches manifest JSON and binary artifacts via libcurl.
 * Binary download streams to a temp file to avoid holding large
 * binaries in memory.
 */

#include <stdint.h>

#include "updater/transport_http.h"
#include "updater/updater.h"
#include "constants.h"
#include "logger.h"
#include "util/str.h"
#include "util/curl_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "updater-http"

typedef struct {
    char *manifest_url;
} http_transport_data_t;

/* curl write callback for in-memory buffer */
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} mem_buf_t;

static size_t mem_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    mem_buf_t *buf = userdata;
    if (nmemb > 0 && size > SIZE_MAX / nmemb) return 0;
    size_t total = size * nmemb;

    if (buf->size + total + 1 > buf->capacity) {
        size_t new_cap = (buf->capacity + total + 1) * 2;
        if (new_cap > SC_CURL_MAX_RESPONSE) return 0;
        char *tmp = realloc(buf->data, new_cap);
        if (!tmp) return 0;
        buf->data = tmp;
        buf->capacity = new_cap;
    }

    memcpy(buf->data + buf->size, ptr, total);
    buf->size += total;
    buf->data[buf->size] = '\0';
    return total;
}

/* curl write callback for file download */
typedef struct {
    FILE *fp;
    size_t written;
} file_write_ctx_t;

static size_t file_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    file_write_ctx_t *ctx = userdata;
    if (nmemb > 0 && size > SIZE_MAX / nmemb) return 0;
    size_t total = size * nmemb;

    if (ctx->written + total > (size_t)SC_UPDATE_MAX_BINARY_SIZE)
        return 0;  /* abort: too large */

    size_t n = fwrite(ptr, 1, total, ctx->fp);
    ctx->written += n;
    return n;
}

/* ===== fetch_manifest ===== */

static sc_update_manifest_t *http_fetch_manifest(sc_update_transport_t *self)
{
    http_transport_data_t *d = self->data;
    if (!d || !d->manifest_url) return NULL;

    CURL *curl = sc_curl_init();
    if (!curl) return NULL;

    mem_buf_t buf = { .data = malloc(4096), .size = 0, .capacity = 4096 };
    if (!buf.data) { curl_easy_cleanup(curl); return NULL; }
    buf.data[0] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, d->manifest_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, mem_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)SC_UPDATE_MANIFEST_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        SC_LOG_ERROR(LOG_TAG, "Manifest fetch failed: %s", curl_easy_strerror(res));
        free(buf.data);
        return NULL;
    }

    if (http_code != 200) {
        SC_LOG_ERROR(LOG_TAG, "Manifest fetch HTTP %ld", http_code);
        free(buf.data);
        return NULL;
    }

    const char *arch = sc_updater_get_arch();
    sc_update_manifest_t *m = sc_updater_parse_manifest(buf.data, arch);
    free(buf.data);
    return m;
}

/* ===== fetch_binary ===== */

static sc_fetch_result_t *http_fetch_binary(sc_update_transport_t *self,
                                             const sc_update_artifact_t *artifact)
{
    (void)self;

    sc_fetch_result_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;

    if (!artifact || !artifact->url) {
        r->error = sc_strdup("No artifact URL");
        return r;
    }

    /* Create temp file */
    char tmp_path[] = "/tmp/smolclaw-update-XXXXXX";
    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        r->error = sc_strdup("Failed to create temp file");
        return r;
    }

    FILE *fp = fdopen(fd, "wb");
    if (!fp) {
        close(fd);
        unlink(tmp_path);
        r->error = sc_strdup("Failed to open temp file");
        return r;
    }

    file_write_ctx_t fctx = { .fp = fp, .written = 0 };

    CURL *curl = sc_curl_init();
    if (!curl) {
        fclose(fp);
        unlink(tmp_path);
        r->error = sc_strdup("curl init failed");
        return r;
    }

    curl_easy_setopt(curl, CURLOPT_URL, artifact->url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, file_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &fctx);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)SC_UPDATE_DOWNLOAD_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);
    fclose(fp);

    if (res != CURLE_OK || http_code != 200) {
        unlink(tmp_path);
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        if (res != CURLE_OK)
            sc_strbuf_appendf(&sb, "Download failed: %s", curl_easy_strerror(res));
        else
            sc_strbuf_appendf(&sb, "Download HTTP %ld", http_code);
        r->error = sc_strbuf_finish(&sb);
        return r;
    }

    r->path = sc_strdup(tmp_path);
    r->size = fctx.written;
    r->success = 1;

    SC_LOG_INFO(LOG_TAG, "Downloaded %zu bytes to %s", r->size, r->path);
    return r;
}

/* ===== destroy ===== */

static void http_destroy(sc_update_transport_t *self)
{
    if (!self) return;
    http_transport_data_t *d = self->data;
    if (d) {
        free(d->manifest_url);
        free(d);
    }
    free(self);
}

/* ===== factory ===== */

sc_update_transport_t *sc_update_transport_http_new(const char *manifest_url)
{
    if (!manifest_url) return NULL;

    sc_update_transport_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    http_transport_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(t); return NULL; }

    d->manifest_url = sc_strdup(manifest_url);

    t->name = "http";
    t->fetch_manifest = http_fetch_manifest;
    t->fetch_binary = http_fetch_binary;
    t->destroy = http_destroy;
    t->data = d;

    return t;
}
