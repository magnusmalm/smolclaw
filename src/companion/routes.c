/*
 * companion/routes.c — Layer 1 companion HTTP handlers (capabilities, snap).
 *
 * Phone-initiated upload (raw body, not multipart) per plan §13.1 D1.
 */

#include "companion/routes.h"
#include "companion/auth.h"
#include "companion/random.h"
#include "channels/base.h"
#include "channels/web.h"
#include "constants.h"
#include "logger.h"
#include "sc_features.h"
#include "sc_version.h"
#include "util/str.h"

#include <cJSON.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TAG "companion"
#define SNAP_MAX_BYTES (10 * 1024 * 1024)

static int mkdir_p(const char *path, mode_t mode)
{
    char buf[PATH_MAX];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, mode) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    return (mkdir(buf, mode) == 0 || errno == EEXIST) ? 0 : -1;
}

static int companion_auth(struct evhttp_request *req, sc_channel_t *ch,
                            const char *scope)
{
    const char *auth = evhttp_find_header(
        evhttp_request_get_input_headers(req), "Authorization");
    return sc_web_companion_check_auth(ch, auth, scope);
}

void sc_companion_handle_capabilities(struct evhttp_request *req, void *arg)
{
    sc_channel_t *ch = arg;
    if (!companion_auth(req, ch, NULL)) {
        sc_web_send_json_error(req, 401, "Unauthorized");
        return;
    }

    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "protocol", "smolclaw-companion/1");
    cJSON_AddStringToObject(j, "version", SC_VERSION);
    cJSON *feat = cJSON_AddObjectToObject(j, "features");
    cJSON_AddBoolToObject(feat, "snap", 1);
    cJSON_AddBoolToObject(feat, "memory_pending", 1);
    cJSON_AddBoolToObject(feat, "audit_poll", 1);
    cJSON *lim = cJSON_AddObjectToObject(j, "limits");
    cJSON_AddNumberToObject(lim, "snap_max_bytes", SNAP_MAX_BYTES);
    cJSON *types = cJSON_AddArrayToObject(lim, "snap_types");
    cJSON_AddItemToArray(types, cJSON_CreateString("image/jpeg"));
    cJSON_AddItemToArray(types, cJSON_CreateString("image/png"));

    char *str = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    struct evbuffer *buf = evbuffer_new();
    evbuffer_add(buf, str, strlen(str));
    free(str);
    evhttp_add_header(evhttp_request_get_output_headers(req),
                       "Content-Type", "application/json");
    evhttp_send_reply(req, 200, "OK", buf);
    evbuffer_free(buf);
}

void sc_companion_handle_snap(struct evhttp_request *req, void *arg)
{
    sc_channel_t *ch = arg;

    if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
        sc_web_send_json_error(req, 405, "Method not allowed");
        return;
    }

    if (!companion_auth(req, ch, SC_COMP_SCOPE_SNAP_UPLOAD)) {
        sc_web_send_json_error(req, 401, "Unauthorized");
        return;
    }

    char ip[64];
    sc_web_client_ip(req, ip, sizeof(ip));
    const char *auth = evhttp_find_header(
        evhttp_request_get_input_headers(req), "Authorization");
    pthread_mutex_lock(&ch->security_mutex);
    sc_rate_limiter_t *rl = ch->rate_limiter;
    pthread_mutex_unlock(&ch->security_mutex);
    if (!sc_web_check_snap_rate_limit(rl, ip, auth)) {
        sc_web_send_json_error(req, 429, "Rate limit exceeded");
        return;
    }

    const char *ctype = evhttp_find_header(
        evhttp_request_get_input_headers(req), "Content-Type");
    const char *ext = NULL;
    if (ctype && strcasecmp(ctype, "image/jpeg") == 0)
        ext = ".jpg";
    else if (ctype && strcasecmp(ctype, "image/png") == 0)
        ext = ".png";
    else {
        sc_web_send_json_error(req, 400, "unsupported content type");
        return;
    }

    struct evbuffer *input = evhttp_request_get_input_buffer(req);
    size_t len = evbuffer_get_length(input);
    if (len == 0 || len > SNAP_MAX_BYTES) {
        sc_web_send_json_error(req, len > SNAP_MAX_BYTES ? 413 : 400,
                               len > SNAP_MAX_BYTES ? "image too large"
                                                    : "empty body");
        return;
    }

    const char *workspace = sc_web_channel_workspace(ch);
    if (!workspace || !workspace[0]) {
        sc_web_send_json_error(req, 500, "workspace not configured");
        return;
    }

    unsigned char rnd[16];
    if (sc_companion_random_bytes(rnd, sizeof(rnd)) != 0) {
        sc_web_send_json_error(req, 500, "random failure");
        return;
    }
    char uuid[33];
    for (size_t i = 0; i < sizeof(rnd); i++)
        snprintf(uuid + i * 2, 3, "%02x", rnd[i]);

    char inbox[PATH_MAX];
    snprintf(inbox, sizeof(inbox), "%s/companion/inbox", workspace);
    if (mkdir_p(inbox, 0700) != 0) {
        sc_web_send_json_error(req, 500, "mkdir failed");
        return;
    }

    char rel[128];
    snprintf(rel, sizeof(rel), "companion/inbox/%s%s", uuid, ext);
    /* sc_validate_path handles non-existent tails (write path); sc_web_confine_image
     * requires the file to exist (read path) — see plan §13.4 / web.c:723. */
    char *full = sc_validate_path(rel, workspace, 1);
    if (!full) {
        sc_web_send_json_error(req, 500, "path confinement failed");
        return;
    }

    int fd = open(full, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        free(full);
        sc_web_send_json_error(req, 500, "create failed");
        return;
    }

    unsigned char chunk[8192];
    size_t off = 0;
    while (off < len) {
        size_t n = evbuffer_copyout(input, chunk,
            len - off > sizeof(chunk) ? sizeof(chunk) : len - off);
        if (n == 0) break;
        ssize_t w = write(fd, chunk, n);
        if (w < 0) {
            close(fd);
            unlink(full);
            free(full);
            sc_web_send_json_error(req, 500, "write failed");
            return;
        }
        evbuffer_drain(input, (size_t)w);
        off += (size_t)w;
    }
    close(fd);
    free(full);

    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "path", rel);
    cJSON_AddNumberToObject(j, "bytes", (double)len);
    cJSON_AddStringToObject(j, "content_type", ctype);
    char *str = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    struct evbuffer *buf = evbuffer_new();
    evbuffer_add(buf, str, strlen(str));
    free(str);
    evhttp_add_header(evhttp_request_get_output_headers(req),
                       "Content-Type", "application/json");
    evhttp_send_reply(req, 201, "Created", buf);
    evbuffer_free(buf);
}