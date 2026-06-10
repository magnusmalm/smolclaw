/*
 * tools/camera.c - camera capture + vision describe tool
 *
 * Three actions:
 *   snap     — run the configured capture command (no shell) writing a
 *              timestamped JPEG into <workspace>/camera/
 *   events   — list recent motion-event captures from the events dir,
 *              newest first
 *   describe — base64 a captured image and ask a remote vision model
 *              about it (ollama /api/chat with an images array)
 *
 * The vision call is tool-internal (like voice transcription): the
 * agent's own provider/model stay text-only, so no provider plumbing
 * is involved and minimal builds are unaffected (SC_ENABLE_CAMERA=n).
 */

#include "tools/camera.h"
#include "tools/registry.h"
#include "util/curl_common.h"
#include "util/json_helpers.h"
#include "util/base64.h"
#include "util/str.h"
#include "logger.h"

#include <cJSON.h>
#include <curl/curl.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TAG "camera_tool"

#define SNAP_TIMEOUT_SECS   20
#define SNAP_MAX_ARGS       32
#define MAX_IMAGE_BYTES     (10 * 1024 * 1024)
#define EVENTS_DEFAULT_N    10
#define EVENTS_MAX_N        50
#define DEFAULT_QUESTION \
    "Describe what you see in this image. Note any people, vehicles, " \
    "animals, packages, or unusual activity. Be concise."

typedef struct {
    char *workspace;
    char *snap_command;
    char *events_dir;     /* relative to workspace */
    char *vision_url;
    char *vision_model;
    int   vision_timeout_secs;
} camera_data_t;

/* ------------------------------------------------------------------ */
/*  Path safety                                                        */
/* ------------------------------------------------------------------ */

/* Resolve `path` (absolute or workspace-relative) and require it to
 * live under the workspace. Returns malloc'd resolved path or NULL. */
static char *resolve_under_workspace(camera_data_t *cd, const char *path)
{
    if (!path || !path[0] || !cd->workspace) return NULL;

    char joined[PATH_MAX];
    if (path[0] == '/')
        snprintf(joined, sizeof(joined), "%s", path);
    else
        snprintf(joined, sizeof(joined), "%s/%s", cd->workspace, path);

    char *resolved = realpath(joined, NULL);
    if (!resolved) return NULL;

    char *ws_resolved = realpath(cd->workspace, NULL);
    if (!ws_resolved) { free(resolved); return NULL; }

    size_t wlen = strlen(ws_resolved);
    int ok = strncmp(resolved, ws_resolved, wlen) == 0 &&
             (resolved[wlen] == '/' || resolved[wlen] == '\0');
    free(ws_resolved);
    if (!ok) { free(resolved); return NULL; }
    return resolved;
}

/* ------------------------------------------------------------------ */
/*  snap                                                               */
/* ------------------------------------------------------------------ */

static int mkdir_p_under(const char *base, const char *sub)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", base, sub);
    char *p = path + strlen(base) + 1;
    for (; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(path, 0755); *p = '/'; }
    }
    return mkdir(path, 0755) == 0 || errno == EEXIST ? 0 : -1;
}

static sc_tool_result_t *cmd_snap(camera_data_t *cd)
{
    if (!cd->snap_command || !cd->snap_command[0])
        return sc_tool_result_error(
            "snap is not configured (camera.snap_command missing)");

    if (mkdir_p_under(cd->workspace, "camera") != 0)
        return sc_tool_result_error("cannot create camera/ directory");

    char out_path[PATH_MAX];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    snprintf(out_path, sizeof(out_path),
             "%s/camera/snap-%04d%02d%02d-%02d%02d%02d.jpg",
             cd->workspace, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);

    /* Split snap_command on whitespace (no shell), append out_path */
    char *cmd_copy = sc_strdup(cd->snap_command);
    if (!cmd_copy) return sc_tool_result_error("out of memory");
    char *argv[SNAP_MAX_ARGS + 2];
    int argc = 0;
    for (char *tok = strtok(cmd_copy, " \t");
         tok && argc < SNAP_MAX_ARGS; tok = strtok(NULL, " \t"))
        argv[argc++] = tok;
    if (argc == 0) {
        free(cmd_copy);
        return sc_tool_result_error("camera.snap_command is empty");
    }
    argv[argc++] = out_path;
    argv[argc] = NULL;

    pid_t pid = fork();
    if (pid < 0) {
        free(cmd_copy);
        return sc_tool_result_error("fork() failed");
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
        }
        execvp(argv[0], argv);
        _exit(127);
    }

    int status = 0, timed_out = 0;
    time_t start = time(NULL);
    while (1) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) break;
        if (r < 0) break;
        if (time(NULL) - start > SNAP_TIMEOUT_SECS) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            timed_out = 1;
            break;
        }
        usleep(100 * 1000);
    }
    free(cmd_copy);

    if (timed_out)
        return sc_tool_result_error("capture command timed out");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "capture command failed (exit %d)",
                          WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        char *msg = sc_strbuf_finish(&sb);
        sc_tool_result_t *res = sc_tool_result_error(
            msg ? msg : "capture command failed");
        free(msg);
        return res;
    }

    struct stat st;
    if (stat(out_path, &st) != 0 || st.st_size == 0)
        return sc_tool_result_error(
            "capture command exited 0 but produced no image");

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb,
        "Captured %s (%lld KB). Use action=describe with this path to "
        "analyze it.", out_path, (long long)(st.st_size / 1024));
    char *msg = sc_strbuf_finish(&sb);
    sc_tool_result_t *res = sc_tool_result_new(msg ? msg : out_path);
    free(msg);
    return res;
}

/* ------------------------------------------------------------------ */
/*  events                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    char name[256];
    time_t mtime;
    off_t size;
} event_entry_t;

static int has_image_ext(const char *name)
{
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;
    return strcasecmp(dot, ".jpg") == 0 || strcasecmp(dot, ".jpeg") == 0 ||
           strcasecmp(dot, ".png") == 0;
}

static int entry_cmp_newest(const void *a, const void *b)
{
    const event_entry_t *ea = a, *eb = b;
    if (ea->mtime == eb->mtime) return strcmp(eb->name, ea->name);
    return eb->mtime > ea->mtime ? 1 : -1;
}

static sc_tool_result_t *cmd_events(camera_data_t *cd, cJSON *args)
{
    int limit = sc_json_get_int(args, "limit", EVENTS_DEFAULT_N);
    if (limit < 1) limit = 1;
    if (limit > EVENTS_MAX_N) limit = EVENTS_MAX_N;

    char dir_path[PATH_MAX];
    snprintf(dir_path, sizeof(dir_path), "%s/%s",
             cd->workspace, cd->events_dir);

    DIR *d = opendir(dir_path);
    if (!d) {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb,
            "No motion events (events dir %s not present — the motion "
            "daemon may not have recorded anything yet).", cd->events_dir);
        char *msg = sc_strbuf_finish(&sb);
        sc_tool_result_t *res = sc_tool_result_new(msg ? msg : "no events");
        free(msg);
        return res;
    }

    event_entry_t *entries = NULL;
    int count = 0, cap = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.' || !has_image_ext(de->d_name)) continue;
        char fpath[PATH_MAX];
        snprintf(fpath, sizeof(fpath), "%s/%s", dir_path, de->d_name);
        struct stat st;
        if (stat(fpath, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (count >= cap) {
            cap = cap ? cap * 2 : 64;
            event_entry_t *tmp = realloc(entries,
                                         (size_t)cap * sizeof(*entries));
            if (!tmp) break;
            entries = tmp;
        }
        snprintf(entries[count].name, sizeof(entries[count].name), "%s",
                 de->d_name);
        entries[count].mtime = st.st_mtime;
        entries[count].size = st.st_size;
        count++;
    }
    closedir(d);

    if (count == 0) {
        free(entries);
        return sc_tool_result_new("No motion-event captures found.");
    }

    qsort(entries, (size_t)count, sizeof(*entries), entry_cmp_newest);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    int shown = count < limit ? count : limit;
    sc_strbuf_appendf(&sb, "%d capture(s), newest first (of %d total):\n",
                      shown, count);
    for (int i = 0; i < shown; i++) {
        struct tm tm;
        localtime_r(&entries[i].mtime, &tm);
        sc_strbuf_appendf(&sb,
            "%s/%s | %04d-%02d-%02d %02d:%02d:%02d | %lld KB\n",
            cd->events_dir, entries[i].name,
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec,
            (long long)(entries[i].size / 1024));
    }
    free(entries);

    char *msg = sc_strbuf_finish(&sb);
    sc_tool_result_t *res = sc_tool_result_new(msg ? msg : "error");
    free(msg);
    return res;
}

/* ------------------------------------------------------------------ */
/*  describe                                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} resp_buf_t;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    resp_buf_t *buf = userdata;
    size_t total = size * nmemb;
    if (buf->len + total + 1 > buf->cap) {
        size_t newcap = (buf->cap + total + 1) * 2;
        char *tmp = realloc(buf->data, newcap);
        if (!tmp) return 0;
        buf->data = tmp;
        buf->cap = newcap;
    }
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

static sc_tool_result_t *cmd_describe(camera_data_t *cd, cJSON *args)
{
    if (!cd->vision_url || !cd->vision_model)
        return sc_tool_result_error(
            "describe is not configured (camera.vision_url / "
            "camera.vision_model missing)");

    const char *image = sc_json_get_string(args, "image", NULL);
    if (!image || !image[0])
        return sc_tool_result_error(
            "'image' is required (a path from snap or events)");
    const char *question = sc_json_get_string(args, "question",
                                              DEFAULT_QUESTION);

    char *path = resolve_under_workspace(cd, image);
    if (!path)
        return sc_tool_result_error(
            "image not found or outside the workspace");

    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size == 0) {
        free(path);
        return sc_tool_result_error("image is not a readable file");
    }
    if (st.st_size > MAX_IMAGE_BYTES) {
        free(path);
        return sc_tool_result_error("image exceeds 10 MB limit");
    }

    FILE *f = fopen(path, "rb");
    if (!f) { free(path); return sc_tool_result_error("cannot open image"); }
    unsigned char *raw = malloc((size_t)st.st_size);
    if (!raw) { fclose(f); free(path); return sc_tool_result_error("OOM"); }
    size_t got = fread(raw, 1, (size_t)st.st_size, f);
    fclose(f);
    if (got != (size_t)st.st_size) {
        free(raw); free(path);
        return sc_tool_result_error("short read on image");
    }

    char *b64 = sc_base64_encode(raw, got);
    free(raw);
    if (!b64) { free(path); return sc_tool_result_error("base64 failed"); }

    /* ollama native chat: messages[].images = ["<base64>"] */
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "model", cd->vision_model);
    cJSON_AddBoolToObject(body, "stream", 0);
    cJSON *msgs = cJSON_AddArrayToObject(body, "messages");
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddStringToObject(msg, "role", "user");
    cJSON_AddStringToObject(msg, "content", question);
    cJSON *images = cJSON_AddArrayToObject(msg, "images");
    cJSON_AddItemToArray(images, cJSON_CreateString(b64));
    cJSON_AddItemToArray(msgs, msg);
    free(b64);

    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) { free(path); return sc_tool_result_error("OOM"); }

    char url[1024];
    snprintf(url, sizeof(url), "%s/api/chat", cd->vision_url);

    CURL *curl = sc_curl_init();
    if (!curl) {
        free(body_str); free(path);
        return sc_tool_result_error("curl init failed");
    }
    resp_buf_t resp = {.data = malloc(1024), .len = 0, .cap = 1024};
    if (!resp.data) {
        curl_easy_cleanup(curl); free(body_str); free(path);
        return sc_tool_result_error("OOM");
    }
    resp.data[0] = '\0';

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,
                     (long)(cd->vision_timeout_secs > 0
                            ? cd->vision_timeout_secs : 120));

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(body_str);

    if (rc != CURLE_OK) {
        SC_LOG_WARN(TAG, "vision call failed: %s", curl_easy_strerror(rc));
        free(resp.data); free(path);
        return sc_tool_result_error(
            "vision model unreachable (check camera.vision_url)");
    }
    if (http_code != 200) {
        SC_LOG_WARN(TAG, "vision call HTTP %ld: %.200s", http_code,
                    resp.data ? resp.data : "");
        free(resp.data); free(path);
        return sc_tool_result_error("vision model returned an error");
    }

    cJSON *root = cJSON_Parse(resp.data);
    free(resp.data);
    const char *content = NULL;
    if (root) {
        cJSON *m = cJSON_GetObjectItem(root, "message");
        if (m) {
            cJSON *c = cJSON_GetObjectItem(m, "content");
            if (cJSON_IsString(c)) content = c->valuestring;
        }
    }
    if (!content || !content[0]) {
        if (root) cJSON_Delete(root);
        free(path);
        return sc_tool_result_error("vision model returned no content");
    }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "[%s] %s", path, content);
    cJSON_Delete(root);
    free(path);
    char *out = sc_strbuf_finish(&sb);
    sc_tool_result_t *res = sc_tool_result_new(out ? out : "error");
    free(out);
    return res;
}

/* ------------------------------------------------------------------ */
/*  Tool plumbing                                                      */
/* ------------------------------------------------------------------ */

static cJSON *camera_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");
    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *action = cJSON_AddObjectToObject(props, "action");
    cJSON_AddStringToObject(action, "type", "string");
    cJSON_AddStringToObject(action, "description",
        "Action: snap (capture a still now), events (list recent "
        "motion captures), describe (analyze an image with the vision "
        "model)");

    cJSON *image = cJSON_AddObjectToObject(props, "image");
    cJSON_AddStringToObject(image, "type", "string");
    cJSON_AddStringToObject(image, "description",
        "Image path from snap/events output (for describe)");

    cJSON *question = cJSON_AddObjectToObject(props, "question");
    cJSON_AddStringToObject(question, "type", "string");
    cJSON_AddStringToObject(question, "description",
        "What to ask about the image (for describe; default: general "
        "scene description)");

    cJSON *limit = cJSON_AddObjectToObject(props, "limit");
    cJSON_AddStringToObject(limit, "type", "integer");
    cJSON_AddStringToObject(limit, "description",
        "Max captures to list (for events; default 10, max 50)");

    cJSON *required = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(required, cJSON_CreateString("action"));
    return schema;
}

static sc_tool_result_t *camera_execute(sc_tool_t *self, cJSON *args,
                                         void *ctx)
{
    (void)ctx;
    camera_data_t *cd = self->data;
    const char *action = sc_json_get_string(args, "action", NULL);
    if (!action)
        return sc_tool_result_error("'action' is required");

    if (strcmp(action, "snap") == 0)     return cmd_snap(cd);
    if (strcmp(action, "events") == 0)   return cmd_events(cd, args);
    if (strcmp(action, "describe") == 0) return cmd_describe(cd, args);

    return sc_tool_result_error(
        "unknown action (expected snap, events, or describe)");
}

static void camera_destroy(sc_tool_t *self)
{
    if (!self) return;
    camera_data_t *cd = self->data;
    if (cd) {
        free(cd->workspace);
        free(cd->snap_command);
        free(cd->events_dir);
        free(cd->vision_url);
        free(cd->vision_model);
        free(cd);
    }
    free(self);
}

sc_tool_t *sc_tool_camera_new(const char *workspace,
                              const char *snap_command,
                              const char *events_dir,
                              const char *vision_url,
                              const char *vision_model,
                              int vision_timeout_secs)
{
    if (!workspace) return NULL;

    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    camera_data_t *cd = calloc(1, sizeof(*cd));
    if (!cd) { free(t); return NULL; }

    cd->workspace = sc_strdup(workspace);
    if (snap_command) cd->snap_command = sc_strdup(snap_command);
    cd->events_dir = sc_strdup(events_dir && events_dir[0]
                               ? events_dir : "camera/motion");
    if (vision_url)   cd->vision_url   = sc_strdup(vision_url);
    if (vision_model) cd->vision_model = sc_strdup(vision_model);
    cd->vision_timeout_secs = vision_timeout_secs;

    t->name        = "camera";
    t->description = "Camera — capture stills, list motion events, and "
                     "describe images via the vision model";
    t->parameters  = camera_parameters;
    t->execute     = camera_execute;
    t->destroy     = camera_destroy;
    t->data        = cd;
    return t;
}
