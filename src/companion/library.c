/*
 * companion/library.c — P2.2a library endpoints: browse + delete snaps
 * and daily-note lines (plan docs/plans/companion-library.md §3).
 *
 * Deterministic REST, never model-mediated: the agent model cannot be
 * trusted to enumerate or mutate state (P2.1 evidence), and destructive
 * operations must not depend on tool-call volition.
 */

#include "companion/routes.h"
#include "companion/auth.h"
#include "channels/base.h"
#include "channels/web.h"
#include "audit.h"
#include "logger.h"
#include "util/str.h"

#include <cJSON.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define TAG "companion"
#define LIB_SNAPS_LIST_MAX 100
#define LIB_NOTES_DAYS_MAX 31
#define LIB_NOTE_LINE_MAX  8192
#define LIB_IMAGE_MAX      (10 * 1024 * 1024)

static int lib_auth(struct evhttp_request *req, sc_channel_t *ch)
{
    const char *auth = evhttp_find_header(
        evhttp_request_get_input_headers(req), "Authorization");
    return sc_web_companion_check_auth(ch, auth, SC_COMP_SCOPE_LIBRARY);
}

static void lib_send_json(struct evhttp_request *req, int code,
                          const char *reason, cJSON *j)
{
    char *str = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!str) {
        sc_web_send_json_error(req, 500, "out of memory");
        return;
    }
    struct evbuffer *buf = evbuffer_new();
    if (!buf) {
        free(str);
        sc_web_send_json_error(req, 500, "out of memory");
        return;
    }
    evbuffer_add(buf, str, strlen(str));
    free(str);
    evhttp_add_header(evhttp_request_get_output_headers(req),
                       "Content-Type", "application/json");
    evhttp_send_reply(req, code, reason, buf);
    evbuffer_free(buf);
}

/* Copy of a query parameter value, or NULL. Caller frees. */
static char *lib_query_param(struct evhttp_request *req, const char *key)
{
    const char *uri = evhttp_request_get_uri(req);
    if (!uri) return NULL;
    struct evhttp_uri *u = evhttp_uri_parse(uri);
    if (!u) return NULL;
    char *val = NULL;
    const char *q = evhttp_uri_get_query(u);
    if (q) {
        struct evkeyvalq params;
        if (evhttp_parse_query_str(q, &params) == 0) {
            const char *v = evhttp_find_header(&params, key);
            if (v) val = sc_strdup(v);
            evhttp_clear_headers(&params);
        }
    }
    evhttp_uri_free(u);
    return val;
}

/* 32 lowercase-hex snap id — the ONLY accepted reference to a photo.
 * By construction the resulting path cannot traverse. */
static int lib_valid_snap_id(const char *s)
{
    if (!s || strlen(s) != 32) return 0;
    for (int i = 0; i < 32; i++) {
        if (!isxdigit((unsigned char)s[i]) || isupper((unsigned char)s[i]))
            return 0;
    }
    return 1;
}

/* Rewrite `path` without some lines (atomic: tmp + rename).
 * exact != NULL: remove the FIRST line byte-equal to `exact` (sans \n).
 * else:          remove EVERY line containing `needle`.
 * Returns number of removed lines, -1 on I/O error, 0 if file missing. */
static int lib_file_remove_lines(const char *path, const char *needle,
                                 const char *exact)
{
    FILE *in = fopen(path, "r");
    if (!in) return 0;

    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) {
        fclose(in);
        return -1;
    }
    FILE *out = fopen(tmp, "w");
    if (!out) {
        fclose(in);
        return -1;
    }

    int removed = 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, in)) != -1) {
        int drop = 0;
        size_t len = (size_t)n;
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            len--;
        if (exact) {
            if (removed == 0 && len == strlen(exact) &&
                memcmp(line, exact, len) == 0)
                drop = 1;
        } else if (needle) {
            /* getline NUL-terminates, so substring search is safe. */
            if (strstr(line, needle) != NULL)
                drop = 1;
        }
        if (drop) {
            removed++;
        } else if (fwrite(line, 1, (size_t)n, out) != (size_t)n) {
            free(line);
            fclose(in);
            fclose(out);
            unlink(tmp);
            return -1;
        }
    }
    free(line);
    fclose(in);
    if (fclose(out) != 0) {
        unlink(tmp);
        return -1;
    }

    if (removed == 0) {
        unlink(tmp);
        return 0;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return removed;
}

/* Remove every daily-note line referencing a snap id, across all months.
 * NOTE: deleted lines may linger in the FTS search index until its next
 * rebuild (startup) — documented limitation, plan §3.6. */
static int lib_purge_snap_notes(const char *workspace, const char *id)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "companion/inbox/%s.", id);

    char memdir[PATH_MAX];
    snprintf(memdir, sizeof(memdir), "%s/memory", workspace);
    DIR *d = opendir(memdir);
    if (!d) return 0;

    int total = 0;
    struct dirent *month;
    while ((month = readdir(d)) != NULL) {
        if (month->d_name[0] == '.') continue;
        char subdir[PATH_MAX];
        if (snprintf(subdir, sizeof(subdir), "%s/%s", memdir,
                     month->d_name) >= (int)sizeof(subdir))
            continue;
        struct stat st;
        if (stat(subdir, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        DIR *sd = opendir(subdir);
        if (!sd) continue;
        struct dirent *f;
        while ((f = readdir(sd)) != NULL) {
            size_t nl = strlen(f->d_name);
            if (nl < 4 || strcmp(f->d_name + nl - 3, ".md") != 0) continue;
            char fpath[PATH_MAX];
            if (snprintf(fpath, sizeof(fpath), "%s/%s", subdir,
                         f->d_name) >= (int)sizeof(fpath))
                continue;
            int r = lib_file_remove_lines(fpath, needle, NULL);
            if (r > 0) total += r;
        }
        closedir(sd);
    }
    closedir(d);
    return total;
}

/* ---------------- /api/companion/snaps ---------------- */

typedef struct {
    char name[64];
    time_t mtime;
    long long bytes;
} lib_snap_entry_t;

static int lib_snap_cmp_newest(const void *a, const void *b)
{
    const lib_snap_entry_t *ea = a, *eb = b;
    if (ea->mtime != eb->mtime) return ea->mtime < eb->mtime ? 1 : -1;
    return strcmp(eb->name, ea->name);
}

static void lib_snaps_list(struct evhttp_request *req, const char *workspace)
{
    int limit = LIB_SNAPS_LIST_MAX;
    char *lim = lib_query_param(req, "limit");
    if (lim) {
        int v = atoi(lim);
        free(lim);
        if (v > 0 && v < LIB_SNAPS_LIST_MAX) limit = v;
    }

    char inbox[PATH_MAX];
    snprintf(inbox, sizeof(inbox), "%s/companion/inbox", workspace);

    lib_snap_entry_t *entries = NULL;
    int count = 0, cap = 0;
    DIR *d = opendir(inbox);
    if (d) {
        struct dirent *f;
        while ((f = readdir(d)) != NULL) {
            size_t nl = strlen(f->d_name);
            if (nl != 36) continue;  /* <32 hex> + ".jpg"/".png" */
            if (strcmp(f->d_name + 32, ".jpg") != 0 &&
                strcmp(f->d_name + 32, ".png") != 0)
                continue;
            char idbuf[33];
            memcpy(idbuf, f->d_name, 32);
            idbuf[32] = '\0';
            if (!lib_valid_snap_id(idbuf)) continue;
            char fpath[PATH_MAX];
            if (snprintf(fpath, sizeof(fpath), "%s/%s", inbox,
                         f->d_name) >= (int)sizeof(fpath))
                continue;
            struct stat st;
            if (stat(fpath, &st) != 0 || !S_ISREG(st.st_mode)) continue;
            if (count >= cap) {
                int ncap = cap == 0 ? 32 : cap * 2;
                lib_snap_entry_t *ne = realloc(entries,
                    (size_t)ncap * sizeof(*ne));
                if (!ne) break;
                entries = ne;
                cap = ncap;
            }
            snprintf(entries[count].name, sizeof(entries[count].name),
                     "%s", f->d_name);
            entries[count].mtime = st.st_mtime;
            entries[count].bytes = (long long)st.st_size;
            count++;
        }
        closedir(d);
    }
    if (entries && count > 1)
        qsort(entries, (size_t)count, sizeof(*entries), lib_snap_cmp_newest);

    cJSON *j = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(j, "snaps");
    for (int i = 0; i < count && i < limit; i++) {
        cJSON *e = cJSON_CreateObject();
        char idbuf[33];
        memcpy(idbuf, entries[i].name, 32);
        idbuf[32] = '\0';
        cJSON_AddStringToObject(e, "id", idbuf);
        char rel[128];
        snprintf(rel, sizeof(rel), "companion/inbox/%s", entries[i].name);
        cJSON_AddStringToObject(e, "path", rel);
        cJSON_AddNumberToObject(e, "bytes", (double)entries[i].bytes);
        cJSON_AddNumberToObject(e, "mtime", (double)entries[i].mtime);
        cJSON_AddItemToArray(arr, e);
    }
    cJSON_AddNumberToObject(j, "total", (double)count);
    free(entries);
    lib_send_json(req, 200, "OK", j);
}

static void lib_snaps_image(struct evhttp_request *req, const char *workspace,
                            const char *id)
{
    if (!lib_valid_snap_id(id)) {
        sc_web_send_json_error(req, 400, "invalid id");
        return;
    }
    static const char *exts[] = { ".jpg", ".png" };
    static const char *ctypes[] = { "image/jpeg", "image/png" };
    for (int i = 0; i < 2; i++) {
        char fpath[PATH_MAX];
        snprintf(fpath, sizeof(fpath), "%s/companion/inbox/%s%s",
                 workspace, id, exts[i]);
        FILE *f = fopen(fpath, "rb");
        if (!f) continue;
        struct stat st;
        if (stat(fpath, &st) != 0 || !S_ISREG(st.st_mode) ||
            st.st_size <= 0 || st.st_size > LIB_IMAGE_MAX) {
            fclose(f);
            sc_web_send_json_error(req, 500, "unreadable image");
            return;
        }
        struct evbuffer *buf = evbuffer_new();
        if (!buf) {
            fclose(f);
            sc_web_send_json_error(req, 500, "out of memory");
            return;
        }
        char chunk[8192];
        size_t n;
        while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0)
            evbuffer_add(buf, chunk, n);
        int short_read = ferror(f);
        fclose(f);
        if (short_read) {
            evbuffer_free(buf);
            sc_web_send_json_error(req, 500, "read failed");
            return;
        }
        evhttp_add_header(evhttp_request_get_output_headers(req),
                           "Content-Type", ctypes[i]);
        evhttp_send_reply(req, 200, "OK", buf);
        evbuffer_free(buf);
        return;
    }
    sc_web_send_json_error(req, 404, "not found");
}

static void lib_snaps_delete(struct evhttp_request *req,
                             const char *workspace)
{
    char *id = lib_query_param(req, "id");
    if (!id || !lib_valid_snap_id(id)) {
        free(id);
        sc_web_send_json_error(req, 400, "invalid id");
        return;
    }
    char *purge = lib_query_param(req, "purge_notes");
    int do_purge = purge && strcmp(purge, "1") == 0;
    free(purge);

    int found = 0;
    static const char *exts[] = { ".jpg", ".png" };
    for (int i = 0; i < 2; i++) {
        char fpath[PATH_MAX];
        snprintf(fpath, sizeof(fpath), "%s/companion/inbox/%s%s",
                 workspace, id, exts[i]);
        if (unlink(fpath) == 0) found = 1;
    }
    int notes_removed = do_purge ? lib_purge_snap_notes(workspace, id) : 0;

    char summary[128];
    snprintf(summary, sizeof(summary),
             "delete snap %s found=%d notes_removed=%d", id, found,
             notes_removed);
    sc_audit_log("companion_library", summary, 0, found || notes_removed);
    SC_LOG_INFO(TAG, "library: %s", summary);
    free(id);

    cJSON *j = cJSON_CreateObject();
    cJSON_AddBoolToObject(j, "deleted", found);
    cJSON_AddNumberToObject(j, "notes_removed", (double)notes_removed);
    lib_send_json(req, found ? 200 : 404, found ? "OK" : "Not Found", j);
}

void sc_companion_handle_snaps(struct evhttp_request *req, void *arg)
{
    sc_channel_t *ch = arg;
    if (!lib_auth(req, ch)) {
        sc_web_send_json_error(req, 401, "Unauthorized");
        return;
    }
    const char *workspace = sc_web_channel_workspace(ch);
    if (!workspace || !workspace[0]) {
        sc_web_send_json_error(req, 500, "workspace not configured");
        return;
    }

    switch (evhttp_request_get_command(req)) {
    case EVHTTP_REQ_GET: {
        char *img = lib_query_param(req, "image");
        if (img) {
            lib_snaps_image(req, workspace, img);
            free(img);
        } else {
            lib_snaps_list(req, workspace);
        }
        return;
    }
    case EVHTTP_REQ_DELETE:
        lib_snaps_delete(req, workspace);
        return;
    default:
        sc_web_send_json_error(req, 405, "Method not allowed");
        return;
    }
}

/* ---------------- /api/companion/notes ---------------- */

/* Classify a daily-note line; extracts the snap id when present. */
static const char *lib_classify_line(const char *l, char *id_out)
{
    id_out[0] = '\0';
    static const char SNAP_PFX[] = "snap companion/inbox/";
    static const char NOTE_PFX[] = "- snap-note companion/inbox/";
    const char *idp = NULL;
    const char *kind = NULL;
    if (strncmp(l, SNAP_PFX, sizeof(SNAP_PFX) - 1) == 0) {
        idp = l + sizeof(SNAP_PFX) - 1;
        kind = "snap";
    } else if (strncmp(l, NOTE_PFX, sizeof(NOTE_PFX) - 1) == 0) {
        idp = l + sizeof(NOTE_PFX) - 1;
        kind = "snap-note";
    }
    if (kind) {
        char idbuf[33];
        snprintf(idbuf, 33, "%s", idp);
        if (lib_valid_snap_id(idbuf))
            memcpy(id_out, idbuf, 33);
        return kind;
    }
    if (strncmp(l, "- ", 2) == 0) {
        const char *p = strstr(l, " | ");
        if (p && strstr(p + 3, " | "))
            return "triage";
    }
    return "other";
}

static void lib_notes_list(struct evhttp_request *req, const char *workspace)
{
    int days = 7;
    char *dq = lib_query_param(req, "days");
    if (dq) {
        int v = atoi(dq);
        free(dq);
        if (v > 0 && v <= LIB_NOTES_DAYS_MAX) days = v;
    }

    cJSON *j = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(j, "notes");

    time_t now = time(NULL);
    for (int d = 0; d < days; d++) {
        time_t t = now - (time_t)d * 86400;
        struct tm tmv;
        localtime_r(&t, &tmv);
        char month[8], date[10];
        strftime(month, sizeof(month), "%Y%m", &tmv);
        strftime(date, sizeof(date), "%Y%m%d", &tmv);
        char fpath[PATH_MAX];
        snprintf(fpath, sizeof(fpath), "%s/memory/%s/%s.md",
                 workspace, month, date);
        FILE *f = fopen(fpath, "r");
        if (!f) continue;
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        while ((n = getline(&line, &cap, f)) != -1) {
            while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
                line[--n] = '\0';
            if (n == 0) continue;
            char id[33];
            const char *kind = lib_classify_line(line, id);
            cJSON *e = cJSON_CreateObject();
            cJSON_AddStringToObject(e, "date", date);
            cJSON_AddStringToObject(e, "line", line);
            cJSON_AddStringToObject(e, "kind", kind);
            if (id[0]) cJSON_AddStringToObject(e, "id", id);
            cJSON_AddItemToArray(arr, e);
        }
        free(line);
        fclose(f);
    }
    lib_send_json(req, 200, "OK", j);
}

static void lib_notes_delete(struct evhttp_request *req,
                             const char *workspace)
{
    struct evbuffer *input = evhttp_request_get_input_buffer(req);
    size_t len = evbuffer_get_length(input);
    if (len == 0 || len > LIB_NOTE_LINE_MAX + 256) {
        sc_web_send_json_error(req, 400, "bad body");
        return;
    }
    char *body = malloc(len + 1);
    if (!body) {
        sc_web_send_json_error(req, 500, "out of memory");
        return;
    }
    evbuffer_copyout(input, body, len);
    body[len] = '\0';
    cJSON *in = cJSON_Parse(body);
    free(body);
    if (!in) {
        sc_web_send_json_error(req, 400, "invalid json");
        return;
    }
    const char *date = cJSON_GetStringValue(cJSON_GetObjectItem(in, "date"));
    const char *line = cJSON_GetStringValue(cJSON_GetObjectItem(in, "line"));
    int date_ok = date && strlen(date) == 8;
    for (int i = 0; date_ok && i < 8; i++)
        if (!isdigit((unsigned char)date[i])) date_ok = 0;
    if (!date_ok || !line || !line[0] || strlen(line) > LIB_NOTE_LINE_MAX) {
        cJSON_Delete(in);
        sc_web_send_json_error(req, 400, "date (YYYYMMDD) and line required");
        return;
    }

    char fpath[PATH_MAX];
    snprintf(fpath, sizeof(fpath), "%s/memory/%.6s/%s.md",
             workspace, date, date);
    int removed = lib_file_remove_lines(fpath, NULL, line);

    char summary[160];
    snprintf(summary, sizeof(summary), "delete note %s removed=%d \"%.80s\"",
             date, removed, line);
    sc_audit_log("companion_library", summary, 0, removed > 0);
    SC_LOG_INFO(TAG, "library: %s", summary);
    cJSON_Delete(in);

    if (removed < 0) {
        sc_web_send_json_error(req, 500, "rewrite failed");
        return;
    }
    if (removed == 0) {
        sc_web_send_json_error(req, 404, "line not found");
        return;
    }
    cJSON *j = cJSON_CreateObject();
    cJSON_AddBoolToObject(j, "deleted", 1);
    lib_send_json(req, 200, "OK", j);
}

void sc_companion_handle_notes(struct evhttp_request *req, void *arg)
{
    sc_channel_t *ch = arg;
    if (!lib_auth(req, ch)) {
        sc_web_send_json_error(req, 401, "Unauthorized");
        return;
    }
    const char *workspace = sc_web_channel_workspace(ch);
    if (!workspace || !workspace[0]) {
        sc_web_send_json_error(req, 500, "workspace not configured");
        return;
    }

    switch (evhttp_request_get_command(req)) {
    case EVHTTP_REQ_GET:
        lib_notes_list(req, workspace);
        return;
    case EVHTTP_REQ_DELETE:
        lib_notes_delete(req, workspace);
        return;
    default:
        sc_web_send_json_error(req, 405, "Method not allowed");
        return;
    }
}
