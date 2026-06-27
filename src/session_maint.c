#include "session_maint.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "cJSON.h"
#include "logger.h"
#include "util/json_helpers.h"
#include "util/str.h"

#define LOG_TAG "session"

/* Read one '\n'-terminated (or EOF-terminated) line into *buf, growing it as
 * needed. session_read_jsonl() in session.c caps lines at 64 KB with fgets,
 * but compact exists precisely for files with oversized tool outputs, so we
 * must handle arbitrarily long lines. Returns the line length (excluding the
 * stored NUL), or -1 at clean EOF. */
static long read_line(FILE *f, char **buf, size_t *cap)
{
    if (!*buf) {
        *cap = 8192;
        *buf = malloc(*cap);
        if (!*buf) return -1;
    }
    size_t len = 0;
    int c;
    while ((c = fgetc(f)) != EOF) {
        if (len + 1 >= *cap) {
            size_t nc = *cap * 2;
            char *nb = realloc(*buf, nc);
            if (!nb) return -1;
            *buf = nb;
            *cap = nc;
        }
        (*buf)[len++] = (char)c;
        if (c == '\n') break;
    }
    if (len == 0 && c == EOF) return -1;
    (*buf)[len] = '\0';
    return (long)len;
}

/* Build a head + marker + tail truncation of an oversized string. Returns a
 * malloc'd string (caller frees) or NULL if no truncation is warranted. */
static char *make_truncated(const char *s, size_t len, size_t max, long *saved)
{
    size_t head = max / 2;
    size_t tail = max / 4;
    if (head + tail >= len) return NULL;
    size_t cut = len - head - tail;

    char marker[64];
    int mlen = snprintf(marker, sizeof(marker),
                        "\n...[truncated %zu bytes]...\n", cut);
    if (mlen < 0) return NULL;

    char *out = malloc(head + (size_t)mlen + tail + 1);
    if (!out) return NULL;
    memcpy(out, s, head);
    memcpy(out + head, marker, (size_t)mlen);
    memcpy(out + head + (size_t)mlen, s + len - tail, tail);
    out[head + (size_t)mlen + tail] = '\0';

    if (saved) *saved += (long)cut;
    return out;
}

/* Verify a rewritten temp file parses as a session: every non-empty line is
 * valid JSON and at least one "header" line is present. Returns 0 if valid. */
static int validate_session_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char *line = NULL;
    size_t cap = 0;
    long n;
    int header_seen = 0;
    int ok = 1;

    while ((n = read_line(f, &line, &cap)) != -1) {
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        if (n == 0) continue;
        cJSON *obj = cJSON_Parse(line);
        if (!obj) { ok = 0; break; }
        if (strcmp(sc_json_get_string(obj, "type", ""), "header") == 0)
            header_seen = 1;
        cJSON_Delete(obj);
    }

    free(line);
    fclose(f);
    return (ok && header_seen) ? 0 : -1;
}

static int copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    if (!in) return -1;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }

    char buf[65536];
    size_t r;
    int ok = 1;
    while ((r = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, r, out) != r) { ok = 0; break; }
    }
    if (ok) ok = (fflush(out) == 0);
    if (ok) ok = (fsync(fileno(out)) == 0);
    fclose(out);
    fclose(in);
    if (!ok) unlink(dst);
    return ok ? 0 : -1;
}

int sc_session_compact_file(const char *path, size_t max_field_bytes,
                            int *out_fields, long *out_saved_bytes)
{
    if (!path) return -1;
    if (max_field_bytes < 64) max_field_bytes = 64;

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s.compact.tmp", path);
    FILE *out = fopen(tmp, "w");
    if (!out) { fclose(f); return -1; }

    char *line = NULL;
    size_t cap = 0;
    long n;
    int fields = 0;
    long saved = 0;
    int header_seen = 0;
    int ok = 1;

    while ((n = read_line(f, &line, &cap)) != -1) {
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        if (n == 0) continue;

        cJSON *obj = cJSON_Parse(line);
        if (!obj) { ok = 0; break; }  /* malformed → abort, keep original */

        const char *type = sc_json_get_string(obj, "type", "");
        if (strcmp(type, "header") == 0) header_seen = 1;

        /* Truncate oversized tool-result bodies (stdout / web_fetch). */
        if (strcmp(type, "message") == 0 &&
            strcmp(sc_json_get_string(obj, "role", ""), "tool") == 0) {
            cJSON *content = cJSON_GetObjectItem(obj, "content");
            if (cJSON_IsString(content) && content->valuestring) {
                size_t len = strlen(content->valuestring);
                if (len > max_field_bytes) {
                    char *trunc = make_truncated(content->valuestring, len,
                                                 max_field_bytes, &saved);
                    if (trunc) {
                        cJSON_ReplaceItemInObject(obj, "content",
                                                  cJSON_CreateString(trunc));
                        free(trunc);
                        fields++;
                    }
                }
            }
        }

        char *outline = cJSON_PrintUnformatted(obj);
        cJSON_Delete(obj);
        if (!outline) { ok = 0; break; }
        if (fprintf(out, "%s\n", outline) < 0) ok = 0;
        free(outline);
        if (!ok) break;
    }

    free(line);
    if (ok) ok = (fflush(out) == 0);
    if (ok) ok = (fsync(fileno(out)) == 0);
    fclose(out);
    fclose(f);

    if (!ok || !header_seen) {
        unlink(tmp);
        return -1;
    }

    if (fields == 0) {
        unlink(tmp);
        if (out_fields) *out_fields = 0;
        if (out_saved_bytes) *out_saved_bytes = 0;
        return 1;  /* nothing to do */
    }

    if (validate_session_file(tmp) != 0) {
        SC_LOG_ERROR(LOG_TAG, "Compacted %s failed validation; keeping original",
                     path);
        unlink(tmp);
        return -1;
    }

    char bak[1024];
    snprintf(bak, sizeof(bak), "%s.bak", path);
    if (copy_file(path, bak) != 0) {
        SC_LOG_ERROR(LOG_TAG, "Could not write backup %s; aborting compact", bak);
        unlink(tmp);
        return -1;
    }

    if (rename(tmp, path) != 0) {
        SC_LOG_ERROR(LOG_TAG, "Failed to swap compacted %s: %s",
                     path, strerror(errno));
        unlink(tmp);
        return -1;
    }

    if (out_fields) *out_fields = fields;
    if (out_saved_bytes) *out_saved_bytes = saved;
    return 0;
}

/* ---------- prune ---------- */

typedef struct {
    char *path;
    time_t mtime;
} prune_entry_t;

static int prune_cmp_newest_first(const void *a, const void *b)
{
    time_t ma = ((const prune_entry_t *)a)->mtime;
    time_t mb = ((const prune_entry_t *)b)->mtime;
    if (ma < mb) return 1;
    if (ma > mb) return -1;
    return 0;
}

char **sc_session_prune_candidates(const char *sessions_dir, int keep,
                                   int *out_count)
{
    if (out_count) *out_count = 0;
    if (!sessions_dir || keep < 0) return NULL;

    DIR *dir = opendir(sessions_dir);
    if (!dir) return NULL;

    prune_entry_t *entries = NULL;
    int count = 0, alloc = 0;
    struct dirent *ent;

    while ((ent = readdir(dir)) != NULL) {
        size_t len = strlen(ent->d_name);
        if (len <= 6 || strcmp(ent->d_name + len - 6, ".jsonl") != 0)
            continue;

        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "%s/%s", sessions_dir, ent->d_name);
        char *fpath = sc_strbuf_finish(&sb);

        struct stat st;
        if (stat(fpath, &st) != 0 || !S_ISREG(st.st_mode)) {
            free(fpath);
            continue;
        }

        if (count >= alloc) {
            int na = alloc ? alloc * 2 : 16;
            prune_entry_t *ne = realloc(entries, (size_t)na * sizeof(*ne));
            if (!ne) { free(fpath); break; }
            entries = ne;
            alloc = na;
        }
        entries[count].path = fpath;
        entries[count].mtime = st.st_mtime;
        count++;
    }
    closedir(dir);

    if (count <= keep) {
        for (int i = 0; i < count; i++) free(entries[i].path);
        free(entries);
        return NULL;
    }

    qsort(entries, (size_t)count, sizeof(*entries), prune_cmp_newest_first);

    int n_prune = count - keep;
    char **result = malloc((size_t)n_prune * sizeof(char *));
    if (!result) {
        for (int i = 0; i < count; i++) free(entries[i].path);
        free(entries);
        return NULL;
    }

    for (int i = 0; i < count; i++) {
        if (i < keep) free(entries[i].path);       /* kept (newest) */
        else result[i - keep] = entries[i].path;   /* prune (oldest) */
    }
    free(entries);

    if (out_count) *out_count = n_prune;
    return result;
}

/* ---------- gateway run-lock ---------- */

static char *gateway_lock_path(const char *workspace)
{
    if (!workspace) return NULL;
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/.gateway.lock", workspace);
    return sc_strbuf_finish(&sb);
}

int sc_gateway_lock_acquire(const char *workspace)
{
    char *path = gateway_lock_path(workspace);
    if (!path) return -1;

    int fd = open(path, O_RDWR | O_CREAT, 0600);
    free(path);
    if (fd < 0) return -1;

    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        close(fd);
        return -1;
    }
    return fd;  /* held for the gateway's lifetime */
}

int sc_gateway_is_running(const char *workspace)
{
    char *path = gateway_lock_path(workspace);
    if (!path) return 0;

    int fd = open(path, O_RDWR, 0600);  /* do not create */
    free(path);
    if (fd < 0) return 0;  /* no lock file → never ran */

    int running = 0;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        running = 1;  /* someone else holds it */
    } else {
        flock(fd, LOCK_UN);
    }
    close(fd);
    return running;
}
