#include "memory.h"
#include "logger.h"
#include "util/str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_TAG "memory"
#define RECENT_DAYS 3

/* ---- Internal helpers ---- */

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len <= 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);

    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t n = fread(buf, 1, (size_t)len, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static int write_file(const char *path, const char *content)
{
    /* Atomic write: temp file + fsync + rename */
    sc_strbuf_t tmp_sb;
    sc_strbuf_init(&tmp_sb);
    sc_strbuf_appendf(&tmp_sb, "%s.tmp", path);
    char *tmp_path = sc_strbuf_finish(&tmp_sb);
    if (!tmp_path) return -1;

    FILE *f = fopen(tmp_path, "w");
    if (!f) { free(tmp_path); return -1; }

    size_t len = strlen(content);
    size_t written = fwrite(content, 1, len, f);
    int ok = (written == len);

    if (ok) {
        fflush(f);
        fsync(fileno(f));
    }
    fclose(f);

    if (ok) {
        ok = (rename(tmp_path, path) == 0);
    } else {
        unlink(tmp_path);
    }

    free(tmp_path);
    return ok ? 0 : -1;
}

static char *today_path(const sc_memory_t *mem)
{
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm = localtime_r(&now, &tm_buf);

    char date[9];   /* YYYYMMDD */
    char month[7];  /* YYYYMM */
    strftime(date, sizeof(date), "%Y%m%d", tm);
    strftime(month, sizeof(month), "%Y%m", tm);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/%s/%s.md", mem->memory_dir, month, date);
    return sc_strbuf_finish(&sb);
}

static char *date_path(const sc_memory_t *mem, time_t t)
{
    struct tm tm_buf;
    struct tm *tm = localtime_r(&t, &tm_buf);

    char date[9];
    char month[7];
    strftime(date, sizeof(date), "%Y%m%d", tm);
    strftime(month, sizeof(month), "%Y%m", tm);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/%s/%s.md", mem->memory_dir, month, date);
    return sc_strbuf_finish(&sb);
}

/* Ensure parent directory of path exists */
static void ensure_parent_dir(const char *path)
{
    char *dup = sc_strdup(path);
    if (!dup) return;

    /* Find last slash */
    char *slash = strrchr(dup, '/');
    if (slash) {
        *slash = '\0';
        mkdir(dup, 0755);
    }
    free(dup);
}

/* ---- Public API ---- */

sc_memory_t *sc_memory_new(const char *workspace)
{
    sc_memory_t *mem = calloc(1, sizeof(*mem));
    if (!mem) return NULL;

    mem->workspace = sc_strdup(workspace);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory", workspace);
    mem->memory_dir = sc_strbuf_finish(&sb);

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/MEMORY.md", workspace);
    mem->memory_file = sc_strbuf_finish(&sb);

    /* Ensure memory directory exists */
    mkdir(mem->memory_dir, 0755);

    SC_LOG_DEBUG(LOG_TAG, "memory store created at %s", mem->memory_dir);
    return mem;
}

void sc_memory_free(sc_memory_t *mem)
{
    if (!mem) return;
    free(mem->workspace);
    free(mem->memory_dir);
    free(mem->memory_file);
    free(mem);
}

char *sc_memory_read_long_term(const sc_memory_t *mem)
{
    if (!mem) return NULL;
    return read_file(mem->memory_file);
}

int sc_memory_write_long_term(const sc_memory_t *mem, const char *content)
{
    if (!mem || !content) return -1;
    int rc = write_file(mem->memory_file, content);
    if (rc == 0 && mem->index_cb)
        mem->index_cb("long_term", content, mem->index_ctx);
    return rc;
}

char *sc_memory_read_today(const sc_memory_t *mem)
{
    if (!mem) return NULL;
    char *path = today_path(mem);
    if (!path) return NULL;
    char *data = read_file(path);
    free(path);
    return data;
}

int sc_memory_append_today(const sc_memory_t *mem, const char *content)
{
    if (!mem || !content) return -1;

    char *path = today_path(mem);
    if (!path) return -1;

    ensure_parent_dir(path);

    /* Read existing content */
    char *existing = read_file(path);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    if (!existing || strlen(existing) == 0) {
        /* New file: add date header */
        time_t now = time(NULL);
        struct tm tm_buf;
        struct tm *tm = localtime_r(&now, &tm_buf);
        char hdr[32];
        strftime(hdr, sizeof(hdr), "# %Y-%m-%d", tm);
        sc_strbuf_appendf(&sb, "%s\n\n%s", hdr, content);
    } else {
        sc_strbuf_appendf(&sb, "%s\n%s", existing, content);
    }

    free(existing);

    char *result = sc_strbuf_finish(&sb);
    int ret = write_file(path, result);
    if (ret == 0 && mem->index_cb) {
        /* Derive source key from date (YYYYMMDD) */
        time_t now = time(NULL);
        struct tm tm_now_buf;
        struct tm *tm_now = localtime_r(&now, &tm_now_buf);
        char date_key[9];
        strftime(date_key, sizeof(date_key), "%Y%m%d", tm_now);
        mem->index_cb(date_key, result, mem->index_ctx);
    }
    free(result);
    free(path);
    return ret;
}

char *sc_memory_get_recent_notes(const sc_memory_t *mem, int days)
{
    if (!mem || days <= 0) return NULL;

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    int found = 0;

    time_t now = time(NULL);
    for (int i = 0; i < days; i++) {
        time_t t = now - (time_t)i * 86400;
        char *path = date_path(mem, t);
        if (!path) continue;

        char *data = read_file(path);
        free(path);
        if (!data) continue;

        if (found > 0) {
            sc_strbuf_append(&sb, "\n\n---\n\n");
        }
        sc_strbuf_append(&sb, data);
        free(data);
        found++;
    }

    if (found == 0) {
        sc_strbuf_free(&sb);
        return NULL;
    }

    return sc_strbuf_finish(&sb);
}

char *sc_memory_get_context(const sc_memory_t *mem)
{
    if (!mem) return NULL;

    char *long_term    = sc_memory_read_long_term(mem);
    char *recent_notes = sc_memory_get_recent_notes(mem, RECENT_DAYS);

    if (!long_term && !recent_notes) return NULL;

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_append(&sb, "# Memory\n\n");

    int has_long_term = (long_term != NULL);

    if (long_term) {
        sc_strbuf_append(&sb, "## Long-term Memory\n\n");
        sc_strbuf_append(&sb, long_term);
        free(long_term);
    }

    if (recent_notes) {
        if (has_long_term) {
            sc_strbuf_append(&sb, "\n\n---\n\n");
        }
        sc_strbuf_append(&sb, "## Recent Daily Notes\n\n");
        sc_strbuf_append(&sb, recent_notes);
        free(recent_notes);
    }

    return sc_strbuf_finish(&sb);
}

void sc_memory_set_index_cb(sc_memory_t *mem, sc_memory_index_cb cb, void *ctx)
{
    if (!mem) return;
    mem->index_cb = cb;
    mem->index_ctx = ctx;
}
