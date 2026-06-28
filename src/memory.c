#include "memory.h"
#include "logger.h"
#include "util/str.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define LOG_TAG "memory"
#define RECENT_DAYS 3

/* ---- Internal helpers ---- */

#define MAX_MEMORY_FILE_SIZE (256 * 1024)  /* 256 KB cap for memory files */

static int is_namespaced(const sc_memory_t *mem)
{
    return mem && mem->namespace_id && mem->namespace_id[0];
}

/* Allow only [A-Za-z0-9_-]. Reject empty, "..", or anything containing '/'.
 * The web channel already derives namespace_ids as truncated SHA-256 hex,
 * but this defense-in-depth check makes the constructor safe to call with
 * arbitrary caller-supplied strings. */
static int is_valid_ns_id(const char *s)
{
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++) {
        char c = *p;
        int ok = (c >= 'A' && c <= 'Z') ||
                 (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') ||
                  c == '_' || c == '-';
        if (!ok) return 0;
    }
    return 1;
}

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len <= 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);

    if (len > MAX_MEMORY_FILE_SIZE) {
        SC_LOG_WARN(LOG_TAG, "File %s is %ld bytes, truncating to %d",
                    path, len, MAX_MEMORY_FILE_SIZE);
        len = MAX_MEMORY_FILE_SIZE;
    }

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
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    if (is_namespaced(mem)) {
        /* Single per-session file; no date partition. */
        sc_strbuf_appendf(&sb, "%s/today.md", mem->session_dir);
    } else {
        time_t now = time(NULL);
        struct tm tm_buf;
        struct tm *tm = localtime_r(&now, &tm_buf);

        char date[9];   /* YYYYMMDD */
        char month[7];  /* YYYYMM */
        strftime(date, sizeof(date), "%Y%m%d", tm);
        strftime(month, sizeof(month), "%Y%m", tm);

        sc_strbuf_appendf(&sb, "%s/%s/%s.md", mem->memory_dir, month, date);
    }
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

/* Touch the per-session last_access marker. No-op for shared memory. */
static void touch_last_access(const sc_memory_t *mem)
{
    if (!is_namespaced(mem)) return;

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/last_access", mem->session_dir);
    char *path = sc_strbuf_finish(&sb);
    if (!path) return;

    time_t now = time(NULL);
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%lld\n", (long long)now);
    if (n > 0) write_file(path, buf);
    free(path);
}

/* ---- Public API ---- */

sc_memory_t *sc_memory_new(const char *workspace)
{
    if (!workspace) return NULL;

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

sc_memory_t *sc_memory_new_namespaced(const char *workspace,
                                       const char *namespace_id)
{
    if (!workspace || !is_valid_ns_id(namespace_id)) return NULL;

    sc_memory_t *mem = calloc(1, sizeof(*mem));
    if (!mem) return NULL;

    mem->workspace = sc_strdup(workspace);
    mem->namespace_id = sc_strdup(namespace_id);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory", workspace);
    mem->memory_dir = sc_strbuf_finish(&sb);

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/_sessions/%s", workspace, namespace_id);
    mem->session_dir = sc_strbuf_finish(&sb);

    /* memory_file deliberately left NULL — long-term reads/writes are
     * no-ops in namespaced mode. */

    /* Ensure dir tree exists: memory/, memory/_sessions/, memory/_sessions/<ns>/ */
    mkdir(mem->memory_dir, 0755);

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/_sessions", workspace);
    char *sessions_root = sc_strbuf_finish(&sb);
    if (sessions_root) {
        mkdir(sessions_root, 0755);
        free(sessions_root);
    }

    mkdir(mem->session_dir, 0755);
    touch_last_access(mem);

    SC_LOG_DEBUG(LOG_TAG, "isolated memory store created at %s",
                 mem->session_dir);
    return mem;
}

void sc_memory_free(sc_memory_t *mem)
{
    if (!mem) return;
    free(mem->workspace);
    free(mem->memory_dir);
    free(mem->memory_file);
    free(mem->namespace_id);
    free(mem->session_dir);
    free(mem);
}

char *sc_memory_read_long_term(const sc_memory_t *mem)
{
    if (!mem) return NULL;
    if (is_namespaced(mem)) return NULL;  /* isolated: no shared long-term */
    return read_file(mem->memory_file);
}

int sc_memory_write_long_term(const sc_memory_t *mem, const char *content)
{
    if (!mem || !content) return -1;
    if (is_namespaced(mem)) return 0;  /* isolated: silently drop */
    int rc = write_file(mem->memory_file, content);
    if (rc == 0 && mem->index_cb)
        mem->index_cb("long_term", content, mem->index_ctx);
    return rc;
}

int sc_memory_append_long_term(const sc_memory_t *mem, const char *entry)
{
    if (!mem || !entry || !entry[0]) return -1;
    if (is_namespaced(mem)) return 0;  /* isolated: silently drop */

    char *existing = read_file(mem->memory_file);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    if (existing && existing[0]) {
        sc_strbuf_append(&sb, existing);
        size_t n = strlen(existing);
        if (existing[n - 1] != '\n') sc_strbuf_append(&sb, "\n");
    }
    sc_strbuf_appendf(&sb, "- %s\n", entry);
    free(existing);

    char *full = sc_strbuf_finish(&sb);
    if (!full) return -1;
    int rc = write_file(mem->memory_file, full);
    if (rc == 0 && mem->index_cb)
        mem->index_cb("long_term", full, mem->index_ctx);
    free(full);
    return rc;
}

char *sc_memory_read_today(const sc_memory_t *mem)
{
    if (!mem) return NULL;
    char *path = today_path(mem);
    if (!path) return NULL;
    char *data = read_file(path);
    free(path);
    touch_last_access(mem);
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
        /* Derive source key from date (YYYYMMDD) or namespace for isolated */
        const char *src;
        char date_key[9];
        if (is_namespaced(mem)) {
            src = mem->namespace_id;
        } else {
            time_t now = time(NULL);
            struct tm tm_now_buf;
            struct tm *tm_now = localtime_r(&now, &tm_now_buf);
            strftime(date_key, sizeof(date_key), "%Y%m%d", tm_now);
            src = date_key;
        }
        mem->index_cb(src, result, mem->index_ctx);
    }
    free(result);
    free(path);

    touch_last_access(mem);
    return ret;
}

char *sc_memory_get_recent_notes(const sc_memory_t *mem, int days)
{
    if (!mem) return NULL;

    if (is_namespaced(mem)) {
        /* Isolated sessions are ephemeral — `days` is ignored and we return
         * today.md content if any. */
        return sc_memory_read_today(mem);
    }

    if (days <= 0) return NULL;

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

    char *long_term    = sc_memory_read_long_term(mem);  /* NULL in namespaced */
    char *recent_notes = sc_memory_get_recent_notes(mem, RECENT_DAYS);

    if (!long_term && !recent_notes) return NULL;

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_append(&sb, "# Memory\n\n");

    int has_long_term = (long_term != NULL);

    if (long_term) {
        sc_strbuf_append(&sb, "## Long-term Memory\n\n");
        /* Truncate to first 200 lines to prevent context pollution.
         * MEMORY.md should be a concise index, not detailed storage. */
        int lines = 0;
        char *cutoff = long_term;
        while (*cutoff && lines < 200) {
            if (*cutoff == '\n') lines++;
            cutoff++;
        }
        if (*cutoff) {
            *cutoff = '\0';
            sc_strbuf_append(&sb, long_term);
            sc_strbuf_appendf(&sb,
                "\n[...truncated at 200 lines — use memory_read for full content]");
        } else {
            sc_strbuf_append(&sb, long_term);
        }
        free(long_term);
    }

    if (recent_notes) {
        if (has_long_term) {
            sc_strbuf_append(&sb, "\n\n---\n\n");
        }
        sc_strbuf_append(&sb,
                         is_namespaced(mem)
                            ? "## Session Notes\n\n"
                            : "## Recent Daily Notes\n\n");
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

/* ---- Cleanup ---- */

/* Recursively remove `path` and its children. Used only for per-session
 * memory dirs whose contents we own (today.md, scratchpad.md, last_access,
 * and possibly more added by Stage 4). */
static int remove_tree(const char *path)
{
    DIR *d = opendir(path);
    if (!d) {
        /* Not a directory or missing — try unlinking as a file. */
        return unlink(path);
    }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "%s/%s", path, ent->d_name);
        char *child = sc_strbuf_finish(&sb);
        if (child) {
            remove_tree(child);
            free(child);
        }
    }
    closedir(d);
    return rmdir(path);
}

/* Read a session's last_access epoch. Returns -1 if missing/unreadable. */
static long long read_last_access(const char *session_dir)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/last_access", session_dir);
    char *path = sc_strbuf_finish(&sb);
    if (!path) return -1;

    char *data = read_file(path);
    free(path);
    if (!data) return -1;

    long long v = strtoll(data, NULL, 10);
    free(data);
    return v > 0 ? v : -1;
}

int sc_memory_cleanup_sessions(const char *workspace, int max_age_secs)
{
    if (!workspace || max_age_secs < 0) return -1;

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/_sessions", workspace);
    char *root = sc_strbuf_finish(&sb);
    if (!root) return -1;

    DIR *d = opendir(root);
    if (!d) {
        free(root);
        /* Missing _sessions dir is normal — no isolated sessions ever ran. */
        return (errno == ENOENT) ? 0 : -1;
    }

    time_t now = time(NULL);
    int removed = 0;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        /* Only clean entries that look like valid namespace IDs to avoid
         * walking into things we didn't create. */
        if (!is_valid_ns_id(ent->d_name)) continue;

        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "%s/%s", root, ent->d_name);
        char *session_dir = sc_strbuf_finish(&sb);
        if (!session_dir) continue;

        struct stat st;
        if (stat(session_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
            free(session_dir);
            continue;
        }

        long long last = read_last_access(session_dir);
        long long age;
        if (last > 0) {
            age = (long long)now - last;
        } else {
            /* Fallback: use directory mtime. */
            age = (long long)now - (long long)st.st_mtime;
        }

        if (age >= max_age_secs) {
            if (remove_tree(session_dir) == 0) {
                removed++;
                SC_LOG_DEBUG(LOG_TAG,
                             "cleaned up isolated session %s (age=%llds)",
                             ent->d_name, age);
            } else {
                SC_LOG_WARN(LOG_TAG,
                            "failed to remove isolated session dir %s",
                            session_dir);
            }
        }
        free(session_dir);
    }
    closedir(d);
    free(root);

    return removed;
}
