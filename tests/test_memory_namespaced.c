/*
 * smolclaw — session-isolation Stage 2 tests.
 *
 * Cover the namespaced (per-session) sc_memory_t mode added for the
 * Phase 4 memory-contamination fix described in
 * docs/design/session-isolation-plan.md.
 */

#include "test_main.h"

#include "memory.h"
#include "util/str.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ---- helpers ---- */

static char *make_workspace(void)
{
    static char tmpl[64];
    snprintf(tmpl, sizeof(tmpl), "/tmp/sc_test_mem_ns_XXXXXX");
    return mkdtemp(tmpl);
}

static void rm_rf(const char *path)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "rm -rf %s", path);
    char *cmd = sc_strbuf_finish(&sb);
    if (cmd) { system(cmd); free(cmd); }
}

static char *read_whole(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)n, f);
    buf[r] = '\0';
    fclose(f);
    return buf;
}

static int path_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static void write_text(const char *path, const char *content)
{
    /* ensure parent dir */
    char *dup = sc_strdup(path);
    if (dup) {
        char *slash = strrchr(dup, '/');
        if (slash) {
            *slash = '\0';
            /* Recursive: walk all components and mkdir each. */
            for (char *p = dup + 1; *p; p++) {
                if (*p == '/') {
                    *p = '\0';
                    mkdir(dup, 0755);
                    *p = '/';
                }
            }
            mkdir(dup, 0755);
        }
        free(dup);
    }
    FILE *f = fopen(path, "w");
    if (f) { fputs(content, f); fclose(f); }
}

/* Today's per-workspace memory file (shared mode), constructed the way
 * memory.c constructs it. Used to assert on-disk isolation. */
static char *shared_today_path(const char *workspace)
{
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm = localtime_r(&now, &tm_buf);
    char date[9];
    char month[7];
    strftime(date, sizeof(date), "%Y%m%d", tm);
    strftime(month, sizeof(month), "%Y%m", tm);
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/%s/%s.md", workspace, month, date);
    return sc_strbuf_finish(&sb);
}

static char *ns_today_path(const char *workspace, const char *ns)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/_sessions/%s/today.md", workspace, ns);
    return sc_strbuf_finish(&sb);
}

static char *ns_last_access_path(const char *workspace, const char *ns)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/_sessions/%s/last_access", workspace, ns);
    return sc_strbuf_finish(&sb);
}

/* ---- Tests ---- */

static void test_invalid_ns_id_rejected(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);
    ASSERT_NULL(sc_memory_new_namespaced(ws, NULL));
    ASSERT_NULL(sc_memory_new_namespaced(ws, ""));
    ASSERT_NULL(sc_memory_new_namespaced(ws, "../escape"));
    ASSERT_NULL(sc_memory_new_namespaced(ws, "with/slash"));
    ASSERT_NULL(sc_memory_new_namespaced(ws, "with space"));
    ASSERT_NULL(sc_memory_new_namespaced(ws, "with.dot"));
    /* Valid characters: alnum + _ + - */
    sc_memory_t *ok = sc_memory_new_namespaced(ws, "abc123_x-Y");
    ASSERT_NOT_NULL(ok);
    sc_memory_free(ok);
    rm_rf(ws);
}

static void test_namespaced_writes_isolated_from_shared(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    sc_memory_t *iso = sc_memory_new_namespaced(ws, "abcdef0123456789");
    ASSERT_NOT_NULL(iso);

    int rc = sc_memory_append_today(iso, "isolated note about retention work");
    ASSERT_INT_EQ(rc, 0);

    /* Per-session file written. */
    char *ns_path = ns_today_path(ws, "abcdef0123456789");
    ASSERT(path_exists(ns_path), "per-session today.md exists");
    char *got = read_whole(ns_path);
    ASSERT_NOT_NULL(got);
    ASSERT(strstr(got, "retention work") != NULL, "per-session content present");

    /* Shared today.md NOT written. */
    char *shared_path = shared_today_path(ws);
    ASSERT(!path_exists(shared_path), "shared today.md untouched");

    free(got);
    free(ns_path);
    free(shared_path);
    sc_memory_free(iso);
    rm_rf(ws);
}

static void test_namespaced_read_does_not_leak_shared(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    /* Pre-populate the shared today.md as if a prior non-isolated turn
     * had consolidated content into it. */
    char *shared_path = shared_today_path(ws);
    write_text(shared_path, "# Shared\n\nSensitive other-tenant retention details\n");

    sc_memory_t *iso = sc_memory_new_namespaced(ws, "fresh01");
    ASSERT_NOT_NULL(iso);

    char *today = sc_memory_read_today(iso);
    ASSERT_NULL(today);  /* per-session today.md doesn't exist yet */

    char *recent = sc_memory_get_recent_notes(iso, 7);
    ASSERT_NULL(recent);  /* still nothing — must not fall back to shared */

    char *ctx = sc_memory_get_context(iso);
    if (ctx) {
        ASSERT(strstr(ctx, "retention") == NULL,
               "context must not leak shared content");
        free(ctx);
    }
    /* ctx == NULL is also acceptable here (no per-session data yet). */

    free(shared_path);
    sc_memory_free(iso);
    rm_rf(ws);
}

static void test_two_namespaces_isolated(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    sc_memory_t *a = sc_memory_new_namespaced(ws, "alpha01");
    sc_memory_t *b = sc_memory_new_namespaced(ws, "bravo02");
    ASSERT_NOT_NULL(a);
    ASSERT_NOT_NULL(b);

    sc_memory_append_today(a, "alpha-only fact");
    sc_memory_append_today(b, "bravo-only fact");

    char *a_today = sc_memory_read_today(a);
    char *b_today = sc_memory_read_today(b);
    ASSERT_NOT_NULL(a_today);
    ASSERT_NOT_NULL(b_today);
    ASSERT(strstr(a_today, "alpha-only") != NULL, "A sees its own write");
    ASSERT(strstr(a_today, "bravo-only") == NULL, "A does not see B");
    ASSERT(strstr(b_today, "bravo-only") != NULL, "B sees its own write");
    ASSERT(strstr(b_today, "alpha-only") == NULL, "B does not see A");

    /* Context follows the same isolation. */
    char *a_ctx = sc_memory_get_context(a);
    ASSERT_NOT_NULL(a_ctx);
    ASSERT(strstr(a_ctx, "bravo-only") == NULL,
           "A's context must not contain B's content");

    free(a_today);
    free(b_today);
    free(a_ctx);
    sc_memory_free(a);
    sc_memory_free(b);
    rm_rf(ws);
}

static void test_namespaced_self_continuity(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    sc_memory_t *first = sc_memory_new_namespaced(ws, "session01");
    ASSERT_NOT_NULL(first);
    sc_memory_append_today(first, "first turn finding");
    sc_memory_free(first);

    /* New struct, same namespace_id — represents the second turn of the
     * same delegate session. */
    sc_memory_t *second = sc_memory_new_namespaced(ws, "session01");
    ASSERT_NOT_NULL(second);
    char *today = sc_memory_read_today(second);
    ASSERT_NOT_NULL(today);
    ASSERT(strstr(today, "first turn finding") != NULL,
           "second turn sees first turn's writes");

    sc_memory_append_today(second, "second turn finding");
    free(today);
    today = sc_memory_read_today(second);
    ASSERT_NOT_NULL(today);
    ASSERT(strstr(today, "first turn finding") != NULL, "first persists");
    ASSERT(strstr(today, "second turn finding") != NULL, "second appended");

    free(today);
    sc_memory_free(second);
    rm_rf(ws);
}

static void test_long_term_blocked_for_namespaced(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    /* Populate shared MEMORY.md so we can detect leakage. */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/MEMORY.md", ws);
    char *mem_md = sc_strbuf_finish(&sb);
    write_text(mem_md, "long-term durable knowledge");

    sc_memory_t *iso = sc_memory_new_namespaced(ws, "nslt01");
    ASSERT_NOT_NULL(iso);

    char *lt = sc_memory_read_long_term(iso);
    ASSERT_NULL(lt);

    /* Write attempts are a silent no-op (return 0) and don't touch
     * shared MEMORY.md. */
    int rc = sc_memory_write_long_term(iso, "should not persist anywhere");
    ASSERT_INT_EQ(rc, 0);
    char *after = read_whole(mem_md);
    ASSERT_NOT_NULL(after);
    ASSERT_STR_EQ(after, "long-term durable knowledge");

    free(after);
    free(mem_md);
    sc_memory_free(iso);
    rm_rf(ws);
}

static void test_namespaced_context_has_no_long_term_block(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/MEMORY.md", ws);
    char *mem_md = sc_strbuf_finish(&sb);
    write_text(mem_md, "shared long-term content");
    free(mem_md);

    sc_memory_t *iso = sc_memory_new_namespaced(ws, "ctxtest");
    ASSERT_NOT_NULL(iso);
    sc_memory_append_today(iso, "isolated note");

    char *ctx = sc_memory_get_context(iso);
    ASSERT_NOT_NULL(ctx);
    ASSERT(strstr(ctx, "Long-term Memory") == NULL,
           "context omits long-term header in namespaced mode");
    ASSERT(strstr(ctx, "shared long-term content") == NULL,
           "context does not contain shared long-term body");
    ASSERT(strstr(ctx, "isolated note") != NULL,
           "context still contains the session's own notes");

    free(ctx);
    sc_memory_free(iso);
    rm_rf(ws);
}

static void test_shared_mode_unchanged(void)
{
    /* Back-compat: shared memory should behave exactly as before. */
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    sc_memory_t *shared = sc_memory_new(ws);
    ASSERT_NOT_NULL(shared);

    sc_memory_write_long_term(shared, "shared durable");
    sc_memory_append_today(shared, "shared today");

    char *lt = sc_memory_read_long_term(shared);
    ASSERT_NOT_NULL(lt);
    ASSERT_STR_EQ(lt, "shared durable");
    free(lt);

    char *today = sc_memory_read_today(shared);
    ASSERT_NOT_NULL(today);
    ASSERT(strstr(today, "shared today") != NULL, "shared today readable");
    free(today);

    /* _sessions dir must not exist in shared-only mode. */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/_sessions", ws);
    char *sd = sc_strbuf_finish(&sb);
    ASSERT(!path_exists(sd), "shared mode does not create _sessions dir");

    free(sd);
    sc_memory_free(shared);
    rm_rf(ws);
}

static void test_last_access_touched_on_write(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    sc_memory_t *iso = sc_memory_new_namespaced(ws, "lats01");
    ASSERT_NOT_NULL(iso);

    char *la_path = ns_last_access_path(ws, "lats01");
    ASSERT(path_exists(la_path), "last_access created on namespaced new");

    /* Read the current value, force time to advance, then write and
     * confirm last_access changed. */
    char *before = read_whole(la_path);
    ASSERT_NOT_NULL(before);
    sleep(1);
    sc_memory_append_today(iso, "another finding");
    char *after = read_whole(la_path);
    ASSERT_NOT_NULL(after);
    ASSERT(strcmp(before, after) != 0, "last_access epoch advanced");

    free(before);
    free(after);
    free(la_path);
    sc_memory_free(iso);
    rm_rf(ws);
}

static void test_cleanup_missing_sessions_dir_returns_zero(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    /* Brand-new workspace — no memory/_sessions/ has ever existed. */
    int rc = sc_memory_cleanup_sessions(ws, 60);
    ASSERT_INT_EQ(rc, 0);

    rm_rf(ws);
}

static void test_cleanup_removes_old_and_preserves_fresh(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    /* Old session: write last_access into the past. */
    sc_memory_t *old_s = sc_memory_new_namespaced(ws, "oldsess");
    ASSERT_NOT_NULL(old_s);
    sc_memory_append_today(old_s, "ancient");
    sc_memory_free(old_s);
    {
        char *la = ns_last_access_path(ws, "oldsess");
        long long past = (long long)time(NULL) - 3600;
        char buf[32];
        snprintf(buf, sizeof(buf), "%lld\n", past);
        write_text(la, buf);
        free(la);
    }

    /* Fresh session: leave last_access as-is (now). */
    sc_memory_t *fresh = sc_memory_new_namespaced(ws, "freshsess");
    ASSERT_NOT_NULL(fresh);
    sc_memory_append_today(fresh, "current");
    sc_memory_free(fresh);

    /* TTL = 600s (10 min). Old (>1h) should go, fresh should stay. */
    int removed = sc_memory_cleanup_sessions(ws, 600);
    ASSERT_INT_EQ(removed, 1);

    char *old_today = ns_today_path(ws, "oldsess");
    char *fresh_today = ns_today_path(ws, "freshsess");
    ASSERT(!path_exists(old_today), "old session dir removed");
    ASSERT(path_exists(fresh_today), "fresh session dir preserved");
    free(old_today);
    free(fresh_today);

    rm_rf(ws);
}

static void test_cleanup_idempotent(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    sc_memory_t *iso = sc_memory_new_namespaced(ws, "idem01");
    sc_memory_append_today(iso, "x");
    sc_memory_free(iso);

    /* No session is old yet — both calls should remove 0. */
    int r1 = sc_memory_cleanup_sessions(ws, 3600);
    int r2 = sc_memory_cleanup_sessions(ws, 3600);
    ASSERT_INT_EQ(r1, 0);
    ASSERT_INT_EQ(r2, 0);

    rm_rf(ws);
}

static void test_cleanup_ignores_unrelated_entries(void)
{
    char *ws = make_workspace();
    ASSERT_NOT_NULL(ws);

    /* Create _sessions with one valid session + one foreign file/dir. */
    sc_memory_t *iso = sc_memory_new_namespaced(ws, "ok01");
    sc_memory_free(iso);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/_sessions/has spaces", ws);
    char *foreign = sc_strbuf_finish(&sb);
    mkdir(foreign, 0755);

    int removed = sc_memory_cleanup_sessions(ws, 0);  /* age >= 0 always */
    /* "has spaces" is not a valid namespace id, so it must not be touched. */
    ASSERT(path_exists(foreign), "non-namespace entries preserved");
    ASSERT(removed >= 1, "valid session was removed");

    free(foreign);
    rm_rf(ws);
}

int main(void)
{
    printf("test_memory_namespaced:\n");
    RUN_TEST(test_invalid_ns_id_rejected);
    RUN_TEST(test_namespaced_writes_isolated_from_shared);
    RUN_TEST(test_namespaced_read_does_not_leak_shared);
    RUN_TEST(test_two_namespaces_isolated);
    RUN_TEST(test_namespaced_self_continuity);
    RUN_TEST(test_long_term_blocked_for_namespaced);
    RUN_TEST(test_namespaced_context_has_no_long_term_block);
    RUN_TEST(test_shared_mode_unchanged);
    RUN_TEST(test_last_access_touched_on_write);
    RUN_TEST(test_cleanup_missing_sessions_dir_returns_zero);
    RUN_TEST(test_cleanup_removes_old_and_preserves_fresh);
    RUN_TEST(test_cleanup_idempotent);
    RUN_TEST(test_cleanup_ignores_unrelated_entries);
    TEST_REPORT();
}
