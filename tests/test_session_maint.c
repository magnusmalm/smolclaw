/*
 * smolclaw - session maintenance tests (compact / prune)
 */

#include "test_main.h"
#include "session_maint.h"
#include "session.h"
#include "util/str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

static char *join(const char *dir, const char *name)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/%s", dir, name);
    return sc_strbuf_finish(&sb);
}

static void write_file(const char *path, const char *contents)
{
    FILE *f = fopen(path, "w");
    ASSERT_NOT_NULL(f);
    fputs(contents, f);
    fclose(f);
}

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (buf) {
        size_t r = fread(buf, 1, (size_t)n, f);
        buf[r] = '\0';
    }
    fclose(f);
    return buf;
}

/* Write a session file with one small user message and a tool message whose
 * content is `body_len` 'x' bytes. */
static void write_session_with_tool_body(const char *path, size_t body_len)
{
    char *body = malloc(body_len + 1);
    memset(body, 'x', body_len);
    body[body_len] = '\0';

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb,
        "{\"type\":\"header\",\"key\":\"cli:default\","
        "\"created\":1,\"updated\":2,\"active_leaf\":1}\n");
    sc_strbuf_appendf(&sb,
        "{\"type\":\"message\",\"id\":0,\"parent_id\":-1,"
        "\"role\":\"user\",\"content\":\"hello world\"}\n");
    sc_strbuf_appendf(&sb,
        "{\"type\":\"message\",\"id\":1,\"parent_id\":0,"
        "\"role\":\"tool\",\"content\":\"%s\"}\n", body);
    char *s = sc_strbuf_finish(&sb);
    write_file(path, s);
    free(s);
    free(body);
}

static void rm_rf(const char *dir)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "rm -rf %s", dir);
    char *cmd = sc_strbuf_finish(&sb);
    int rc = system(cmd);
    (void)rc;
    free(cmd);
}

static void test_compact_truncates_oversized_tool_body(void)
{
    char dir[] = "/tmp/sc_test_maint_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(dir));
    char *path = join(dir, "s.jsonl");

    write_session_with_tool_body(path, 10000);

    int fields = 0;
    long saved = 0;
    int rc = sc_session_compact_file(path, 4096, &fields, &saved);
    ASSERT_INT_EQ(rc, 0);
    ASSERT_INT_EQ(fields, 1);
    ASSERT(saved > 0, "should report bytes saved");

    char *after = read_file(path);
    ASSERT_NOT_NULL(after);
    ASSERT(strstr(after, "[truncated") != NULL, "marker should be present");
    ASSERT(strstr(after, "hello world") != NULL, "user message must survive");
    ASSERT(strlen(after) < 10000, "file should be smaller than the raw body");
    free(after);

    /* .bak holds the original (full body). */
    char *bak = join(dir, "s.jsonl.bak");
    char *bak_contents = read_file(bak);
    ASSERT_NOT_NULL(bak_contents);
    ASSERT(strlen(bak_contents) > 10000, "backup retains the full body");
    free(bak_contents);
    free(bak);

    free(path);
    rm_rf(dir);
}

static void test_compact_noop_when_small(void)
{
    char dir[] = "/tmp/sc_test_maint_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(dir));
    char *path = join(dir, "s.jsonl");

    write_session_with_tool_body(path, 100);  /* below threshold */
    char *before = read_file(path);

    int fields = -1;
    long saved = -1;
    int rc = sc_session_compact_file(path, 4096, &fields, &saved);
    ASSERT_INT_EQ(rc, 1);   /* nothing to do */
    ASSERT_INT_EQ(fields, 0);

    char *after = read_file(path);
    ASSERT_STR_EQ(before, after);  /* untouched */

    /* No .bak written for a no-op. */
    char *bak = join(dir, "s.jsonl.bak");
    struct stat st;
    ASSERT(stat(bak, &st) != 0, "no .bak for a no-op compact");
    free(bak);

    free(before);
    free(after);
    free(path);
    rm_rf(dir);
}

/* After compaction the file must still load through the real session manager. */
static void test_compact_output_loads_in_manager(void)
{
    char dir[] = "/tmp/sc_test_maint_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(dir));
    char *path = join(dir, "cli__default.jsonl");  /* sanitized "cli:default" */

    write_session_with_tool_body(path, 8000);
    int rc = sc_session_compact_file(path, 2048, NULL, NULL);
    ASSERT_INT_EQ(rc, 0);

    sc_session_manager_t *sm = sc_session_manager_new(dir);
    ASSERT_NOT_NULL(sm);
    int count = 0;
    sc_llm_message_t *hist = sc_session_get_history(sm, "cli:default", &count);
    ASSERT_INT_EQ(count, 2);
    ASSERT_NOT_NULL(hist);
    ASSERT_STR_EQ(hist[0].content, "hello world");
    sc_session_manager_free(sm);

    free(path);
    rm_rf(dir);
}

static void set_mtime(const char *path, time_t when)
{
    struct timeval tv[2];
    tv[0].tv_sec = when; tv[0].tv_usec = 0;
    tv[1].tv_sec = when; tv[1].tv_usec = 0;
    utimes(path, tv);
}

static void test_prune_candidates_keeps_newest(void)
{
    char dir[] = "/tmp/sc_test_maint_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(dir));

    /* Five sessions, increasing mtime: s0 oldest ... s4 newest. */
    char *paths[5];
    for (int i = 0; i < 5; i++) {
        char name[32];
        snprintf(name, sizeof(name), "s%d.jsonl", i);
        paths[i] = join(dir, name);
        write_file(paths[i], "{\"type\":\"header\",\"key\":\"k\"}\n");
        set_mtime(paths[i], 1000 + i * 100);
    }
    /* A non-session file must be ignored. */
    char *other = join(dir, "notes.txt");
    write_file(other, "ignore me\n");

    int count = 0;
    char **cands = sc_session_prune_candidates(dir, 2, &count);
    ASSERT_INT_EQ(count, 3);   /* keep 2 newest → 3 pruned */
    ASSERT_NOT_NULL(cands);

    /* The newest two (s3, s4) must NOT appear among the candidates. */
    int seen_s3 = 0, seen_s4 = 0;
    for (int i = 0; i < count; i++) {
        if (strstr(cands[i], "s3.jsonl")) seen_s3 = 1;
        if (strstr(cands[i], "s4.jsonl")) seen_s4 = 1;
        free(cands[i]);
    }
    free(cands);
    ASSERT(!seen_s3 && !seen_s4, "newest sessions must be kept");

    /* keep >= file count → nothing to prune. */
    count = -1;
    cands = sc_session_prune_candidates(dir, 10, &count);
    ASSERT_INT_EQ(count, 0);
    ASSERT_NULL(cands);

    for (int i = 0; i < 5; i++) free(paths[i]);
    free(other);
    rm_rf(dir);
}

static void test_gateway_lock_detection(void)
{
    char dir[] = "/tmp/sc_test_maint_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(dir));

    /* No lock file yet → not running. */
    ASSERT_INT_EQ(sc_gateway_is_running(dir), 0);

    int fd = sc_gateway_lock_acquire(dir);
    ASSERT(fd >= 0, "should acquire run-lock");
    /* While held, the probe reports running (flock is per-open-file-
     * description, so a fresh open in the same process still blocks). */
    ASSERT_INT_EQ(sc_gateway_is_running(dir), 1);

    close(fd);
    /* Released → not running. */
    ASSERT_INT_EQ(sc_gateway_is_running(dir), 0);

    rm_rf(dir);
}

int main(void)
{
    printf("test_session_maint\n");

    RUN_TEST(test_compact_truncates_oversized_tool_body);
    RUN_TEST(test_compact_noop_when_small);
    RUN_TEST(test_compact_output_loads_in_manager);
    RUN_TEST(test_prune_candidates_keeps_newest);
    RUN_TEST(test_gateway_lock_detection);

    TEST_REPORT();
}
