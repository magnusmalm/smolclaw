/*
 * smolclaw - project memory / repo_search tests (task 4.5).
 *
 * Pure helpers (hash, language, tokenize, match score) plus a build->search
 * round-trip over a temp workspace, with SMOLCLAW_HOME pointed at a temp dir so
 * the index file lands there (never inside a repo).
 */

#include "test_main.h"
#include "project_memory.h"
#include "util/str.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

static void test_workspace_hash(void)
{
    char *a = sc_pm_workspace_hash("/home/u/proj");
    char *b = sc_pm_workspace_hash("/home/u/proj");
    char *c = sc_pm_workspace_hash("/home/u/other");
    ASSERT_NOT_NULL(a);
    ASSERT_INT_EQ((int)strlen(a), 16);
    ASSERT_STR_EQ(a, b);                 /* deterministic */
    ASSERT(strcmp(a, c) != 0, "different paths -> different hash");
    ASSERT_NULL(sc_pm_workspace_hash(NULL));
    ASSERT_NULL(sc_pm_workspace_hash(""));
    free(a); free(b); free(c);
}

static void test_language_for(void)
{
    ASSERT_STR_EQ(sc_pm_language_for("src/x.c"), "c");
    ASSERT_STR_EQ(sc_pm_language_for("a/b/foo.py"), "python");
    ASSERT_STR_EQ(sc_pm_language_for("x.ts"), "typescript");
    ASSERT_NULL(sc_pm_language_for("README"));
    ASSERT_NULL(sc_pm_language_for("a.bin"));
    ASSERT_NULL(sc_pm_language_for(NULL));
}

static void test_tokenize(void)
{
    int n = 0;
    char **t = sc_pm_tokenize("Foo_bar BAZ ab foo_bar", &n);
    ASSERT_NOT_NULL(t);
    /* "ab" dropped (<3), "foo_bar" deduped (lowercased), so {foo_bar, baz}. */
    ASSERT_INT_EQ(n, 2);
    sc_pm_free_terms(t, n);

    int z = -1;
    ASSERT_NULL(sc_pm_tokenize("a b c", &z));  /* all < 3 chars */
    ASSERT_INT_EQ(z, 0);
}

static void test_match_score(void)
{
    const char *blob = "parser tokenize render widget";
    ASSERT_INT_EQ(sc_pm_match_score(blob, "tokenize"), 1);
    ASSERT_INT_EQ(sc_pm_match_score(blob, "parser render"), 2);
    ASSERT_INT_EQ(sc_pm_match_score(blob, "parser parser"), 1);   /* distinct */
    ASSERT_INT_EQ(sc_pm_match_score(blob, "missing"), 0);
    ASSERT_INT_EQ(sc_pm_match_score(NULL, "x"), 0);
    ASSERT_INT_EQ(sc_pm_match_score(blob, ""), 0);
}

static void test_build_and_search(void)
{
    char home[] = "/tmp/sc_pm_home_XXXXXX";
    char ws[]   = "/tmp/sc_pm_ws_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(home));
    ASSERT_NOT_NULL(mkdtemp(ws));
    setenv("SMOLCLAW_HOME", home, 1);

    /* A C source file with a recognizable symbol + term. */
    char src[512];
    snprintf(src, sizeof(src), "%s/widget.c", ws);
    FILE *f = fopen(src, "w");
    ASSERT_NOT_NULL(f);
    fprintf(f, "#include <stdio.h>\n"
               "int render_widget(int frobnicator) {\n"
               "    return frobnicator + 1;\n"
               "}\n");
    fclose(f);

    int n = sc_pm_build(ws, 0);
    ASSERT(n >= 1, "should index at least the one .c file");

    int count = 0;
    sc_pm_hit_t *hits = sc_pm_search(ws, "frobnicator", 10, &count);
    ASSERT_NOT_NULL(hits);
    ASSERT(count >= 1, "search should find the file");
    ASSERT(strstr(hits[0].path, "widget.c") != NULL, "hit is widget.c");
    sc_pm_hits_free(hits, count);

    /* Symbol match also works. */
    hits = sc_pm_search(ws, "render_widget", 10, &count);
    ASSERT_NOT_NULL(hits);
    ASSERT(count >= 1, "symbol search finds the file");
    sc_pm_hits_free(hits, count);

    /* No match. */
    hits = sc_pm_search(ws, "zzzznotpresent", 10, &count);
    ASSERT_NULL(hits);
    ASSERT_INT_EQ(count, 0);

    /* status reflects a built index. */
    char *st = sc_pm_status(ws);
    ASSERT(st && strstr(st, "file") != NULL, "status mentions files");
    free(st);

    /* cleanup */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "rm -rf %s %s", home, ws);
    if (system(cmd) != 0) { /* ignore */ }
}

int main(void)
{
    printf("test_project_memory:\n");
    RUN_TEST(test_workspace_hash);
    RUN_TEST(test_language_for);
    RUN_TEST(test_tokenize);
    RUN_TEST(test_match_score);
    RUN_TEST(test_build_and_search);
    TEST_REPORT();
}
