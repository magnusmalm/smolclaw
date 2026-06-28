/*
 * smolclaw - post-turn memory review tests (task 4.13).
 *
 * Covers the pure helpers (should-run gate + LLM-response parser). The async
 * worker / live LLM call is a human-gated acceptance (needs a provider).
 */

#include "test_main.h"
#include "memory_review.h"
#include "util/str.h"

#include <stdlib.h>
#include <string.h>

static void test_should_run(void)
{
    ASSERT_INT_EQ(sc_memory_review_should_run(1, 1), 1);  /* ok + enabled */
    ASSERT_INT_EQ(sc_memory_review_should_run(1, 0), 0);  /* disabled */
    ASSERT_INT_EQ(sc_memory_review_should_run(0, 1), 0);  /* turn failed */
    ASSERT_INT_EQ(sc_memory_review_should_run(0, 0), 0);
}

static void test_parse_basic(void)
{
    int n = -1;
    char **e = sc_memory_review_parse("[\"likes tea\",\"uses vim\"]", 2, &n);
    ASSERT_NOT_NULL(e);
    ASSERT_INT_EQ(n, 2);
    ASSERT_STR_EQ(e[0], "likes tea");
    ASSERT_STR_EQ(e[1], "uses vim");
    sc_memory_review_entries_free(e, n);
}

static void test_parse_caps_at_max(void)
{
    int n = -1;
    char **e = sc_memory_review_parse("[\"a\",\"b\",\"c\",\"d\"]", 2, &n);
    ASSERT_NOT_NULL(e);
    ASSERT_INT_EQ(n, 2);  /* only first max=2 kept */
    sc_memory_review_entries_free(e, n);
}

static void test_parse_strips_code_fence(void)
{
    int n = -1;
    char **e = sc_memory_review_parse("```json\n[\"fact\"]\n```", 2, &n);
    ASSERT_NOT_NULL(e);
    ASSERT_INT_EQ(n, 1);
    ASSERT_STR_EQ(e[0], "fact");
    sc_memory_review_entries_free(e, n);
}

static void test_parse_empty_array(void)
{
    int n = -1;
    char **e = sc_memory_review_parse("[]", 2, &n);
    ASSERT_NULL(e);
    ASSERT_INT_EQ(n, 0);
}

static void test_parse_skips_blank_entries(void)
{
    int n = -1;
    char **e = sc_memory_review_parse("[\"  \",\"real\",\"\"]", 2, &n);
    ASSERT_NOT_NULL(e);
    ASSERT_INT_EQ(n, 1);
    ASSERT_STR_EQ(e[0], "real");
    sc_memory_review_entries_free(e, n);
}

static void test_parse_rejects_non_array(void)
{
    int n = -1;
    ASSERT_NULL(sc_memory_review_parse("NONE", 2, &n));
    ASSERT_INT_EQ(n, 0);
    ASSERT_NULL(sc_memory_review_parse("{\"x\":1}", 2, &n));
    ASSERT_NULL(sc_memory_review_parse("not json at all", 2, &n));
    ASSERT_NULL(sc_memory_review_parse(NULL, 2, &n));
    ASSERT_NULL(sc_memory_review_parse("[\"x\"]", 0, &n));  /* max=0 */
}

int main(void)
{
    printf("test_memory_review:\n");
    RUN_TEST(test_should_run);
    RUN_TEST(test_parse_basic);
    RUN_TEST(test_parse_caps_at_max);
    RUN_TEST(test_parse_strips_code_fence);
    RUN_TEST(test_parse_empty_array);
    RUN_TEST(test_parse_skips_blank_entries);
    RUN_TEST(test_parse_rejects_non_array);
    TEST_REPORT();
}
