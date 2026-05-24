#include "test_main.h"

#include "util/glob.h"

static void test_exact_match(void)
{
    ASSERT_INT_EQ(sc_glob_match("foo", "foo"), 1);
    ASSERT_INT_EQ(sc_glob_match("foo", "bar"), 0);
    ASSERT_INT_EQ(sc_glob_match("foo", "fo"),  0);
    ASSERT_INT_EQ(sc_glob_match("foo", "fooo"), 0);
}

static void test_empty(void)
{
    ASSERT_INT_EQ(sc_glob_match("",  ""),    1);
    ASSERT_INT_EQ(sc_glob_match("",  "foo"), 0);
    ASSERT_INT_EQ(sc_glob_match("*", ""),    1);
    ASSERT_INT_EQ(sc_glob_match("*", "anything-at-all"), 1);
}

static void test_null_inputs(void)
{
    ASSERT_INT_EQ(sc_glob_match(NULL, "foo"), 0);
    ASSERT_INT_EQ(sc_glob_match("foo", NULL), 0);
    ASSERT_INT_EQ(sc_glob_match(NULL, NULL),  0);
}

static void test_star_prefix(void)
{
    ASSERT_INT_EQ(sc_glob_match("wf-*", "wf-researcher-x"), 1);
    ASSERT_INT_EQ(sc_glob_match("wf-*", "wf-"),              1);
    ASSERT_INT_EQ(sc_glob_match("wf-*", "wf"),               0);
    ASSERT_INT_EQ(sc_glob_match("wf-*", "chat-1"),           0);
    ASSERT_INT_EQ(sc_glob_match("wf-*", "x-wf-researcher"),  0);
}

static void test_star_suffix(void)
{
    ASSERT_INT_EQ(sc_glob_match("*-foo", "bar-foo"),  1);
    ASSERT_INT_EQ(sc_glob_match("*-foo", "-foo"),     1);
    ASSERT_INT_EQ(sc_glob_match("*-foo", "foo"),      0);
    ASSERT_INT_EQ(sc_glob_match("*-foo", "bar-foo-x"), 0);
}

static void test_star_middle(void)
{
    ASSERT_INT_EQ(sc_glob_match("a*z", "az"),    1);
    ASSERT_INT_EQ(sc_glob_match("a*z", "abcz"),  1);
    ASSERT_INT_EQ(sc_glob_match("a*z", "abc"),   0);
    ASSERT_INT_EQ(sc_glob_match("a*z", "bcz"),   0);
}

static void test_multiple_stars(void)
{
    ASSERT_INT_EQ(sc_glob_match("a*b*c", "abc"),       1);
    ASSERT_INT_EQ(sc_glob_match("a*b*c", "axbxc"),     1);
    ASSERT_INT_EQ(sc_glob_match("a*b*c", "abxc"),      1);
    ASSERT_INT_EQ(sc_glob_match("a*b*c", "ac"),        0);
    ASSERT_INT_EQ(sc_glob_match("**foo", "foo"),       1);
    ASSERT_INT_EQ(sc_glob_match("**foo", "barfoo"),    1);
}

static void test_question_mark(void)
{
    ASSERT_INT_EQ(sc_glob_match("f?o",  "foo"),  1);
    ASSERT_INT_EQ(sc_glob_match("f?o",  "fxo"),  1);
    ASSERT_INT_EQ(sc_glob_match("f?o",  "fo"),   0);
    ASSERT_INT_EQ(sc_glob_match("f?o",  "fooo"), 0);
    ASSERT_INT_EQ(sc_glob_match("???",  "abc"),  1);
    ASSERT_INT_EQ(sc_glob_match("???",  "ab"),   0);
}

static void test_mixed(void)
{
    ASSERT_INT_EQ(sc_glob_match("wf-?-*", "wf-a-foo"),    1);
    ASSERT_INT_EQ(sc_glob_match("wf-?-*", "wf-ab-foo"),   0);
    ASSERT_INT_EQ(sc_glob_match("wf-?-*", "wf-a-"),       1);
    ASSERT_INT_EQ(sc_glob_match("*?*",    "x"),           1);
    ASSERT_INT_EQ(sc_glob_match("*?*",    ""),            0);
}

static void test_backtracking(void)
{
    /* Greedy '*' must backtrack so the literal tail can match. */
    ASSERT_INT_EQ(sc_glob_match("*a*b", "aaab"),    1);
    ASSERT_INT_EQ(sc_glob_match("*aab", "xxaaab"),  1);
    ASSERT_INT_EQ(sc_glob_match("*ab",  "ababab"),  1);
    ASSERT_INT_EQ(sc_glob_match("a*a*a", "aaaaaa"), 1);
    ASSERT_INT_EQ(sc_glob_match("a*a*a", "aa"),     0);
}

int main(void)
{
    printf("test_glob:\n");
    RUN_TEST(test_exact_match);
    RUN_TEST(test_empty);
    RUN_TEST(test_null_inputs);
    RUN_TEST(test_star_prefix);
    RUN_TEST(test_star_suffix);
    RUN_TEST(test_star_middle);
    RUN_TEST(test_multiple_stars);
    RUN_TEST(test_question_mark);
    RUN_TEST(test_mixed);
    RUN_TEST(test_backtracking);
    TEST_REPORT();
}
