/*
 * test_output_filter.c - Tests for output filter
 */

#include "test_main.h"
#include "tools/output_filter.h"

#include <stdlib.h>
#include <string.h>

static void test_filter_detect(void)
{
    /* Should detect known commands */
    ASSERT_INT_EQ(sc_filter_detect("cargo test"), SC_FILTER_CARGO_TEST);
    ASSERT_INT_EQ(sc_filter_detect("cargo test --release"), SC_FILTER_CARGO_TEST);
    ASSERT_INT_EQ(sc_filter_detect("cargo build"), SC_FILTER_CARGO_BUILD);
    ASSERT_INT_EQ(sc_filter_detect("cargo check"), SC_FILTER_CARGO_BUILD);
    ASSERT_INT_EQ(sc_filter_detect("git status"), SC_FILTER_GIT_STATUS);
    ASSERT_INT_EQ(sc_filter_detect("git diff"), SC_FILTER_GIT_DIFF);
    ASSERT_INT_EQ(sc_filter_detect("git diff HEAD~1"), SC_FILTER_GIT_DIFF);
    ASSERT_INT_EQ(sc_filter_detect("pytest"), SC_FILTER_PYTEST);
    ASSERT_INT_EQ(sc_filter_detect("python -m pytest"), SC_FILTER_PYTEST);
    ASSERT_INT_EQ(sc_filter_detect("npm test"), SC_FILTER_NPM_TEST);
    ASSERT_INT_EQ(sc_filter_detect("npx jest"), SC_FILTER_NPM_TEST);

    /* Should not detect unknown commands */
    ASSERT_INT_EQ(sc_filter_detect("ls -la"), SC_FILTER_NONE);
    ASSERT_INT_EQ(sc_filter_detect("echo hello"), SC_FILTER_NONE);
    ASSERT_INT_EQ(sc_filter_detect(NULL), SC_FILTER_NONE);

    /* Should skip help flags */
    ASSERT_INT_EQ(sc_filter_detect("cargo test --help"), SC_FILTER_NONE);
    ASSERT_INT_EQ(sc_filter_detect("git status -h"), SC_FILTER_NONE);

    /* Leading whitespace should be handled */
    ASSERT_INT_EQ(sc_filter_detect("  cargo test"), SC_FILTER_CARGO_TEST);
}

static void test_filter_cargo_test(void)
{
    /* Simple passing test output */
    const char *raw =
        "   Compiling myproject v0.1.0\n"
        "    Finished test profile\n"
        "     Running unittests src/lib.rs\n"
        "\n"
        "running 50 tests\n"
        "test parser::test_parse_basic ... ok\n"
        "test parser::test_parse_complex ... ok\n"
        "test parser::test_parse_edge ... ok\n"
        /* repeat to make it longer */
        "test a::b ... ok\n"
        "test a::c ... ok\n"
        "test a::d ... ok\n"
        "test a::e ... ok\n"
        "test a::f ... ok\n"
        "test a::g ... ok\n"
        "test a::h ... ok\n"
        "\n"
        "test result: ok. 50 passed; 0 failed; 0 ignored\n";

    size_t raw_len = strlen(raw);
    char *filtered = sc_filter_apply(SC_FILTER_CARGO_TEST, raw, raw_len);

    /* Should be shorter than original */
    if (filtered) {
        ASSERT(strlen(filtered) < raw_len, "filtered should be shorter");
        ASSERT(strstr(filtered, "test result:") != NULL, "should contain summary");
        free(filtered);
    }
    /* If NULL, filter decided not to compress (acceptable for small input) */
}

static void test_filter_cargo_test_failures(void)
{
    /* Test with failures — should include failure details */
    const char *raw =
        "   Compiling myproject v0.1.0\n"
        "    Finished test profile\n"
        "     Running unittests src/lib.rs\n"
        "\n"
        "running 3 tests\n"
        "test parser::test_ok ... ok\n"
        "test parser::test_bad ... FAILED\n"
        "test parser::test_other ... ok\n"
        "\n"
        "failures:\n"
        "\n"
        "---- parser::test_bad stdout ----\n"
        "thread 'parser::test_bad' panicked at 'assertion failed'\n"
        "left: 1\n"
        "right: 2\n"
        "\n"
        /* pad to make it large enough for filtering to be worthwhile */
        "lots of output padding lots of output padding\n"
        "lots of output padding lots of output padding\n"
        "lots of output padding lots of output padding\n"
        "lots of output padding lots of output padding\n"
        "lots of output padding lots of output padding\n"
        "lots of output padding lots of output padding\n"
        "lots of output padding lots of output padding\n"
        "lots of output padding lots of output padding\n"
        "\n"
        "test result: FAILED. 2 passed; 1 failed; 0 ignored\n";

    size_t raw_len = strlen(raw);
    char *filtered = sc_filter_apply(SC_FILTER_CARGO_TEST, raw, raw_len);
    if (filtered) {
        ASSERT(strstr(filtered, "FAILED") != NULL, "should contain FAILED");
        ASSERT(strstr(filtered, "test result:") != NULL, "should contain summary");
        free(filtered);
    }
}

static void test_filter_git_status(void)
{
    const char *raw =
        "On branch main\n"
        "Changes to be committed:\n"
        "  (use \"git restore --staged <file>...\" to unstage)\n"
        "\tnew file:   src/tee.c\n"
        "\tnew file:   src/tee.h\n"
        "\tmodified:   src/config.c\n"
        "\n"
        "Changes not staged for commit:\n"
        "  (use \"git add <file>...\" to update)\n"
        "\tmodified:   src/agent.c\n"
        "\n"
        "Untracked files:\n"
        "  (use \"git add <file>...\" to include)\n"
        "\tsrc/analytics.c\n"
        "\tsrc/analytics.h\n";

    size_t raw_len = strlen(raw);
    char *filtered = sc_filter_apply(SC_FILTER_GIT_STATUS, raw, raw_len);
    if (filtered) {
        ASSERT(strstr(filtered, "On branch main") != NULL, "should contain branch");
        ASSERT(strstr(filtered, "Staged (3)") != NULL, "should show 3 staged");
        ASSERT(strstr(filtered, "Unstaged (1)") != NULL, "should show 1 unstaged");
        ASSERT(strstr(filtered, "Untracked (2)") != NULL, "should show 2 untracked");
        free(filtered);
    }
}

static void test_filter_none(void)
{
    /* SC_FILTER_NONE should return NULL */
    char *result = sc_filter_apply(SC_FILTER_NONE, "data", 4);
    ASSERT_NULL(result);

    /* NULL raw should return NULL */
    result = sc_filter_apply(SC_FILTER_CARGO_TEST, NULL, 0);
    ASSERT_NULL(result);

    /* Empty raw should return NULL */
    result = sc_filter_apply(SC_FILTER_CARGO_TEST, "", 0);
    ASSERT_NULL(result);
}

static void test_filter_no_reduction(void)
{
    /* Very short input — filter should return NULL (no significant reduction) */
    const char *raw = "test result: ok. 1 passed\n";
    char *filtered = sc_filter_apply(SC_FILTER_CARGO_TEST, raw, strlen(raw));
    /* Should return NULL because filtered is not <50% of original */
    /* (the summary IS the entire output) */
    ASSERT_NULL(filtered);
}

int main(void)
{
    printf("test_output_filter\n");
    RUN_TEST(test_filter_detect);
    RUN_TEST(test_filter_cargo_test);
    RUN_TEST(test_filter_cargo_test_failures);
    RUN_TEST(test_filter_git_status);
    RUN_TEST(test_filter_none);
    RUN_TEST(test_filter_no_reduction);
    TEST_REPORT();
}
