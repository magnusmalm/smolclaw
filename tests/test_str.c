/*
 * smolclaw - string utility tests
 */

#include "test_main.h"
#include "util/str.h"

static void test_sc_strdup(void)
{
    /* NULL input returns NULL */
    char *r = sc_strdup(NULL);
    ASSERT_NULL(r);

    /* Normal string */
    r = sc_strdup("hello");
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "hello");
    free(r);

    /* Empty string */
    r = sc_strdup("");
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "");
    free(r);
}

static void test_sc_truncate(void)
{
    /* NULL returns NULL */
    char *r = sc_truncate(NULL, 10);
    ASSERT_NULL(r);

    /* Short string not truncated */
    r = sc_truncate("hello", 10);
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "hello");
    free(r);

    /* Exact length */
    r = sc_truncate("hello", 5);
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "hello");
    free(r);

    /* Truncated */
    r = sc_truncate("hello world", 5);
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "hello...");
    free(r);

    /* Zero length */
    r = sc_truncate("hello", 0);
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "...");
    free(r);
}

static void test_sc_trim(void)
{
    /* NULL returns NULL */
    char *r = sc_trim(NULL);
    ASSERT_NULL(r);

    /* No whitespace */
    r = sc_trim("hello");
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "hello");
    free(r);

    /* Leading whitespace */
    r = sc_trim("  hello");
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "hello");
    free(r);

    /* Trailing whitespace */
    r = sc_trim("hello  ");
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "hello");
    free(r);

    /* Both sides */
    r = sc_trim("  hello world  ");
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "hello world");
    free(r);

    /* All whitespace */
    r = sc_trim("   ");
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "");
    free(r);

    /* Newlines and tabs */
    r = sc_trim("\n\thello\n\t");
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "hello");
    free(r);
}

static void test_sc_expand_home(void)
{
    /* NULL returns NULL */
    char *r = sc_expand_home(NULL);
    ASSERT_NULL(r);

    /* No tilde */
    r = sc_expand_home("/usr/local");
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "/usr/local");
    free(r);

    /* Tilde at start */
    r = sc_expand_home("~/Documents");
    ASSERT_NOT_NULL(r);
    ASSERT(r[0] == '/', "Should start with /");
    ASSERT(strstr(r, "Documents") != NULL, "Should contain Documents");
    free(r);
}

static void test_sc_strbuf(void)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    sc_strbuf_append(&sb, "hello");
    sc_strbuf_append(&sb, " ");
    sc_strbuf_append(&sb, "world");

    char *r = sc_strbuf_finish(&sb);
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "hello world");
    free(r);

    /* Appendf */
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "count: %d", 42);
    r = sc_strbuf_finish(&sb);
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "count: 42");
    free(r);

    /* Append char */
    sc_strbuf_init(&sb);
    sc_strbuf_append_char(&sb, 'A');
    sc_strbuf_append_char(&sb, 'B');
    sc_strbuf_append_char(&sb, 'C');
    r = sc_strbuf_finish(&sb);
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "ABC");
    free(r);

    /* Empty buffer */
    sc_strbuf_init(&sb);
    r = sc_strbuf_finish(&sb);
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "");
    free(r);
}

static void test_sc_sanitize_filename(void)
{
    /* NULL returns NULL */
    char *r = sc_sanitize_filename(NULL);
    ASSERT_NULL(r);

    /* No colons */
    r = sc_sanitize_filename("hello");
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "hello");
    free(r);

    /* Colons replaced with double underscores */
    r = sc_sanitize_filename("telegram:12345");
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "telegram__12345");
    free(r);

    /* Multiple colons */
    r = sc_sanitize_filename("a:b:c");
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "a__b__c");
    free(r);
}

static void test_strbuf_oom_flag(void)
{
    /* Simulate OOM by setting the flag directly */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    ASSERT_INT_EQ(sb.oom, 0);

    /* Normal append works */
    sc_strbuf_append(&sb, "hello");
    ASSERT_INT_EQ(sb.oom, 0);
    ASSERT(sb.len == 5, "len should be 5");

    /* Set OOM flag — subsequent appends should be no-ops */
    sb.oom = 1;
    sc_strbuf_append(&sb, " world");
    ASSERT(sb.len == 5, "len should still be 5 after OOM append");

    sc_strbuf_append_char(&sb, '!');
    ASSERT(sb.len == 5, "len should still be 5 after OOM append_char");

    sc_strbuf_appendf(&sb, "%d", 42);
    ASSERT(sb.len == 5, "len should still be 5 after OOM appendf");

    /* finish should return NULL when OOM */
    char *r = sc_strbuf_finish(&sb);
    ASSERT_NULL(r);
    ASSERT_INT_EQ(sb.oom, 0); /* reset after finish */

    /* After OOM finish, init and use normally */
    sc_strbuf_init(&sb);
    sc_strbuf_append(&sb, "ok");
    r = sc_strbuf_finish(&sb);
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r, "ok");
    free(r);
}

static void test_safe_realloc(void)
{
    /* Normal realloc should work */
    int *p = malloc(4 * sizeof(int));
    ASSERT_NOT_NULL(p);
    p[0] = 42;

    int *new_p = sc_safe_realloc(p, 8 * sizeof(int));
    ASSERT_NOT_NULL(new_p);
    ASSERT_INT_EQ(new_p[0], 42);
    free(new_p);

    /* NULL ptr acts like malloc */
    void *m = sc_safe_realloc(NULL, 16);
    ASSERT_NOT_NULL(m);
    free(m);
}

static void test_timing_safe_cmp(void)
{
    /* Equal strings */
    ASSERT_INT_EQ(sc_timing_safe_cmp("hello", "hello"), 0);
    ASSERT_INT_EQ(sc_timing_safe_cmp("", ""), 0);
    ASSERT_INT_EQ(sc_timing_safe_cmp("ABCD2345EFGH", "ABCD2345EFGH"), 0);

    /* Different strings */
    ASSERT(sc_timing_safe_cmp("hello", "world") != 0, "different strings should not match");
    ASSERT(sc_timing_safe_cmp("hello", "hellp") != 0, "last byte differs");
    ASSERT(sc_timing_safe_cmp("hello", "xello") != 0, "first byte differs");

    /* Different lengths */
    ASSERT(sc_timing_safe_cmp("hello", "hell") != 0, "different lengths");
    ASSERT(sc_timing_safe_cmp("hi", "hello") != 0, "different lengths reversed");
    ASSERT(sc_timing_safe_cmp("a", "") != 0, "empty vs non-empty");
}

int main(void)
{
    printf("test_str\n");

    RUN_TEST(test_sc_strdup);
    RUN_TEST(test_sc_truncate);
    RUN_TEST(test_sc_trim);
    RUN_TEST(test_sc_expand_home);
    RUN_TEST(test_sc_strbuf);
    RUN_TEST(test_sc_sanitize_filename);
    RUN_TEST(test_strbuf_oom_flag);
    RUN_TEST(test_safe_realloc);
    RUN_TEST(test_timing_safe_cmp);

    TEST_REPORT();
}
