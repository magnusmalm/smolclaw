/*
 * smolclaw — session-isolation Stage 5 tests.
 *
 * Covers the web channel's pattern-driven isolation decision via the
 * sc_web_compute_isolation helper. The HTTP-level integration is exercised
 * by the live acceptance test (Stage 8); this file proves the decision
 * function maps inputs to outputs correctly for the cases the live test
 * cannot enumerate cheaply.
 */

#include "test_main.h"

#include "channels/web.h"

#include <string.h>

static void test_default_pattern_matches_wf_prefix(void)
{
    char ns[17];
    int rc = sc_web_compute_isolation("wf-*",
                                       "wf-researcher-abc",
                                       "web:tokenhash:wf-researcher-abc",
                                       ns);
    ASSERT_INT_EQ(rc, 1);
    ASSERT_INT_EQ((int)strlen(ns), 16);
    /* Should be hex */
    for (int i = 0; i < 16; i++) {
        char c = ns[i];
        ASSERT((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
               "namespace_id is lowercase hex");
    }
}

static void test_default_pattern_rejects_non_wf(void)
{
    char ns[17];
    ASSERT_INT_EQ(sc_web_compute_isolation("wf-*", "chat-1", "k", ns), 0);
    ASSERT_STR_EQ(ns, "");
    ASSERT_INT_EQ(sc_web_compute_isolation("wf-*", "abc", "k", ns), 0);
    ASSERT_STR_EQ(ns, "");
    ASSERT_INT_EQ(sc_web_compute_isolation("wf-*", "x-wf-x", "k", ns), 0);
    ASSERT_STR_EQ(ns, "");
}

static void test_empty_or_null_pattern_disables(void)
{
    char ns[17];
    ASSERT_INT_EQ(sc_web_compute_isolation("",   "wf-foo", "k", ns), 0);
    ASSERT_STR_EQ(ns, "");
    ASSERT_INT_EQ(sc_web_compute_isolation(NULL, "wf-foo", "k", ns), 0);
    ASSERT_STR_EQ(ns, "");
}

static void test_null_session_inputs_safe(void)
{
    char ns[17];
    ASSERT_INT_EQ(sc_web_compute_isolation("wf-*", NULL, "k", ns), 0);
    ASSERT_INT_EQ(sc_web_compute_isolation("wf-*", "wf-x", NULL, ns), 0);
    ASSERT_INT_EQ(sc_web_compute_isolation("wf-*", "wf-x", "k", NULL), 0);
}

static void test_custom_pattern(void)
{
    char ns[17];
    ASSERT_INT_EQ(sc_web_compute_isolation("task-*", "task-foo", "k", ns), 1);
    ASSERT_INT_EQ(sc_web_compute_isolation("task-*", "wf-foo",   "k", ns), 0);
    ASSERT_INT_EQ(sc_web_compute_isolation("*-iso",  "smoke-iso","k", ns), 1);
    ASSERT_INT_EQ(sc_web_compute_isolation("*-iso",  "noniso",   "k", ns), 0);
}

static void test_same_session_key_yields_same_ns(void)
{
    /* Stability is critical: turn 2 of the same session must hit the same
     * per-session memory bucket as turn 1, so the agent has continuity. */
    char ns1[17], ns2[17];
    int r1 = sc_web_compute_isolation("wf-*", "wf-stable",
                                       "web:abc:wf-stable", ns1);
    int r2 = sc_web_compute_isolation("wf-*", "wf-stable",
                                       "web:abc:wf-stable", ns2);
    ASSERT_INT_EQ(r1, 1);
    ASSERT_INT_EQ(r2, 1);
    ASSERT_STR_EQ(ns1, ns2);
}

static void test_different_session_keys_yield_different_ns(void)
{
    char ns_a[17], ns_b[17];
    sc_web_compute_isolation("wf-*", "wf-a", "web:t:wf-a", ns_a);
    sc_web_compute_isolation("wf-*", "wf-b", "web:t:wf-b", ns_b);
    ASSERT(strcmp(ns_a, ns_b) != 0,
           "distinct session_keys produce distinct namespace_ids");
}

static void test_ns_id_buffer_terminated(void)
{
    /* Confirm the helper writes exactly 16 hex + NUL. */
    char ns[17] = {'X'};
    /* Pre-fill ns with 'X' to detect under-write. */
    memset(ns, 'X', sizeof(ns) - 1);
    ns[sizeof(ns) - 1] = '\0';

    int rc = sc_web_compute_isolation("wf-*", "wf-x", "k", ns);
    ASSERT_INT_EQ(rc, 1);
    ASSERT_INT_EQ((int)strlen(ns), 16);
    ASSERT_INT_EQ(ns[16], '\0');
}

int main(void)
{
    printf("test_web_isolation:\n");
    RUN_TEST(test_default_pattern_matches_wf_prefix);
    RUN_TEST(test_default_pattern_rejects_non_wf);
    RUN_TEST(test_empty_or_null_pattern_disables);
    RUN_TEST(test_null_session_inputs_safe);
    RUN_TEST(test_custom_pattern);
    RUN_TEST(test_same_session_key_yields_same_ns);
    RUN_TEST(test_different_session_keys_yield_different_ns);
    RUN_TEST(test_ns_id_buffer_terminated);
    TEST_REPORT();
}
