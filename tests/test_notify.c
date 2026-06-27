/*
 * smolclaw — notify URL parser tests (task 3.5).
 *
 * Locks the Apprise-compatible scheme truth table for the notify tool's pure
 * parse_one_url() (tools/notify_internal.h). No HTTP is sent — this only
 * exercises classification + param extraction, which is where the Slack and
 * ntfy schemes added in 3.5 (and the pre-existing discord/tg/json schemes)
 * can silently regress. The curl send path is covered by manual smoke only.
 */

#include "test_main.h"

#include "tools/notify_internal.h"

#include <string.h>

/* ---- existing schemes (retro-coverage) ------------------------------ */

static void test_discord_parses(void)
{
    parsed_url_t u;
    ASSERT_INT_EQ(parse_one_url("discord://123456/abcdef", &u), 0);
    ASSERT_INT_EQ(u.scheme, SCHEME_DISCORD);
    ASSERT_STR_EQ(u.param1, "123456");
    ASSERT_STR_EQ(u.param2, "abcdef");
    parsed_url_free(&u);
}

static void test_telegram_parses(void)
{
    parsed_url_t u;
    ASSERT_INT_EQ(parse_one_url("tg://bottoken/chat42", &u), 0);
    ASSERT_INT_EQ(u.scheme, SCHEME_TELEGRAM);
    ASSERT_STR_EQ(u.param1, "bottoken");
    ASSERT_STR_EQ(u.param2, "chat42");
    parsed_url_free(&u);
}

static void test_json_parses(void)
{
    parsed_url_t u;
    ASSERT_INT_EQ(parse_one_url("json://https://example.com/hook", &u), 0);
    ASSERT_INT_EQ(u.scheme, SCHEME_JSON);
    ASSERT_STR_EQ(u.param1, "https://example.com/hook");
    parsed_url_free(&u);
}

/* ---- Slack (3.5) ----------------------------------------------------- */

static void test_slack_parses_full_path(void)
{
    parsed_url_t u;
    ASSERT_INT_EQ(parse_one_url("slack://T00000000/B00000000/XXXXXXXXXXXX", &u), 0);
    ASSERT_INT_EQ(u.scheme, SCHEME_SLACK);
    /* Whole remainder is kept verbatim — appended to the services/ base. */
    ASSERT_STR_EQ(u.param1, "T00000000/B00000000/XXXXXXXXXXXX");
    parsed_url_free(&u);
}

static void test_slack_rejects_empty_path(void)
{
    parsed_url_t u;
    ASSERT_INT_EQ(parse_one_url("slack://", &u), -1);
}

/* ---- ntfy (3.5) ------------------------------------------------------ */

static void test_ntfy_topic_only_defaults_host(void)
{
    parsed_url_t u;
    ASSERT_INT_EQ(parse_one_url("ntfy://alerts", &u), 0);
    ASSERT_INT_EQ(u.scheme, SCHEME_NTFY);
    ASSERT_STR_EQ(u.param1, "ntfy.sh");
    ASSERT_STR_EQ(u.param2, "alerts");
    parsed_url_free(&u);
}

static void test_ntfy_self_hosted_host_and_topic(void)
{
    parsed_url_t u;
    ASSERT_INT_EQ(parse_one_url("ntfy://ntfy.example.com/alerts", &u), 0);
    ASSERT_INT_EQ(u.scheme, SCHEME_NTFY);
    ASSERT_STR_EQ(u.param1, "ntfy.example.com");
    ASSERT_STR_EQ(u.param2, "alerts");
    parsed_url_free(&u);
}

static void test_ntfy_rejects_empty_and_missing_topic(void)
{
    parsed_url_t u;
    ASSERT_INT_EQ(parse_one_url("ntfy://", &u), -1);
    /* host present, topic empty */
    ASSERT_INT_EQ(parse_one_url("ntfy://host/", &u), -1);
    /* leading slash -> empty host */
    ASSERT_INT_EQ(parse_one_url("ntfy:///topic", &u), -1);
}

/* ---- unknown scheme -------------------------------------------------- */

static void test_unknown_scheme_rejected(void)
{
    parsed_url_t u;
    ASSERT_INT_EQ(parse_one_url("smtp://user@host", &u), -1);
    ASSERT_INT_EQ(parse_one_url("not a url", &u), -1);
}

int main(void)
{
    printf("test_notify:\n");
    RUN_TEST(test_discord_parses);
    RUN_TEST(test_telegram_parses);
    RUN_TEST(test_json_parses);
    RUN_TEST(test_slack_parses_full_path);
    RUN_TEST(test_slack_rejects_empty_path);
    RUN_TEST(test_ntfy_topic_only_defaults_host);
    RUN_TEST(test_ntfy_self_hosted_host_and_topic);
    RUN_TEST(test_ntfy_rejects_empty_and_missing_topic);
    RUN_TEST(test_unknown_scheme_rejected);
    TEST_REPORT();
}
