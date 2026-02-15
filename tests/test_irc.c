/*
 * smolclaw - IRC channel unit tests
 * Tests message parsing, highlight detection, and message splitting.
 */

#include "test_main.h"
#include "channels/irc.h"

static void test_parse_privmsg(void)
{
    char prefix[256], command[32], params[512];

    /* Standard PRIVMSG to channel */
    int ret = sc_irc_parse_message(
        ":nick!user@host PRIVMSG #channel :hello world",
        prefix, sizeof(prefix), command, sizeof(command),
        params, sizeof(params));
    ASSERT_INT_EQ(ret, 0);
    ASSERT_STR_EQ(prefix, "nick!user@host");
    ASSERT_STR_EQ(command, "PRIVMSG");
    ASSERT_STR_EQ(params, "#channel hello world");

    /* DM (target is bot nick) */
    ret = sc_irc_parse_message(
        ":sender!user@host PRIVMSG botnick :hi there",
        prefix, sizeof(prefix), command, sizeof(command),
        params, sizeof(params));
    ASSERT_INT_EQ(ret, 0);
    ASSERT_STR_EQ(prefix, "sender!user@host");
    ASSERT_STR_EQ(command, "PRIVMSG");
    ASSERT_STR_EQ(params, "botnick hi there");
}

static void test_parse_ping(void)
{
    char prefix[256], command[32], params[512];

    int ret = sc_irc_parse_message(
        "PING :server.example.com",
        prefix, sizeof(prefix), command, sizeof(command),
        params, sizeof(params));
    ASSERT_INT_EQ(ret, 0);
    ASSERT_STR_EQ(prefix, "");
    ASSERT_STR_EQ(command, "PING");
    ASSERT_STR_EQ(params, "server.example.com");
}

static void test_parse_numeric(void)
{
    char prefix[256], command[32], params[512];

    /* RPL_WELCOME */
    int ret = sc_irc_parse_message(
        ":irc.server.com 001 botnick :Welcome to IRC",
        prefix, sizeof(prefix), command, sizeof(command),
        params, sizeof(params));
    ASSERT_INT_EQ(ret, 0);
    ASSERT_STR_EQ(prefix, "irc.server.com");
    ASSERT_STR_EQ(command, "001");
    ASSERT_STR_EQ(params, "botnick Welcome to IRC");
}

static void test_parse_with_crlf(void)
{
    char prefix[256], command[32], params[512];

    /* Line with \r\n */
    int ret = sc_irc_parse_message(
        ":nick!user@host PRIVMSG #test :hello\r\n",
        prefix, sizeof(prefix), command, sizeof(command),
        params, sizeof(params));
    ASSERT_INT_EQ(ret, 0);
    ASSERT_STR_EQ(command, "PRIVMSG");
    ASSERT_STR_EQ(params, "#test hello");
}

static void test_highlight_colon(void)
{
    const char *result = sc_irc_check_highlight("botnick: do something", "botnick");
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "do something");
}

static void test_highlight_comma(void)
{
    const char *result = sc_irc_check_highlight("botnick, do something", "botnick");
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "do something");
}

static void test_highlight_no_match(void)
{
    const char *result = sc_irc_check_highlight("hello everyone", "botnick");
    ASSERT_NULL(result);
}

static void test_highlight_case_insensitive(void)
{
    const char *result = sc_irc_check_highlight("BotNick: test", "botnick");
    ASSERT_NOT_NULL(result);
    ASSERT_STR_EQ(result, "test");
}

static void test_highlight_no_separator(void)
{
    /* "botnickfoo" should not match "botnick" */
    const char *result = sc_irc_check_highlight("botnickfoo bar", "botnick");
    ASSERT_NULL(result);
}

static void test_mention_at_nick(void)
{
    ASSERT_INT_EQ(sc_irc_check_mention("@botnick do something", "botnick"), 1);
}

static void test_mention_mid_sentence(void)
{
    ASSERT_INT_EQ(sc_irc_check_mention("hey botnick what's up", "botnick"), 1);
}

static void test_mention_at_nick_punctuation(void)
{
    ASSERT_INT_EQ(sc_irc_check_mention("hey @botnick, thoughts?", "botnick"), 1);
}

static void test_mention_no_word_boundary_prefix(void)
{
    /* "botnickname" should not match "botnick" */
    ASSERT_INT_EQ(sc_irc_check_mention("botnickname blah", "botnick"), 0);
}

static void test_mention_no_word_boundary_suffix(void)
{
    /* "xbotnick" should not match "botnick" */
    ASSERT_INT_EQ(sc_irc_check_mention("some botnicking", "botnick"), 0);
}

static void test_mention_case_insensitive(void)
{
    ASSERT_INT_EQ(sc_irc_check_mention("hey BOTNICK", "botnick"), 1);
}

static void test_mention_end_of_string(void)
{
    ASSERT_INT_EQ(sc_irc_check_mention("thanks botnick", "botnick"), 1);
}

static void test_mention_alone(void)
{
    ASSERT_INT_EQ(sc_irc_check_mention("botnick", "botnick"), 1);
}

static void test_split_short(void)
{
    int count = 0;
    char **chunks = sc_irc_split_message("hello", 400, &count);
    ASSERT_NOT_NULL(chunks);
    ASSERT_INT_EQ(count, 1);
    ASSERT_STR_EQ(chunks[0], "hello");
    free(chunks[0]);
    free(chunks);
}

static void test_split_long(void)
{
    /* Build a string longer than 400 chars */
    char longmsg[900];
    memset(longmsg, 'A', 800);
    longmsg[800] = '\0';

    int count = 0;
    char **chunks = sc_irc_split_message(longmsg, 400, &count);
    ASSERT_NOT_NULL(chunks);
    ASSERT_INT_EQ(count, 2);
    ASSERT(strlen(chunks[0]) == 400, "first chunk is 400 chars");
    ASSERT(strlen(chunks[1]) == 400, "second chunk is 400 chars");

    for (int i = 0; i < count; i++) free(chunks[i]);
    free(chunks);
}

static void test_split_exact(void)
{
    /* String of exactly max_len should produce 1 chunk */
    char exact[11];
    memset(exact, 'B', 10);
    exact[10] = '\0';

    int count = 0;
    char **chunks = sc_irc_split_message(exact, 10, &count);
    ASSERT_NOT_NULL(chunks);
    ASSERT_INT_EQ(count, 1);
    ASSERT_STR_EQ(chunks[0], "BBBBBBBBBB");
    free(chunks[0]);
    free(chunks);
}

int main(void)
{
    printf("test_irc\n");
    RUN_TEST(test_parse_privmsg);
    RUN_TEST(test_parse_ping);
    RUN_TEST(test_parse_numeric);
    RUN_TEST(test_parse_with_crlf);
    RUN_TEST(test_highlight_colon);
    RUN_TEST(test_highlight_comma);
    RUN_TEST(test_highlight_no_match);
    RUN_TEST(test_highlight_case_insensitive);
    RUN_TEST(test_highlight_no_separator);
    RUN_TEST(test_mention_at_nick);
    RUN_TEST(test_mention_mid_sentence);
    RUN_TEST(test_mention_at_nick_punctuation);
    RUN_TEST(test_mention_no_word_boundary_prefix);
    RUN_TEST(test_mention_no_word_boundary_suffix);
    RUN_TEST(test_mention_case_insensitive);
    RUN_TEST(test_mention_end_of_string);
    RUN_TEST(test_mention_alone);
    RUN_TEST(test_split_short);
    RUN_TEST(test_split_long);
    RUN_TEST(test_split_exact);
    TEST_REPORT();
}
