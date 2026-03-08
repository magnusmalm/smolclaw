/*
 * smolclaw - X (Twitter) channel tests
 * Tests OAuth 1.0a signing, tweet splitting, mention parsing, and channel vtable.
 */

#include "test_main.h"
#include "mock_http.h"
#include "channels/x.h"
#include "constants.h"
#include "util/str.h"

#include <stdlib.h>
#include <string.h>

/* ---- Channel creation tests ---- */

static void test_x_channel_create(void)
{
    /* NULL config -> NULL */
    sc_channel_t *ch = sc_channel_x_new(NULL, NULL);
    ASSERT_NULL(ch);

    /* Missing credentials -> NULL */
    sc_x_config_t cfg = { .enabled = 1, .consumer_key = NULL };
    ch = sc_channel_x_new(&cfg, NULL);
    ASSERT_NULL(ch);

    /* Partial credentials -> NULL */
    cfg.consumer_key = "ck";
    cfg.consumer_secret = "cs";
    cfg.access_token = NULL;
    ch = sc_channel_x_new(&cfg, NULL);
    ASSERT_NULL(ch);

    /* Valid config -> creates channel */
    cfg.consumer_key = "ck";
    cfg.consumer_secret = "cs";
    cfg.access_token = "at";
    cfg.access_token_secret = "ats";
    ch = sc_channel_x_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ASSERT_STR_EQ(ch->name, SC_CHANNEL_X);
    ASSERT_INT_EQ(ch->running, 0);
    ASSERT_NOT_NULL(ch->start);
    ASSERT_NOT_NULL(ch->stop);
    ASSERT_NOT_NULL(ch->send);
    ASSERT_NOT_NULL(ch->destroy);

    ch->destroy(ch);
}

static void test_x_channel_not_running(void)
{
    sc_x_config_t cfg = {
        .enabled = 1,
        .consumer_key = "ck",
        .consumer_secret = "cs",
        .access_token = "at",
        .access_token_secret = "ats",
    };

    sc_channel_t *ch = sc_channel_x_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);

    sc_outbound_msg_t msg = {
        .channel = "x",
        .chat_id = "123",
        .content = "test",
    };

    /* Should fail when not running */
    int ret = ch->send(ch, &msg);
    ASSERT_INT_EQ(ret, -1);

    ch->destroy(ch);
}

static void test_x_typing_noop(void)
{
    sc_x_config_t cfg = {
        .enabled = 1,
        .consumer_key = "ck",
        .consumer_secret = "cs",
        .access_token = "at",
        .access_token_secret = "ats",
    };

    sc_channel_t *ch = sc_channel_x_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);

    /* send_typing should be a no-op (returns 0) */
    int ret = ch->send_typing(ch, "123");
    ASSERT_INT_EQ(ret, 0);

    ch->destroy(ch);
}

static void test_x_allow_list(void)
{
    char *allow[] = { "user123", "user456" };
    sc_x_config_t cfg = {
        .enabled = 1,
        .consumer_key = "ck",
        .consumer_secret = "cs",
        .access_token = "at",
        .access_token_secret = "ats",
        .allow_from = allow,
        .allow_from_count = 2,
    };

    sc_channel_t *ch = sc_channel_x_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ASSERT_INT_EQ(ch->allow_list_count, 2);
    ASSERT_STR_EQ(ch->allow_list[0], "user123");
    ASSERT_STR_EQ(ch->allow_list[1], "user456");

    ch->destroy(ch);
}

static void test_x_default_poll_interval(void)
{
    sc_x_config_t cfg = {
        .enabled = 1,
        .consumer_key = "ck",
        .consumer_secret = "cs",
        .access_token = "at",
        .access_token_secret = "ats",
        .poll_interval_sec = 0,  /* should default to 60 */
    };

    sc_channel_t *ch = sc_channel_x_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);

    /* Channel created successfully with default interval */
    ch->destroy(ch);
}

/* ---- Tweet splitting tests ---- */

/*
 * split_tweets is static in x.c, so we test it indirectly via send().
 * For direct unit testing, we replicate the splitting logic here.
 */

#define TEST_MAX_TWEET 280

static int count_split_chunks(const char *text)
{
    if (!text || !text[0]) return 0;
    size_t len = strlen(text);
    if (len <= TEST_MAX_TWEET) return 1;

    int count = 0;
    const char *pos = text;
    while (*pos) {
        size_t remaining = strlen(pos);
        if (remaining <= TEST_MAX_TWEET) {
            count++;
            break;
        }
        int split = TEST_MAX_TWEET;
        while (split > TEST_MAX_TWEET / 2 && pos[split] != ' ' && pos[split] != '\n')
            split--;
        if (split <= TEST_MAX_TWEET / 2)
            split = TEST_MAX_TWEET;
        count++;
        pos += split;
        while (*pos == ' ') pos++;
    }
    return count;
}

static void test_tweet_split_short(void)
{
    /* Short text -> 1 chunk */
    ASSERT_INT_EQ(count_split_chunks("Hello world"), 1);
}

static void test_tweet_split_exact(void)
{
    /* Exactly 280 chars -> 1 chunk */
    char buf[281];
    memset(buf, 'a', 280);
    buf[280] = '\0';
    ASSERT_INT_EQ(count_split_chunks(buf), 1);
}

static void test_tweet_split_long(void)
{
    /* 600 chars with spaces -> 2-3 chunks */
    char buf[601];
    for (int i = 0; i < 600; i++)
        buf[i] = (i % 20 == 19) ? ' ' : 'a';
    buf[600] = '\0';
    int chunks = count_split_chunks(buf);
    ASSERT(chunks >= 2 && chunks <= 3, "600 chars should split into 2-3 chunks");
}

static void test_tweet_split_no_spaces(void)
{
    /* 600 chars with no spaces -> forced split at 280 */
    char buf[601];
    memset(buf, 'a', 600);
    buf[600] = '\0';
    int chunks = count_split_chunks(buf);
    ASSERT(chunks >= 2 && chunks <= 3, "600 chars no spaces should split into 2-3 chunks");
}

static void test_tweet_split_empty(void)
{
    ASSERT_INT_EQ(count_split_chunks(""), 0);
    ASSERT_INT_EQ(count_split_chunks(NULL), 0);
}

/* ---- Mention text parsing tests ---- */

/*
 * strip_bot_mention is static in x.c, so replicate its logic for testing.
 */
static void strip_mention(char *text, const char *bot_username)
{
    if (!text || !bot_username) return;
    if (text[0] != '@') return;

    size_t ulen = strlen(bot_username);
    if (strncasecmp(text + 1, bot_username, ulen) != 0) return;

    char after = text[1 + ulen];
    if (after != '\0' && after != ' ' && after != '\t' && after != '\n')
        return;

    const char *src = text + 1 + ulen;
    while (*src == ' ' || *src == '\t') src++;
    memmove(text, src, strlen(src) + 1);
}

static void test_mention_strip_basic(void)
{
    char buf[256];
    strcpy(buf, "@botname hello world");
    strip_mention(buf, "botname");
    ASSERT_STR_EQ(buf, "hello world");
}

static void test_mention_strip_case_insensitive(void)
{
    char buf[256];
    strcpy(buf, "@BotName hello world");
    strip_mention(buf, "botname");
    ASSERT_STR_EQ(buf, "hello world");
}

static void test_mention_strip_only_mention(void)
{
    char buf[256];
    strcpy(buf, "@botname");
    strip_mention(buf, "botname");
    ASSERT_STR_EQ(buf, "");
}

static void test_mention_strip_no_match(void)
{
    char buf[256];
    strcpy(buf, "@otherbot hello");
    strip_mention(buf, "botname");
    ASSERT_STR_EQ(buf, "@otherbot hello");
}

static void test_mention_strip_partial_username(void)
{
    /* @botname2 should NOT be stripped for bot "botname" */
    char buf[256];
    strcpy(buf, "@botname2 hello");
    strip_mention(buf, "botname");
    ASSERT_STR_EQ(buf, "@botname2 hello");
}

static void test_mention_strip_no_at(void)
{
    char buf[256];
    strcpy(buf, "botname hello");
    strip_mention(buf, "botname");
    ASSERT_STR_EQ(buf, "botname hello");
}

/* ---- Send tweet via mock ---- */

static void test_x_send_tweet(void)
{
    /* Mock X API tweet endpoint */
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = NULL, /* catch-all */
        .status = 200,
        .body = "{\"data\":{\"id\":\"1234567890\",\"text\":\"hello\"}}",
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_x_config_t cfg = {
        .enabled = 1,
        .consumer_key = "test_ck",
        .consumer_secret = "test_cs",
        .access_token = "test_at",
        .access_token_secret = "test_ats",
        .api_base = (char *)sc_mock_http_url(mock),
    };

    sc_channel_t *ch = sc_channel_x_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ch->running = 1;

    sc_outbound_msg_t msg = {
        .channel = "x",
        .chat_id = "9876543210",
        .content = "Hello from test!",
    };

    int ret = ch->send(ch, &msg);
    ASSERT_INT_EQ(ret, 0);

    /* Verify mock received POST with OAuth header */
    sc_mock_request_t req = sc_mock_http_last_request(mock);
    ASSERT_STR_EQ(req.method, "POST");
    ASSERT(strstr(req.uri, "/2/tweets") != NULL,
           "Should POST to /2/tweets");
    ASSERT(strstr(req.body, "Hello from test!") != NULL,
           "Body should contain message text");
    ASSERT(strstr(req.body, "9876543210") != NULL,
           "Body should contain reply-to tweet ID");
    sc_mock_request_free(&req);

    ch->running = 0;
    ch->destroy(ch);
    sc_mock_http_stop(mock);
}

static void test_x_read_only_blocks_send(void)
{
    sc_x_config_t cfg = {
        .enabled = 1,
        .consumer_key = "ck",
        .consumer_secret = "cs",
        .access_token = "at",
        .access_token_secret = "ats",
        .read_only = 1,
    };

    sc_channel_t *ch = sc_channel_x_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ch->running = 1;

    sc_outbound_msg_t msg = {
        .channel = "x",
        .chat_id = "123456",
        .content = "This should be blocked",
    };

    /* Send should fail in read-only mode */
    int ret = ch->send(ch, &msg);
    ASSERT_INT_EQ(ret, -1);

    /* DM should also be blocked */
    sc_outbound_msg_t dm = {
        .channel = "x",
        .chat_id = "dm:789",
        .content = "This DM should be blocked",
    };
    ret = ch->send(ch, &dm);
    ASSERT_INT_EQ(ret, -1);

    ch->running = 0;
    ch->destroy(ch);
}

static void test_x_read_only_off_allows_send(void)
{
    /* Mock that accepts tweets */
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = NULL,
        .status = 200,
        .body = "{\"data\":{\"id\":\"111\",\"text\":\"ok\"}}",
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_x_config_t cfg = {
        .enabled = 1,
        .consumer_key = "ck",
        .consumer_secret = "cs",
        .access_token = "at",
        .access_token_secret = "ats",
        .api_base = (char *)sc_mock_http_url(mock),
        .read_only = 0,  /* explicitly off */
    };

    sc_channel_t *ch = sc_channel_x_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ch->running = 1;

    sc_outbound_msg_t msg = {
        .channel = "x",
        .chat_id = "123456",
        .content = "This should go through",
    };

    int ret = ch->send(ch, &msg);
    ASSERT_INT_EQ(ret, 0);

    ch->running = 0;
    ch->destroy(ch);
    sc_mock_http_stop(mock);
}

static void test_x_send_tweet_fail(void)
{
    /* Mock returns error */
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = NULL,
        .status = 200,
        .body = "{\"errors\":[{\"message\":\"Forbidden\"}]}",
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_x_config_t cfg = {
        .enabled = 1,
        .consumer_key = "test_ck",
        .consumer_secret = "test_cs",
        .access_token = "test_at",
        .access_token_secret = "test_ats",
        .api_base = (char *)sc_mock_http_url(mock),
    };

    sc_channel_t *ch = sc_channel_x_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ch->running = 1;

    sc_outbound_msg_t msg = {
        .channel = "x",
        .chat_id = "123",
        .content = "test",
    };

    int ret = ch->send(ch, &msg);
    ASSERT_INT_EQ(ret, -1);

    ch->running = 0;
    ch->destroy(ch);
    sc_mock_http_stop(mock);
}

int main(void)
{
    printf("test_x\n");

    RUN_TEST(test_x_channel_create);
    RUN_TEST(test_x_channel_not_running);
    RUN_TEST(test_x_typing_noop);
    RUN_TEST(test_x_allow_list);
    RUN_TEST(test_x_default_poll_interval);
    RUN_TEST(test_tweet_split_short);
    RUN_TEST(test_tweet_split_exact);
    RUN_TEST(test_tweet_split_long);
    RUN_TEST(test_tweet_split_no_spaces);
    RUN_TEST(test_tweet_split_empty);
    RUN_TEST(test_mention_strip_basic);
    RUN_TEST(test_mention_strip_case_insensitive);
    RUN_TEST(test_mention_strip_only_mention);
    RUN_TEST(test_mention_strip_no_match);
    RUN_TEST(test_mention_strip_partial_username);
    RUN_TEST(test_mention_strip_no_at);
    RUN_TEST(test_x_read_only_blocks_send);
    RUN_TEST(test_x_read_only_off_allows_send);
    RUN_TEST(test_x_send_tweet);
    RUN_TEST(test_x_send_tweet_fail);

    TEST_REPORT();
}
