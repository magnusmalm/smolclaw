/*
 * smolclaw - Telegram channel E2E tests
 * Tests Telegram REST API (sendMessage, sendChatAction) via mock HTTP server.
 */

#include "test_main.h"
#include "mock_http.h"
#include "channels/telegram.h"
#include "constants.h"
#include "util/str.h"

#include <stdlib.h>
#include <string.h>

static void test_telegram_channel_create(void)
{
    /* NULL config -> NULL */
    sc_channel_t *ch = sc_channel_telegram_new(NULL, NULL);
    ASSERT_NULL(ch);

    /* No token -> NULL */
    sc_telegram_config_t cfg = { .enabled = 1, .token = NULL };
    ch = sc_channel_telegram_new(&cfg, NULL);
    ASSERT_NULL(ch);

    /* Valid config -> creates channel */
    cfg.token = "123456:ABC-DEF";
    ch = sc_channel_telegram_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ASSERT_STR_EQ(ch->name, SC_CHANNEL_TELEGRAM);
    ASSERT_INT_EQ(ch->running, 0);
    ASSERT_NOT_NULL(ch->start);
    ASSERT_NOT_NULL(ch->stop);
    ASSERT_NOT_NULL(ch->send);
    ASSERT_NOT_NULL(ch->destroy);

    ch->destroy(ch);
}

static void test_telegram_send_message(void)
{
    /* Mock Telegram sendMessage API */
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = NULL, /* catch-all for /bot<token>/sendMessage */
        .status = 200,
        .body = "{\"ok\":true,\"result\":{\"message_id\":42}}",
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_telegram_config_t cfg = {
        .enabled = 1,
        .token = "123456:TESTTOKEN",
        .api_base = (char *)sc_mock_http_url(mock),
    };

    sc_channel_t *ch = sc_channel_telegram_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ch->running = 1;

    sc_outbound_msg_t msg = {
        .channel = "telegram",
        .chat_id = "99887766",
        .content = "Hello from test!",
    };

    int ret = ch->send(ch, &msg);
    ASSERT_INT_EQ(ret, 0);

    /* Verify mock received POST to correct endpoint */
    sc_mock_request_t req = sc_mock_http_last_request(mock);
    ASSERT_STR_EQ(req.method, "POST");
    ASSERT(strstr(req.uri, "/bot123456:TESTTOKEN/sendMessage") != NULL,
           "Should POST to /bot<token>/sendMessage");
    ASSERT(strstr(req.body, "99887766") != NULL,
           "Body should contain chat_id");
    ASSERT(strstr(req.body, "Hello from test!") != NULL,
           "Body should contain message text");
    sc_mock_request_free(&req);

    ch->running = 0;
    ch->destroy(ch);
    sc_mock_http_stop(mock);
}

static void test_telegram_send_typing(void)
{
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = NULL,
        .status = 200,
        .body = "{\"ok\":true}",
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_telegram_config_t cfg = {
        .enabled = 1,
        .token = "123456:TESTTOKEN",
        .api_base = (char *)sc_mock_http_url(mock),
    };

    sc_channel_t *ch = sc_channel_telegram_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ch->running = 1;

    int ret = ch->send_typing(ch, "99887766");
    ASSERT_INT_EQ(ret, 0);

    /* Verify mock received POST to sendChatAction */
    sc_mock_request_t req = sc_mock_http_last_request(mock);
    ASSERT_STR_EQ(req.method, "POST");
    ASSERT(strstr(req.uri, "/bot123456:TESTTOKEN/sendChatAction") != NULL,
           "Should POST to sendChatAction endpoint");
    ASSERT(strstr(req.body, "typing") != NULL,
           "Body should contain typing action");
    sc_mock_request_free(&req);

    ch->running = 0;
    ch->destroy(ch);
    sc_mock_http_stop(mock);
}

static void test_telegram_send_fail(void)
{
    /* Mock returns error */
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = NULL,
        .status = 200,
        .body = "{\"ok\":false,\"description\":\"Bad Request\"}",
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_telegram_config_t cfg = {
        .enabled = 1,
        .token = "123456:TESTTOKEN",
        .api_base = (char *)sc_mock_http_url(mock),
    };

    sc_channel_t *ch = sc_channel_telegram_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ch->running = 1;

    sc_outbound_msg_t msg = {
        .channel = "telegram",
        .chat_id = "123",
        .content = "test",
    };

    /* First attempt with parse_mode fails, retry without also fails -> -1 */
    int ret = ch->send(ch, &msg);
    ASSERT_INT_EQ(ret, -1);

    ch->running = 0;
    ch->destroy(ch);
    sc_mock_http_stop(mock);
}

static void test_telegram_send_not_running(void)
{
    sc_telegram_config_t cfg = {
        .enabled = 1,
        .token = "123456:TESTTOKEN",
    };

    sc_channel_t *ch = sc_channel_telegram_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);

    sc_outbound_msg_t msg = {
        .channel = "telegram",
        .chat_id = "123",
        .content = "test",
    };

    int ret = ch->send(ch, &msg);
    ASSERT_INT_EQ(ret, -1);

    ch->destroy(ch);
}

static void test_telegram_allow_list(void)
{
    char *allow[] = { "user1", "user2|bob" };
    sc_telegram_config_t cfg = {
        .enabled = 1,
        .token = "123456:TOKEN",
        .allow_from = allow,
        .allow_from_count = 2,
    };

    sc_channel_t *ch = sc_channel_telegram_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ASSERT_INT_EQ(ch->allow_list_count, 2);
    ASSERT_STR_EQ(ch->allow_list[0], "user1");
    ASSERT_STR_EQ(ch->allow_list[1], "user2|bob");

    ch->destroy(ch);
}

int main(void)
{
    printf("test_telegram\n");

    RUN_TEST(test_telegram_channel_create);
    RUN_TEST(test_telegram_send_message);
    RUN_TEST(test_telegram_send_typing);
    RUN_TEST(test_telegram_send_fail);
    RUN_TEST(test_telegram_send_not_running);
    RUN_TEST(test_telegram_allow_list);

    TEST_REPORT();
}
