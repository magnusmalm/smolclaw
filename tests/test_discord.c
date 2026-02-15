/*
 * smolclaw - Discord channel tests
 * Tests Discord config, channel creation, WebSocket client (offline),
 * and REST API (send/typing) via mock HTTP.
 */

#include "test_main.h"
#include "mock_http.h"
#include "channels/discord.h"
#include "config.h"
#include "constants.h"
#include "util/websocket.h"
#include "util/str.h"

#include <stdlib.h>
#include <string.h>

static void test_discord_config_defaults(void)
{
    sc_config_t *cfg = sc_config_default();
    ASSERT_NOT_NULL(cfg);

    /* Discord should be disabled by default */
    ASSERT_INT_EQ(cfg->discord.enabled, 0);
    ASSERT_NULL(cfg->discord.token);
    ASSERT_INT_EQ(cfg->discord.allow_from_count, 0);

    sc_config_free(cfg);
}

static void test_discord_channel_create(void)
{
    /* NULL config -> NULL channel */
    sc_channel_t *ch = sc_channel_discord_new(NULL, NULL);
    ASSERT_NULL(ch);

    /* Config without token -> NULL */
    sc_discord_config_t cfg = { .enabled = 1, .token = NULL };
    ch = sc_channel_discord_new(&cfg, NULL);
    ASSERT_NULL(ch);

    /* Valid config -> creates channel */
    cfg.token = "test-token-123";
    ch = sc_channel_discord_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ASSERT_STR_EQ(ch->name, SC_CHANNEL_DISCORD);
    ASSERT_INT_EQ(ch->running, 0);

    /* Verify vtable is populated */
    ASSERT_NOT_NULL(ch->start);
    ASSERT_NOT_NULL(ch->stop);
    ASSERT_NOT_NULL(ch->send);
    ASSERT_NOT_NULL(ch->is_running);
    ASSERT_NOT_NULL(ch->destroy);

    ch->destroy(ch);
}

static void test_discord_channel_allow_list(void)
{
    char *allow[] = { "123456", "user2" };
    sc_discord_config_t cfg = {
        .enabled = 1,
        .token = "test-token",
        .allow_from = allow,
        .allow_from_count = 2,
    };

    sc_channel_t *ch = sc_channel_discord_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ASSERT_INT_EQ(ch->allow_list_count, 2);
    ASSERT_STR_EQ(ch->allow_list[0], "123456");
    ASSERT_STR_EQ(ch->allow_list[1], "user2");

    ch->destroy(ch);
}

static void test_discord_constant(void)
{
    ASSERT_STR_EQ(SC_CHANNEL_DISCORD, "discord");

    /* Verify discord is NOT an internal channel */
    ASSERT_INT_EQ(sc_is_internal_channel("discord"), 0);
}

static void test_websocket_bad_url(void)
{
    /* Bad URLs should return NULL */
    sc_ws_t *ws = sc_ws_connect("http://example.com");
    ASSERT_NULL(ws);

    ws = sc_ws_connect("not-a-url");
    ASSERT_NULL(ws);
}

static void test_websocket_unreachable(void)
{
    /* Connecting to a non-existent host should fail gracefully */
    sc_ws_t *ws = sc_ws_connect("wss://localhost:1/test");
    ASSERT_NULL(ws);
}

static void test_websocket_null_ops(void)
{
    /* Operations on NULL should not crash */
    ASSERT_INT_EQ(sc_ws_is_connected(NULL), 0);
    ASSERT_INT_EQ(sc_ws_send_text(NULL, "test", 4), -1);
    ASSERT_NULL(sc_ws_recv(NULL));
    sc_ws_close(NULL); /* Should not crash */
}

static void test_discord_send_message(void)
{
    /* Mock Discord REST API: POST /channels/{id}/messages returns message ID */
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = NULL, /* catch-all */
        .status = 200,
        .body = "{\"id\":\"msg_12345\",\"content\":\"Hello!\"}",
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_discord_config_t cfg = {
        .enabled = 1,
        .token = "test-bot-token",
        .api_base = (char *)sc_mock_http_url(mock),
    };

    sc_channel_t *ch = sc_channel_discord_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ch->running = 1; /* simulate running state for send */

    sc_outbound_msg_t msg = {
        .channel = "discord",
        .chat_id = "987654321",
        .content = "Hello from test!",
    };

    int ret = ch->send(ch, &msg);
    ASSERT_INT_EQ(ret, 0);

    /* Verify the mock received the POST with correct endpoint and body */
    sc_mock_request_t req = sc_mock_http_last_request(mock);
    ASSERT_STR_EQ(req.method, "POST");
    ASSERT(strstr(req.uri, "/channels/987654321/messages") != NULL,
           "Should POST to /channels/{chat_id}/messages");
    ASSERT(strstr(req.body, "Hello from test!") != NULL,
           "Body should contain message content");
    sc_mock_request_free(&req);

    ch->running = 0;
    ch->destroy(ch);
    sc_mock_http_stop(mock);
}

static void test_discord_send_typing(void)
{
    /* Mock typing endpoint */
    sc_mock_route_t routes[] = {{
        .method = "POST",
        .path = NULL,
        .status = 204, /* Discord returns 204 No Content for typing */
        .body = "",
    }};
    sc_mock_http_t *mock = sc_mock_http_start(routes, 1);
    ASSERT_NOT_NULL(mock);

    sc_discord_config_t cfg = {
        .enabled = 1,
        .token = "test-token",
        .api_base = (char *)sc_mock_http_url(mock),
    };

    sc_channel_t *ch = sc_channel_discord_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    ch->running = 1;

    int ret = ch->send_typing(ch, "123456789");
    ASSERT_INT_EQ(ret, 0);

    /* Verify the mock received the POST to typing endpoint */
    sc_mock_request_t req = sc_mock_http_last_request(mock);
    ASSERT_STR_EQ(req.method, "POST");
    ASSERT(strstr(req.uri, "/channels/123456789/typing") != NULL,
           "Should POST to /channels/{id}/typing");
    sc_mock_request_free(&req);

    ch->running = 0;
    ch->destroy(ch);
    sc_mock_http_stop(mock);
}

static void test_discord_send_not_running(void)
{
    sc_discord_config_t cfg = {
        .enabled = 1,
        .token = "test-token",
    };

    sc_channel_t *ch = sc_channel_discord_new(&cfg, NULL);
    ASSERT_NOT_NULL(ch);
    /* ch->running is 0 (not started) */

    sc_outbound_msg_t msg = {
        .channel = "discord",
        .chat_id = "123",
        .content = "test",
    };

    int ret = ch->send(ch, &msg);
    ASSERT_INT_EQ(ret, -1); /* Should fail when not running */

    ch->destroy(ch);
}

int main(void)
{
    printf("test_discord\n");

    RUN_TEST(test_discord_config_defaults);
    RUN_TEST(test_discord_channel_create);
    RUN_TEST(test_discord_channel_allow_list);
    RUN_TEST(test_discord_constant);
    RUN_TEST(test_websocket_bad_url);
    RUN_TEST(test_websocket_unreachable);
    RUN_TEST(test_websocket_null_ops);
    RUN_TEST(test_discord_send_message);
    RUN_TEST(test_discord_send_typing);
    RUN_TEST(test_discord_send_not_running);

    TEST_REPORT();
}
