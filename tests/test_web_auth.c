/*
 * smolclaw — web channel bearer auth tests (audit 4298ba13 / PR-1).
 */

#include "test_main.h"

#include "channels/web.h"
#include "bus.h"
#include "rate_limit.h"

#include <string.h>

static void test_bearer_auth_empty_config_denies(void)
{
    ASSERT_INT_EQ(sc_web_check_bearer_auth(NULL, "Bearer secret"), 0);
    ASSERT_INT_EQ(sc_web_check_bearer_auth("", "Bearer secret"), 0);
}

static void test_bearer_auth_missing_header_denies(void)
{
    ASSERT_INT_EQ(sc_web_check_bearer_auth("secret", NULL), 0);
}

static void test_bearer_auth_wrong_scheme_denies(void)
{
    ASSERT_INT_EQ(sc_web_check_bearer_auth("secret", "Basic secret"), 0);
    ASSERT_INT_EQ(sc_web_check_bearer_auth("secret", "Bearerwrong"), 0);
}

static void test_bearer_auth_wrong_token_denies(void)
{
    ASSERT_INT_EQ(sc_web_check_bearer_auth("secret", "Bearer other"), 0);
}

static void test_bearer_auth_valid_accepts(void)
{
    ASSERT_INT_EQ(sc_web_check_bearer_auth("secret", "Bearer secret"), 1);
}

static void test_message_rate_key_includes_ip_and_token(void)
{
    char key[128];
    ASSERT_INT_EQ(sc_web_build_message_rate_key("192.0.2.1",
        "Bearer my-secret", key, sizeof(key)), 0);
    ASSERT(strstr(key, "web:msg:192.0.2.1:") != NULL,
           "rate key must include IP prefix");
    ASSERT(strcmp(key, "web:msg:192.0.2.1:anon") != 0,
           "rate key must hash bearer token");

    ASSERT_INT_EQ(sc_web_build_message_rate_key(NULL, NULL, key, sizeof(key)), 0);
    ASSERT_STR_EQ(key, "web:msg:unknown:anon");
}

static void test_message_rate_limit_burst_blocked(void)
{
    sc_rate_limiter_t *rl = sc_rate_limiter_new(2);
    ASSERT_NOT_NULL(rl);

    ASSERT_INT_EQ(sc_web_check_message_rate_limit(rl, "10.0.0.1",
        "Bearer tok"), 1);
    ASSERT_INT_EQ(sc_web_check_message_rate_limit(rl, "10.0.0.1",
        "Bearer tok"), 1);
    ASSERT_INT_EQ(sc_web_check_message_rate_limit(rl, "10.0.0.1",
        "Bearer tok"), 0);

    ASSERT_INT_EQ(sc_web_check_message_rate_limit(rl, "10.0.0.2",
        "Bearer tok"), 1);

    sc_rate_limiter_free(rl);
}

static void test_web_start_rejects_empty_token(void)
{
    sc_bus_t *bus = sc_bus_create(NULL);
    ASSERT(bus != NULL, "bus alloc");

    sc_web_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.bind_addr = "127.0.0.1";
    cfg.port = 18080;
    cfg.bearer_token = "";

    sc_channel_t *ch = sc_channel_web_new(&cfg, bus, "/tmp");
    ASSERT(ch != NULL, "channel alloc");

    ASSERT_INT_EQ(ch->start(ch), -1);

    ch->destroy(ch);
    sc_bus_destroy(bus);
}

int main(void)
{
    printf("test_web_auth:\n");
    RUN_TEST(test_bearer_auth_empty_config_denies);
    RUN_TEST(test_bearer_auth_missing_header_denies);
    RUN_TEST(test_bearer_auth_wrong_scheme_denies);
    RUN_TEST(test_bearer_auth_wrong_token_denies);
    RUN_TEST(test_bearer_auth_valid_accepts);
    RUN_TEST(test_message_rate_key_includes_ip_and_token);
    RUN_TEST(test_message_rate_limit_burst_blocked);
    RUN_TEST(test_web_start_rejects_empty_token);
    TEST_REPORT();
}