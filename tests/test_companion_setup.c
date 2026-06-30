/*
 * companion/setup.c unit tests — URI encoding, connect URI, TLS hints.
 */

#include "test_main.h"

#include "companion/setup.h"
#include "config.h"

#include <string.h>

static void test_uri_encode_reserved(void)
{
    char *enc = sc_companion_uri_encode("https://gw.example.com:8080/path");
    ASSERT_NOT_NULL(enc);
    ASSERT(strstr(enc, "%3A") != NULL, "colons must be percent-encoded");
    ASSERT(strstr(enc, "gw.example.com") != NULL, "host label passes through");
    free(enc);
}

static void test_uri_encode_spaces(void)
{
    char *enc = sc_companion_uri_encode("a b");
    ASSERT_NOT_NULL(enc);
    ASSERT_STR_EQ(enc, "a%20b");
    free(enc);
}

static void test_build_connect_uri(void)
{
    char *uri = sc_companion_build_connect_uri(
        "https://gw.example.com", "sec ret+tok");
    ASSERT_NOT_NULL(uri);
    ASSERT(strstr(uri, "smolclaw://v1/connect?url=") != NULL, "scheme prefix");
    ASSERT(strstr(uri, "&token=") != NULL, "token param");
    ASSERT(strstr(uri, "sec ret") == NULL,
           "spaces in token must be encoded");
    ASSERT(strstr(uri, "%2B") != NULL, "plus in token must be encoded");
    free(uri);
}

static void test_origin_from_web_http_loopback(void)
{
    sc_web_config_t web = {0};
    web.bind_addr = "127.0.0.1";
    web.port = 8080;
    char *origin = sc_companion_origin_from_web(&web, NULL);
    ASSERT_NOT_NULL(origin);
    ASSERT_STR_EQ(origin, "http://127.0.0.1:8080");
    free(origin);
}

static void test_origin_from_web_https_tls(void)
{
    sc_web_config_t web = {0};
    web.bind_addr = "0.0.0.0";
    web.port = 443;
    web.tls_cert = "/tmp/cert.pem";
    web.tls_key = "/tmp/key.pem";
    char *origin = sc_companion_origin_from_web(&web, NULL);
    ASSERT_NOT_NULL(origin);
    ASSERT_STR_EQ(origin, "https://127.0.0.1");
    free(origin);
}

static void test_origin_override(void)
{
    sc_web_config_t web = {0};
    char *origin = sc_companion_origin_from_web(&web,
        "https://pi.tailnet.ts.net");
    ASSERT_NOT_NULL(origin);
    ASSERT_STR_EQ(origin, "https://pi.tailnet.ts.net");
    free(origin);
}

static void test_tls_ok_https(void)
{
    ASSERT_INT_EQ(sc_companion_origin_tls_ok("https://remote.example.com"), 1);
}

static void test_tls_ok_private_http(void)
{
    ASSERT_INT_EQ(sc_companion_origin_tls_ok("http://192.168.1.10:8080"), 1);
    ASSERT_INT_EQ(sc_companion_origin_tls_ok("http://127.0.0.1:8080"), 1);
}

static void test_tls_ok_public_http_rejected(void)
{
    ASSERT_INT_EQ(sc_companion_origin_tls_ok("http://gw.example.com"), 0);
}

int main(void)
{
    printf("test_companion_setup:\n");
    RUN_TEST(test_uri_encode_reserved);
    RUN_TEST(test_uri_encode_spaces);
    RUN_TEST(test_build_connect_uri);
    RUN_TEST(test_origin_from_web_http_loopback);
    RUN_TEST(test_origin_from_web_https_tls);
    RUN_TEST(test_origin_override);
    RUN_TEST(test_tls_ok_https);
    RUN_TEST(test_tls_ok_private_http);
    RUN_TEST(test_tls_ok_public_http_rejected);
    TEST_REPORT();
}