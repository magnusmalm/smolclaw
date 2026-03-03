/*
 * smolclaw - curl_common tests
 *
 * Tests CA bundle discovery, env var override, and curl handle defaults.
 */

#include "test_main.h"
#include "util/curl_common.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

static void test_find_ca_bundle_system_path(void)
{
    /* Unset env vars so we fall through to path probing */
    unsetenv("CURL_CA_BUNDLE");
    unsetenv("SSL_CERT_FILE");

    const char *ca = sc_curl_find_ca_bundle();
    /* On any standard Linux, at least one known path should exist */
    if (access("/etc/ssl/certs/ca-certificates.crt", R_OK) == 0 ||
        access("/etc/pki/tls/certs/ca-bundle.crt", R_OK) == 0 ||
        access("/etc/ssl/cert.pem", R_OK) == 0 ||
        access("/etc/ssl/certs/ca-bundle.crt", R_OK) == 0) {
        ASSERT_NOT_NULL(ca);
        /* Must be one of the known paths */
        ASSERT(
            strcmp(ca, "/etc/ssl/certs/ca-certificates.crt") == 0 ||
            strcmp(ca, "/etc/pki/tls/certs/ca-bundle.crt") == 0 ||
            strcmp(ca, "/etc/ssl/cert.pem") == 0 ||
            strcmp(ca, "/etc/ssl/certs/ca-bundle.crt") == 0,
            "CA bundle should be a known system path"
        );
    } else {
        /* No system certs — NULL is correct */
        ASSERT_NULL(ca);
    }
}

static void test_find_ca_bundle_env_override(void)
{
    /* CURL_CA_BUNDLE pointing to a real file should win */
    setenv("CURL_CA_BUNDLE", "/etc/passwd", 1);
    unsetenv("SSL_CERT_FILE");

    const char *ca = sc_curl_find_ca_bundle();
    ASSERT_NOT_NULL(ca);
    ASSERT_STR_EQ(ca, "/etc/passwd");

    unsetenv("CURL_CA_BUNDLE");
}

static void test_find_ca_bundle_ssl_cert_file(void)
{
    /* SSL_CERT_FILE should work as fallback when CURL_CA_BUNDLE is unset */
    unsetenv("CURL_CA_BUNDLE");
    setenv("SSL_CERT_FILE", "/etc/passwd", 1);

    const char *ca = sc_curl_find_ca_bundle();
    ASSERT_NOT_NULL(ca);
    ASSERT_STR_EQ(ca, "/etc/passwd");

    unsetenv("SSL_CERT_FILE");
}

static void test_find_ca_bundle_env_priority(void)
{
    /* CURL_CA_BUNDLE takes precedence over SSL_CERT_FILE */
    setenv("CURL_CA_BUNDLE", "/etc/hostname", 1);
    setenv("SSL_CERT_FILE", "/etc/passwd", 1);

    const char *ca = sc_curl_find_ca_bundle();
    ASSERT_NOT_NULL(ca);
    ASSERT_STR_EQ(ca, "/etc/hostname");

    unsetenv("CURL_CA_BUNDLE");
    unsetenv("SSL_CERT_FILE");
}

static void test_find_ca_bundle_nonexistent_env(void)
{
    /* Env var pointing to nonexistent file should be skipped */
    setenv("CURL_CA_BUNDLE", "/nonexistent/ca-bundle.crt", 1);
    unsetenv("SSL_CERT_FILE");

    const char *ca = sc_curl_find_ca_bundle();
    /* Should fall through to system paths (or NULL if none exist) */
    if (ca) {
        ASSERT(strcmp(ca, "/nonexistent/ca-bundle.crt") != 0,
               "Should not return nonexistent env path");
    } else {
        ASSERT_NULL(ca);
    }

    unsetenv("CURL_CA_BUNDLE");
}

static void test_find_ca_bundle_hot_swap(void)
{
    /* Verify the path changes when the env var changes (no caching) */
    setenv("CURL_CA_BUNDLE", "/etc/passwd", 1);
    const char *ca1 = sc_curl_find_ca_bundle();
    ASSERT_STR_EQ(ca1, "/etc/passwd");

    setenv("CURL_CA_BUNDLE", "/etc/hostname", 1);
    const char *ca2 = sc_curl_find_ca_bundle();
    ASSERT_STR_EQ(ca2, "/etc/hostname");

    unsetenv("CURL_CA_BUNDLE");
}

static void test_curl_init_returns_handle(void)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);

    CURL *curl = sc_curl_init();
    ASSERT_NOT_NULL(curl);
    curl_easy_cleanup(curl);

    /* Multiple inits should all succeed */
    CURL *curl2 = sc_curl_init();
    ASSERT_NOT_NULL(curl2);
    curl_easy_cleanup(curl2);

    curl_global_cleanup();
}

static void test_curl_apply_defaults_after_reset(void)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);

    CURL *curl = sc_curl_init();
    ASSERT_NOT_NULL(curl);

    /* Reset wipes everything — apply_defaults restores it */
    curl_easy_reset(curl);
    sc_curl_apply_defaults(curl);

    /* Should still be a usable handle (no crash, no error) */
    CURLcode rc = curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    ASSERT_INT_EQ(rc, CURLE_OK);

    curl_easy_cleanup(curl);
    curl_global_cleanup();
}

int main(void)
{
    printf("test_curl_common\n");

    RUN_TEST(test_find_ca_bundle_system_path);
    RUN_TEST(test_find_ca_bundle_env_override);
    RUN_TEST(test_find_ca_bundle_ssl_cert_file);
    RUN_TEST(test_find_ca_bundle_env_priority);
    RUN_TEST(test_find_ca_bundle_nonexistent_env);
    RUN_TEST(test_find_ca_bundle_hot_swap);
    RUN_TEST(test_curl_init_returns_handle);
    RUN_TEST(test_curl_apply_defaults_after_reset);

    TEST_REPORT();
}
