/*
 * smolclaw - curl_common tests
 *
 * Tests CA bundle discovery, env var override, caching, and curl handles.
 * Uses fork() for probe tests since sc_curl_find_ca_bundle() caches on
 * first call — each fork gets a fresh static state.
 */

#include "test_main.h"
#include "util/curl_common.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

/* Run a test function in a forked child. Returns 0 on success, 1 on failure. */
static int run_in_fork(void (*fn)(void))
{
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: reset test counters, run, exit with fail count */
        _test_pass = 0;
        _test_fail = 0;
        fn();
        _exit(_test_fail > 0 ? 1 : 0);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

#define RUN_FORKED_TEST(fn) do { \
    printf("  %s ...\n", #fn); \
    if (run_in_fork(fn) == 0) { _test_pass++; } \
    else { fprintf(stderr, "  FAIL: %s (in child)\n", #fn); _test_fail++; } \
} while(0)

static void test_system_path(void)
{
    unsetenv("CURL_CA_BUNDLE");
    unsetenv("SSL_CERT_FILE");

    const char *ca = sc_curl_find_ca_bundle();
    if (access("/etc/ssl/certs/ca-certificates.crt", R_OK) == 0 ||
        access("/etc/pki/tls/certs/ca-bundle.crt", R_OK) == 0 ||
        access("/etc/ssl/cert.pem", R_OK) == 0 ||
        access("/etc/ssl/certs/ca-bundle.crt", R_OK) == 0) {
        ASSERT_NOT_NULL(ca);
        ASSERT(
            strcmp(ca, "/etc/ssl/certs/ca-certificates.crt") == 0 ||
            strcmp(ca, "/etc/pki/tls/certs/ca-bundle.crt") == 0 ||
            strcmp(ca, "/etc/ssl/cert.pem") == 0 ||
            strcmp(ca, "/etc/ssl/certs/ca-bundle.crt") == 0,
            "CA bundle should be a known system path"
        );
    } else {
        ASSERT_NULL(ca);
    }
}

static void test_env_curl_ca_bundle(void)
{
    setenv("CURL_CA_BUNDLE", "/etc/passwd", 1);
    unsetenv("SSL_CERT_FILE");
    ASSERT_STR_EQ(sc_curl_find_ca_bundle(), "/etc/passwd");
}

static void test_env_ssl_cert_file(void)
{
    unsetenv("CURL_CA_BUNDLE");
    setenv("SSL_CERT_FILE", "/etc/passwd", 1);
    ASSERT_STR_EQ(sc_curl_find_ca_bundle(), "/etc/passwd");
}

static void test_env_priority(void)
{
    setenv("CURL_CA_BUNDLE", "/etc/hostname", 1);
    setenv("SSL_CERT_FILE", "/etc/passwd", 1);
    ASSERT_STR_EQ(sc_curl_find_ca_bundle(), "/etc/hostname");
}

static void test_nonexistent_env_skipped(void)
{
    setenv("CURL_CA_BUNDLE", "/nonexistent/ca-bundle.crt", 1);
    unsetenv("SSL_CERT_FILE");

    const char *ca = sc_curl_find_ca_bundle();
    if (ca) {
        ASSERT(strcmp(ca, "/nonexistent/ca-bundle.crt") != 0,
               "Should not return nonexistent env path");
    } else {
        ASSERT_NULL(ca);
    }
}

static void test_cached_after_first_call(void)
{
    setenv("CURL_CA_BUNDLE", "/etc/passwd", 1);
    const char *ca1 = sc_curl_find_ca_bundle();
    ASSERT_STR_EQ(ca1, "/etc/passwd");

    /* Change env — cached value should stick */
    setenv("CURL_CA_BUNDLE", "/etc/hostname", 1);
    const char *ca2 = sc_curl_find_ca_bundle();
    ASSERT_STR_EQ(ca2, "/etc/passwd");
}

static void test_curl_init_returns_handle(void)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);

    CURL *curl = sc_curl_init();
    ASSERT_NOT_NULL(curl);
    curl_easy_cleanup(curl);

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

    curl_easy_reset(curl);
    sc_curl_apply_defaults(curl);

    CURLcode rc = curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    ASSERT_INT_EQ(rc, CURLE_OK);

    curl_easy_cleanup(curl);
    curl_global_cleanup();
}

int main(void)
{
    printf("test_curl_common\n");

    /* Probe tests run in forks — each gets fresh static cache */
    RUN_FORKED_TEST(test_system_path);
    RUN_FORKED_TEST(test_env_curl_ca_bundle);
    RUN_FORKED_TEST(test_env_ssl_cert_file);
    RUN_FORKED_TEST(test_env_priority);
    RUN_FORKED_TEST(test_nonexistent_env_skipped);
    RUN_FORKED_TEST(test_cached_after_first_call);

    /* Curl handle tests run in-process */
    RUN_TEST(test_curl_init_returns_handle);
    RUN_TEST(test_curl_apply_defaults_after_reset);

    TEST_REPORT();
}
