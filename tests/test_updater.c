/*
 * test_updater.c — Tests for semver, manifest parsing, SHA-256 verification
 */

#include "test_main.h"
#include "updater/updater.h"
#include "updater/types.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ===== Semver parsing ===== */

static void test_semver_parse_valid(void)
{
    sc_semver_t v;
    ASSERT_INT_EQ(sc_semver_parse("1.2.3", &v), 0);
    ASSERT_INT_EQ(v.major, 1);
    ASSERT_INT_EQ(v.minor, 2);
    ASSERT_INT_EQ(v.patch, 3);
}

static void test_semver_parse_zero(void)
{
    sc_semver_t v;
    ASSERT_INT_EQ(sc_semver_parse("0.0.0", &v), 0);
    ASSERT_INT_EQ(v.major, 0);
    ASSERT_INT_EQ(v.minor, 0);
    ASSERT_INT_EQ(v.patch, 0);
}

static void test_semver_parse_large(void)
{
    sc_semver_t v;
    ASSERT_INT_EQ(sc_semver_parse("100.200.300", &v), 0);
    ASSERT_INT_EQ(v.major, 100);
    ASSERT_INT_EQ(v.minor, 200);
    ASSERT_INT_EQ(v.patch, 300);
}

static void test_semver_parse_with_prerelease(void)
{
    sc_semver_t v;
    /* Pre-release suffix is allowed (not validated beyond semver triplet) */
    ASSERT_INT_EQ(sc_semver_parse("1.2.3-beta", &v), 0);
    ASSERT_INT_EQ(v.major, 1);
}

static void test_semver_parse_with_build(void)
{
    sc_semver_t v;
    ASSERT_INT_EQ(sc_semver_parse("1.2.3+build", &v), 0);
    ASSERT_INT_EQ(v.major, 1);
}

static void test_semver_parse_invalid(void)
{
    sc_semver_t v;
    ASSERT(sc_semver_parse("abc", &v) != 0, "should reject 'abc'");
    ASSERT(sc_semver_parse("1.2", &v) != 0, "should reject '1.2'");
    ASSERT(sc_semver_parse("", &v) != 0, "should reject empty");
    ASSERT(sc_semver_parse(NULL, &v) != 0, "should reject NULL");
    ASSERT(sc_semver_parse("1.2.3x", &v) != 0, "should reject trailing char");
}

/* ===== Semver comparison ===== */

static void test_semver_compare_equal(void)
{
    sc_semver_t a = {1, 2, 3}, b = {1, 2, 3};
    ASSERT_INT_EQ(sc_semver_compare(&a, &b), 0);
}

static void test_semver_compare_major(void)
{
    sc_semver_t a = {2, 0, 0}, b = {1, 9, 9};
    ASSERT(sc_semver_compare(&a, &b) > 0, "2.0.0 > 1.9.9");
    ASSERT(sc_semver_compare(&b, &a) < 0, "1.9.9 < 2.0.0");
}

static void test_semver_compare_minor(void)
{
    sc_semver_t a = {1, 3, 0}, b = {1, 2, 9};
    ASSERT(sc_semver_compare(&a, &b) > 0, "1.3.0 > 1.2.9");
}

static void test_semver_compare_patch(void)
{
    sc_semver_t a = {1, 2, 4}, b = {1, 2, 3};
    ASSERT(sc_semver_compare(&a, &b) > 0, "1.2.4 > 1.2.3");
}

/* ===== Manifest parsing ===== */

static const char *VALID_MANIFEST =
    "{"
    "  \"latest\": \"0.2.0\","
    "  \"releases\": {"
    "    \"0.2.0\": {"
    "      \"changelog\": \"Added updater\","
    "      \"artifacts\": {"
    "        \"x86_64\": {"
    "          \"url\": \"https://example.com/smolclaw-x86_64\","
    "          \"sha256\": \"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\","
    "          \"size\": 4800000"
    "        },"
    "        \"aarch64\": {"
    "          \"url\": \"https://example.com/smolclaw-aarch64\","
    "          \"sha256\": \"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\","
    "          \"size\": 5200000"
    "        }"
    "      }"
    "    }"
    "  }"
    "}";

static void test_manifest_parse_valid(void)
{
    sc_update_manifest_t *m = sc_updater_parse_manifest(VALID_MANIFEST, "x86_64");
    ASSERT_NOT_NULL(m);
    ASSERT_STR_EQ(m->latest, "0.2.0");
    ASSERT_INT_EQ(m->latest_ver.major, 0);
    ASSERT_INT_EQ(m->latest_ver.minor, 2);
    ASSERT_INT_EQ(m->latest_ver.patch, 0);
    ASSERT_STR_EQ(m->changelog, "Added updater");
    ASSERT_STR_EQ(m->artifact.url, "https://example.com/smolclaw-x86_64");
    ASSERT_STR_EQ(m->artifact.sha256, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    ASSERT(m->artifact.size == 4800000, "size should be 4800000");
    sc_update_manifest_free(m);
}

static void test_manifest_parse_different_arch(void)
{
    sc_update_manifest_t *m = sc_updater_parse_manifest(VALID_MANIFEST, "aarch64");
    ASSERT_NOT_NULL(m);
    ASSERT_STR_EQ(m->artifact.url, "https://example.com/smolclaw-aarch64");
    sc_update_manifest_free(m);
}

static void test_manifest_parse_wrong_arch(void)
{
    sc_update_manifest_t *m = sc_updater_parse_manifest(VALID_MANIFEST, "armv7l");
    ASSERT_NULL(m);
}

static void test_manifest_parse_missing_fields(void)
{
    /* Missing latest */
    ASSERT_NULL(sc_updater_parse_manifest("{\"releases\":{}}", "x86_64"));
    /* Missing releases */
    ASSERT_NULL(sc_updater_parse_manifest("{\"latest\":\"1.0.0\"}", "x86_64"));
    /* Invalid JSON */
    ASSERT_NULL(sc_updater_parse_manifest("{bad json", "x86_64"));
    /* NULL inputs */
    ASSERT_NULL(sc_updater_parse_manifest(NULL, "x86_64"));
    ASSERT_NULL(sc_updater_parse_manifest(VALID_MANIFEST, NULL));
}

static void test_manifest_parse_empty_releases(void)
{
    const char *json = "{\"latest\":\"1.0.0\",\"releases\":{}}";
    ASSERT_NULL(sc_updater_parse_manifest(json, "x86_64"));
}

/* ===== SHA-256 verification ===== */

/* Helper: compute SHA-256 of data and return hex string (static buffer) */
static const char *sha256_hex(const unsigned char *data, size_t len)
{
    static char hex[65];
    unsigned char hash[32];
    unsigned int hash_len = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", hash[i]);
    hex[64] = '\0';
    return hex;
}

static void test_verify_correct_hash(void)
{
    /* Write test file */
    char tmp[] = "/tmp/test_updater_verify_XXXXXX";
    int fd = mkstemp(tmp);
    ASSERT(fd >= 0, "mkstemp");
    const char *content = "smolclaw test binary content\n";
    write(fd, content, strlen(content));
    close(fd);

    const char *hash = sha256_hex((const unsigned char *)content, strlen(content));
    sc_update_artifact_t art = { .sha256 = (char *)hash };
    ASSERT_INT_EQ(sc_updater_verify(tmp, &art), 0);
    unlink(tmp);
}

static void test_verify_wrong_hash(void)
{
    char tmp[] = "/tmp/test_updater_verify_XXXXXX";
    int fd = mkstemp(tmp);
    ASSERT(fd >= 0, "mkstemp");
    write(fd, "data", 4);
    close(fd);

    sc_update_artifact_t art = {
        .sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
    };
    ASSERT(sc_updater_verify(tmp, &art) != 0, "wrong hash should fail");
    unlink(tmp);
}

static void test_verify_missing_file(void)
{
    sc_update_artifact_t art = {
        .sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    };
    ASSERT(sc_updater_verify("/tmp/nonexistent_updater_test", &art) != 0,
           "missing file should fail");
}

static void test_verify_bad_hash_length(void)
{
    sc_update_artifact_t art = { .sha256 = "tooshort" };
    ASSERT(sc_updater_verify("/tmp/whatever", &art) != 0,
           "short hash should fail");
}

/* ===== Architecture detection ===== */

static void test_get_arch(void)
{
    const char *arch = sc_updater_get_arch();
    ASSERT_NOT_NULL(arch);
    ASSERT(strlen(arch) > 0, "arch should be non-empty");
}

/* ===== Main ===== */

int main(void)
{
    printf("test_updater\n");

    RUN_TEST(test_semver_parse_valid);
    RUN_TEST(test_semver_parse_zero);
    RUN_TEST(test_semver_parse_large);
    RUN_TEST(test_semver_parse_with_prerelease);
    RUN_TEST(test_semver_parse_with_build);
    RUN_TEST(test_semver_parse_invalid);
    RUN_TEST(test_semver_compare_equal);
    RUN_TEST(test_semver_compare_major);
    RUN_TEST(test_semver_compare_minor);
    RUN_TEST(test_semver_compare_patch);
    RUN_TEST(test_manifest_parse_valid);
    RUN_TEST(test_manifest_parse_different_arch);
    RUN_TEST(test_manifest_parse_wrong_arch);
    RUN_TEST(test_manifest_parse_missing_fields);
    RUN_TEST(test_manifest_parse_empty_releases);
    RUN_TEST(test_verify_correct_hash);
    RUN_TEST(test_verify_wrong_hash);
    RUN_TEST(test_verify_missing_file);
    RUN_TEST(test_verify_bad_hash_length);
    RUN_TEST(test_get_arch);

    TEST_REPORT();
}
