/*
 * smolclaw - pairing module tests
 */

#include "test_main.h"
#include "pairing.h"
#include "constants.h"
#include "util/str.h"

#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void test_policy_roundtrip(void)
{
    ASSERT_INT_EQ(sc_dm_policy_from_str("open"), SC_DM_POLICY_OPEN);
    ASSERT_INT_EQ(sc_dm_policy_from_str("allowlist"), SC_DM_POLICY_ALLOWLIST);
    ASSERT_INT_EQ(sc_dm_policy_from_str("pairing"), SC_DM_POLICY_PAIRING);
    ASSERT_INT_EQ(sc_dm_policy_from_str(NULL), SC_DM_POLICY_ALLOWLIST);
    ASSERT_INT_EQ(sc_dm_policy_from_str("bogus"), SC_DM_POLICY_ALLOWLIST);

    ASSERT_STR_EQ(sc_dm_policy_to_str(SC_DM_POLICY_OPEN), "open");
    ASSERT_STR_EQ(sc_dm_policy_to_str(SC_DM_POLICY_ALLOWLIST), "allowlist");
    ASSERT_STR_EQ(sc_dm_policy_to_str(SC_DM_POLICY_PAIRING), "pairing");
}

static void test_challenge_basic(void)
{
    char tmpdir[] = "/tmp/sc_test_pairing_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_pairing_store_t *ps = sc_pairing_store_new("test", tmpdir);
    ASSERT_NOT_NULL(ps);

    const char *code = sc_pairing_store_challenge(ps, "user123");
    ASSERT_NOT_NULL(code);
    ASSERT_INT_EQ((int)strlen(code), SC_PAIRING_CODE_LEN);

    /* Verify code chars are from the expected alphabet */
    const char *alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    for (int i = 0; i < SC_PAIRING_CODE_LEN; i++) {
        ASSERT(strchr(alpha, code[i]) != NULL, "code char in alphabet");
    }

    sc_pairing_store_free(ps);

    /* Cleanup */
    char path[512];
    snprintf(path, sizeof(path), "%s/test.json", tmpdir);
    remove(path);
    rmdir(tmpdir);
}

static void test_same_sender_same_code(void)
{
    char tmpdir[] = "/tmp/sc_test_pairing_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_pairing_store_t *ps = sc_pairing_store_new("test", tmpdir);
    ASSERT_NOT_NULL(ps);

    const char *code1 = sc_pairing_store_challenge(ps, "user456");
    ASSERT_NOT_NULL(code1);

    /* Copy since pointer may be invalidated by internal realloc */
    char saved[SC_PAIRING_CODE_LEN + 1];
    memcpy(saved, code1, SC_PAIRING_CODE_LEN + 1);

    const char *code2 = sc_pairing_store_challenge(ps, "user456");
    ASSERT_NOT_NULL(code2);
    ASSERT_STR_EQ(saved, code2);

    sc_pairing_store_free(ps);

    char path[512];
    snprintf(path, sizeof(path), "%s/test.json", tmpdir);
    remove(path);
    rmdir(tmpdir);
}

static void test_approve_valid(void)
{
    char tmpdir[] = "/tmp/sc_test_pairing_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_pairing_store_t *ps = sc_pairing_store_new("test", tmpdir);
    ASSERT_NOT_NULL(ps);

    const char *code = sc_pairing_store_challenge(ps, "user789");
    ASSERT_NOT_NULL(code);

    char code_copy[SC_PAIRING_CODE_LEN + 1];
    memcpy(code_copy, code, SC_PAIRING_CODE_LEN + 1);

    char *sender = sc_pairing_store_approve(ps, code_copy);
    ASSERT_NOT_NULL(sender);
    ASSERT_STR_EQ(sender, "user789");
    free(sender);

    /* Should be removed now */
    sc_pairing_request_t *reqs;
    int count = sc_pairing_store_list(ps, &reqs);
    ASSERT_INT_EQ(count, 0);

    sc_pairing_store_free(ps);

    char path[512];
    snprintf(path, sizeof(path), "%s/test.json", tmpdir);
    remove(path);
    rmdir(tmpdir);
}

static void test_approve_invalid(void)
{
    char tmpdir[] = "/tmp/sc_test_pairing_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_pairing_store_t *ps = sc_pairing_store_new("test", tmpdir);
    ASSERT_NOT_NULL(ps);

    sc_pairing_store_challenge(ps, "userA");

    char *sender = sc_pairing_store_approve(ps, "ZZZZZZZZ");
    ASSERT_NULL(sender);

    sc_pairing_store_free(ps);

    char path[512];
    snprintf(path, sizeof(path), "%s/test.json", tmpdir);
    remove(path);
    rmdir(tmpdir);
}

static void test_max_pending(void)
{
    char tmpdir[] = "/tmp/sc_test_pairing_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_pairing_store_t *ps = sc_pairing_store_new("test", tmpdir);
    ASSERT_NOT_NULL(ps);

    /* Fill up to max */
    for (int i = 0; i < SC_PAIRING_MAX_PENDING; i++) {
        char sid[32];
        snprintf(sid, sizeof(sid), "sender%d", i);
        const char *code = sc_pairing_store_challenge(ps, sid);
        ASSERT_NOT_NULL(code);
    }

    /* One more should fail */
    const char *code = sc_pairing_store_challenge(ps, "sender_overflow");
    ASSERT_NULL(code);

    sc_pairing_store_free(ps);

    char path[512];
    snprintf(path, sizeof(path), "%s/test.json", tmpdir);
    remove(path);
    rmdir(tmpdir);
}

static void test_persistence(void)
{
    char tmpdir[] = "/tmp/sc_test_pairing_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    /* Create store, add challenges */
    sc_pairing_store_t *ps1 = sc_pairing_store_new("persist", tmpdir);
    ASSERT_NOT_NULL(ps1);

    const char *code_a = sc_pairing_store_challenge(ps1, "alice");
    ASSERT_NOT_NULL(code_a);
    char saved_a[SC_PAIRING_CODE_LEN + 1];
    memcpy(saved_a, code_a, SC_PAIRING_CODE_LEN + 1);

    const char *code_b = sc_pairing_store_challenge(ps1, "bob");
    ASSERT_NOT_NULL(code_b);
    char saved_b[SC_PAIRING_CODE_LEN + 1];
    memcpy(saved_b, code_b, SC_PAIRING_CODE_LEN + 1);

    sc_pairing_store_free(ps1);

    /* Re-open and verify data survived */
    sc_pairing_store_t *ps2 = sc_pairing_store_new("persist", tmpdir);
    ASSERT_NOT_NULL(ps2);

    sc_pairing_request_t *reqs;
    int count = sc_pairing_store_list(ps2, &reqs);
    ASSERT_INT_EQ(count, 2);

    /* Approve alice via saved code */
    char *sender = sc_pairing_store_approve(ps2, saved_a);
    ASSERT_NOT_NULL(sender);
    ASSERT_STR_EQ(sender, "alice");
    free(sender);

    /* bob should still be there */
    count = sc_pairing_store_list(ps2, &reqs);
    ASSERT_INT_EQ(count, 1);
    ASSERT_STR_EQ(reqs[0].sender_id, "bob");
    ASSERT_STR_EQ(reqs[0].code, saved_b);

    sc_pairing_store_free(ps2);

    char path[512];
    snprintf(path, sizeof(path), "%s/persist.json", tmpdir);
    remove(path);
    rmdir(tmpdir);
}

static void test_expiry(void)
{
    char tmpdir[] = "/tmp/sc_test_pairing_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_pairing_store_t *ps = sc_pairing_store_new("test", tmpdir);
    ASSERT_NOT_NULL(ps);

    /* Create a challenge for user1 */
    const char *code1 = sc_pairing_store_challenge(ps, "user_old");
    ASSERT_NOT_NULL(code1);

    /* Backdate the request's created_ms so it looks expired.
     * sc_pairing_store_list returns a pointer to the internal array. */
    sc_pairing_request_t *reqs;
    int count = sc_pairing_store_list(ps, &reqs);
    ASSERT_INT_EQ(count, 1);
    reqs[0].created_ms = 0; /* epoch — well past the 1-hour expiry */

    /* Now create another challenge — this triggers prune_expired() internally */
    const char *code2 = sc_pairing_store_challenge(ps, "user_new");
    ASSERT_NOT_NULL(code2);

    /* The old request should have been pruned, only the new one remains */
    count = sc_pairing_store_list(ps, &reqs);
    ASSERT_INT_EQ(count, 1);
    ASSERT_STR_EQ(reqs[0].sender_id, "user_new");

    sc_pairing_store_free(ps);

    char path[512];
    snprintf(path, sizeof(path), "%s/test.json", tmpdir);
    remove(path);
    rmdir(tmpdir);
}

int main(void)
{
    printf("test_pairing\n");

    RUN_TEST(test_policy_roundtrip);
    RUN_TEST(test_challenge_basic);
    RUN_TEST(test_same_sender_same_code);
    RUN_TEST(test_approve_valid);
    RUN_TEST(test_approve_invalid);
    RUN_TEST(test_max_pending);
    RUN_TEST(test_persistence);
    RUN_TEST(test_expiry);

    TEST_REPORT();
}
