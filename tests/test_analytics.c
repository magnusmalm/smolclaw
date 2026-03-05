/*
 * test_analytics.c - Tests for SQLite analytics
 */

#include "test_main.h"
#include "analytics.h"

#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static const char *TEST_WS = "/tmp/test_smolclaw_analytics";

static void setup(void)
{
    mkdir(TEST_WS, 0755);
    char state_dir[256];
    snprintf(state_dir, sizeof(state_dir), "%s/state", TEST_WS);
    mkdir(state_dir, 0755);

    /* Remove existing DB */
    char db_path[256];
    snprintf(db_path, sizeof(db_path), "%s/state/analytics.db", TEST_WS);
    unlink(db_path);
    /* Also remove WAL/SHM */
    char wal[270], shm[270];
    snprintf(wal, sizeof(wal), "%s-wal", db_path);
    snprintf(shm, sizeof(shm), "%s-shm", db_path);
    unlink(wal);
    unlink(shm);
}

static void test_analytics_new(void)
{
    setup();
    sc_analytics_t *a = sc_analytics_new(TEST_WS);
    ASSERT_NOT_NULL(a);

    /* DB file should exist */
    char db_path[256];
    snprintf(db_path, sizeof(db_path), "%s/state/analytics.db", TEST_WS);
    struct stat st;
    ASSERT(stat(db_path, &st) == 0, "analytics.db should exist");

    sc_analytics_free(a);
}

static void test_analytics_record_and_query(void)
{
    setup();
    sc_analytics_t *a = sc_analytics_new(TEST_WS);
    ASSERT_NOT_NULL(a);

    /* Record some turns */
    sc_analytics_record(a, "claude-sonnet", "sess1", "cli", 100, 50, 3, 1500);
    sc_analytics_record(a, "claude-sonnet", "sess1", "cli", 200, 80, 1, 2000);
    sc_analytics_record(a, "gpt-4o", "sess2", "telegram", 150, 60, 2, 1000);

    /* Summary should show totals */
    char *summary = sc_analytics_summary(a);
    ASSERT_NOT_NULL(summary);
    ASSERT(strstr(summary, "3") != NULL, "summary should show 3 turns");
    free(summary);

    /* Today should have data */
    char *today = sc_analytics_today(a);
    ASSERT_NOT_NULL(today);
    free(today);

    /* By model */
    char *by_model = sc_analytics_by_model(a, 30);
    ASSERT_NOT_NULL(by_model);
    ASSERT(strstr(by_model, "claude-sonnet") != NULL, "should show claude-sonnet");
    ASSERT(strstr(by_model, "gpt-4o") != NULL, "should show gpt-4o");
    free(by_model);

    /* By channel */
    char *by_channel = sc_analytics_by_channel(a, 30);
    ASSERT_NOT_NULL(by_channel);
    ASSERT(strstr(by_channel, "cli") != NULL, "should show cli channel");
    free(by_channel);

    /* Period */
    char *period = sc_analytics_period(a, 7);
    ASSERT_NOT_NULL(period);
    free(period);

    sc_analytics_free(a);
}

static void test_analytics_reset(void)
{
    setup();
    sc_analytics_t *a = sc_analytics_new(TEST_WS);
    ASSERT_NOT_NULL(a);

    sc_analytics_record(a, "claude", "s1", "cli", 100, 50, 0, 500);

    /* Reset should clear data */
    sc_analytics_reset(a);

    char *summary = sc_analytics_summary(a);
    ASSERT_NOT_NULL(summary);
    /* After reset, turns count should be 0 */
    ASSERT(strstr(summary, "0") != NULL, "should show 0 turns after reset");
    free(summary);

    sc_analytics_free(a);
}

static void test_analytics_null_safety(void)
{
    /* NULL workspace */
    sc_analytics_t *a = sc_analytics_new(NULL);
    ASSERT_NULL(a);

    /* NULL analytics */
    sc_analytics_record(NULL, "model", "sess", "cli", 0, 0, 0, 0);
    sc_analytics_free(NULL);  /* should not crash */
}

int main(void)
{
    printf("test_analytics\n");
    RUN_TEST(test_analytics_new);
    RUN_TEST(test_analytics_record_and_query);
    RUN_TEST(test_analytics_reset);
    RUN_TEST(test_analytics_null_safety);
    TEST_REPORT();
}
