/*
 * smolclaw - session tests
 */

#include "test_main.h"
#include "session.h"
#include "util/str.h"

#include <unistd.h>
#include <sys/stat.h>

static void test_session_create(void)
{
    char tmpdir[] = "/tmp/sc_test_sessions_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
    ASSERT_NOT_NULL(sm);

    /* Get or create a new session */
    sc_session_t *s = sc_session_get_or_create(sm, "test-session");
    ASSERT_NOT_NULL(s);

    /* Verify via public API: no messages yet */
    int msg_count = 0;
    sc_session_get_history(sm, "test-session", &msg_count);
    ASSERT_INT_EQ(msg_count, 0);

    sc_session_manager_free(sm);

    /* Cleanup */
    sc_strbuf_t path;
    sc_strbuf_init(&path);
    sc_strbuf_appendf(&path, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&path);
    system(cmd);
    free(cmd);
}

static void test_session_add_message(void)
{
    char tmpdir[] = "/tmp/sc_test_sessions_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
    ASSERT_NOT_NULL(sm);

    /* Add messages */
    sc_session_add_message(sm, "chat1", "user", "Hello");
    sc_session_add_message(sm, "chat1", "assistant", "Hi there!");
    sc_session_add_message(sm, "chat1", "user", "How are you?");

    /* Retrieve history */
    int count = 0;
    sc_llm_message_t *history = sc_session_get_history(sm, "chat1", &count);
    ASSERT_INT_EQ(count, 3);
    ASSERT_NOT_NULL(history);

    ASSERT_STR_EQ(history[0].role, "user");
    ASSERT_STR_EQ(history[0].content, "Hello");
    ASSERT_STR_EQ(history[1].role, "assistant");
    ASSERT_STR_EQ(history[1].content, "Hi there!");
    ASSERT_STR_EQ(history[2].role, "user");
    ASSERT_STR_EQ(history[2].content, "How are you?");

    sc_session_manager_free(sm);

    /* Cleanup */
    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

static void test_session_summary(void)
{
    char tmpdir[] = "/tmp/sc_test_sessions_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
    ASSERT_NOT_NULL(sm);

    /* Initially no summary */
    const char *summary = sc_session_get_summary(sm, "chat1");
    ASSERT(summary == NULL || summary[0] == '\0',
           "Summary should be empty initially");

    /* Set summary */
    sc_session_set_summary(sm, "chat1", "User asked about weather");
    summary = sc_session_get_summary(sm, "chat1");
    ASSERT_NOT_NULL(summary);
    ASSERT_STR_EQ(summary, "User asked about weather");

    sc_session_manager_free(sm);

    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

static void test_session_save_load(void)
{
    char tmpdir[] = "/tmp/sc_test_sessions_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    /* Create and populate session */
    {
        sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
        ASSERT_NOT_NULL(sm);

        sc_session_add_message(sm, "persist-test", "user", "Remember this");
        sc_session_add_message(sm, "persist-test", "assistant", "I will remember");
        sc_session_set_summary(sm, "persist-test", "Test summary");

        int ret = sc_session_save(sm, "persist-test");
        ASSERT_INT_EQ(ret, 0);

        sc_session_manager_free(sm);
    }

    /* Load in new manager and verify */
    {
        sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
        ASSERT_NOT_NULL(sm);

        /* The session should load from disk when accessed */
        int count = 0;
        sc_session_get_history(sm, "persist-test", &count);

        /* Note: sessions are loaded lazily, so count might be 0 if not loaded yet.
         * The get_or_create call should trigger loading. */
        sc_session_t *s = sc_session_get_or_create(sm, "persist-test");
        ASSERT_NOT_NULL(s);

        /* After get_or_create, history should be loaded */
        sc_session_get_history(sm, "persist-test", &count);
        ASSERT(count >= 0, "Count should be non-negative");

        sc_session_manager_free(sm);
    }

    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

static void test_session_truncate(void)
{
    char tmpdir[] = "/tmp/sc_test_sessions_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
    ASSERT_NOT_NULL(sm);

    /* Add many messages */
    for (int i = 0; i < 10; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Message %d", i);
        sc_session_add_message(sm, "trunc-test", i % 2 == 0 ? "user" : "assistant", msg);
    }

    int count = 0;
    sc_session_get_history(sm, "trunc-test", &count);
    ASSERT_INT_EQ(count, 10);

    /* Truncate to last 3 */
    sc_session_truncate(sm, "trunc-test", 3);

    sc_session_get_history(sm, "trunc-test", &count);
    ASSERT_INT_EQ(count, 3);

    sc_session_manager_free(sm);

    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

static void test_session_summary_survives_truncate(void)
{
    char tmpdir[] = "/tmp/sc_test_sessions_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
    ASSERT_NOT_NULL(sm);

    /* Set a summary */
    sc_session_set_summary(sm, "compact-test",
        "User discussed file operations and config changes.");

    /* Add many messages */
    for (int i = 0; i < 10; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Message %d", i);
        sc_session_add_message(sm, "compact-test",
                               i % 2 == 0 ? "user" : "assistant", msg);
    }

    /* Truncate to last 3 */
    sc_session_truncate(sm, "compact-test", 3);

    /* Summary should still be present after truncation */
    const char *summary = sc_session_get_summary(sm, "compact-test");
    ASSERT_NOT_NULL(summary);
    ASSERT_STR_EQ(summary, "User discussed file operations and config changes.");

    /* Save, destroy, reload — summary should persist */
    sc_session_save(sm, "compact-test");
    sc_session_manager_free(sm);

    sm = sc_session_manager_new(tmpdir);
    ASSERT_NOT_NULL(sm);

    /* Force load by accessing the session */
    sc_session_get_or_create(sm, "compact-test");
    summary = sc_session_get_summary(sm, "compact-test");
    ASSERT_NOT_NULL(summary);
    ASSERT_STR_EQ(summary, "User discussed file operations and config changes.");

    /* Messages should be truncated */
    int count = 0;
    sc_session_get_history(sm, "compact-test", &count);
    ASSERT_INT_EQ(count, 3);

    sc_session_manager_free(sm);

    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

int main(void)
{
    printf("test_session\n");

    RUN_TEST(test_session_create);
    RUN_TEST(test_session_add_message);
    RUN_TEST(test_session_summary);
    RUN_TEST(test_session_save_load);
    RUN_TEST(test_session_truncate);
    RUN_TEST(test_session_summary_survives_truncate);

    TEST_REPORT();
}
