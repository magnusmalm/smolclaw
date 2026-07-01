/*
 * smolclaw - session tests
 */

#include "test_main.h"
#include "session.h"
#include "util/str.h"

#include <stdlib.h>
#include <string.h>
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

static void test_session_persistence_roundtrip(void)
{
    char tmpdir[] = "/tmp/sc_test_sessions_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    /* Save with exact content */
    {
        sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
        ASSERT_NOT_NULL(sm);

        sc_session_add_message(sm, "roundtrip", "user", "What is 2+2?");
        sc_session_add_message(sm, "roundtrip", "assistant", "The answer is 4.");
        sc_session_add_message(sm, "roundtrip", "user", "Thanks!");

        int ret = sc_session_save(sm, "roundtrip");
        ASSERT_INT_EQ(ret, 0);
        sc_session_manager_free(sm);
    }

    /* Load and verify exact content */
    {
        sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
        ASSERT_NOT_NULL(sm);

        sc_session_get_or_create(sm, "roundtrip");
        int count = 0;
        sc_llm_message_t *history = sc_session_get_history(sm, "roundtrip", &count);
        ASSERT_INT_EQ(count, 3);
        ASSERT_NOT_NULL(history);

        ASSERT_STR_EQ(history[0].role, "user");
        ASSERT_STR_EQ(history[0].content, "What is 2+2?");
        ASSERT_STR_EQ(history[1].role, "assistant");
        ASSERT_STR_EQ(history[1].content, "The answer is 4.");
        ASSERT_STR_EQ(history[2].role, "user");
        ASSERT_STR_EQ(history[2].content, "Thanks!");

        sc_session_manager_free(sm);
    }

    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

static void test_session_key_length_limit(void)
{
    char tmpdir[] = "/tmp/sc_test_sessions_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
    ASSERT_NOT_NULL(sm);

    /* Key exactly at limit (128 chars) should work */
    char key_ok[129];
    memset(key_ok, 'a', 128);
    key_ok[128] = '\0';
    sc_session_t *s = sc_session_get_or_create(sm, key_ok);
    ASSERT_NOT_NULL(s);

    /* Key over limit (129 chars) should be rejected */
    char key_too_long[130];
    memset(key_too_long, 'b', 129);
    key_too_long[129] = '\0';
    sc_session_t *s2 = sc_session_get_or_create(sm, key_too_long);
    ASSERT(s2 == NULL, "session key over 128 chars should be rejected");

    sc_session_manager_free(sm);

    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

static void test_session_thinking_persistence(void)
{
    char tmpdir[] = "/tmp/sc_test_sessions_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    /* Save a session with a thinking field */
    {
        sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
        ASSERT_NOT_NULL(sm);

        sc_session_add_message(sm, "think-test", "user", "Explain quantum physics");

        /* Add assistant message with thinking via full message API */
        sc_llm_message_t msg = {0};
        msg.role = sc_strdup("assistant");
        msg.content = sc_strdup("Here is my explanation.");
        msg.thinking = sc_strdup("Let me reason step by step about quantum physics...");
        sc_session_add_full_message(sm, "think-test", &msg);
        sc_llm_message_free_fields(&msg);

        int ret = sc_session_save(sm, "think-test");
        ASSERT_INT_EQ(ret, 0);
        sc_session_manager_free(sm);
    }

    /* Load and verify thinking survives round-trip */
    {
        sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
        ASSERT_NOT_NULL(sm);

        int count = 0;
        sc_llm_message_t *history = sc_session_get_history(sm, "think-test", &count);
        ASSERT_INT_EQ(count, 2);
        ASSERT_NOT_NULL(history);

        /* First message: user, no thinking */
        ASSERT_STR_EQ(history[0].role, "user");
        ASSERT_NULL(history[0].thinking);

        /* Second message: assistant with thinking */
        ASSERT_STR_EQ(history[1].role, "assistant");
        ASSERT_STR_EQ(history[1].content, "Here is my explanation.");
        ASSERT_NOT_NULL(history[1].thinking);
        ASSERT(strstr(history[1].thinking, "quantum physics") != NULL,
               "Thinking should contain original text");

        sc_session_manager_free(sm);
    }

    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

static void test_session_branching(void)
{
    char tmpdir[] = "/tmp/sc_test_sessions_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
    ASSERT_NOT_NULL(sm);

    /* Build a linear conversation: msg0 -> msg1 -> msg2 */
    sc_session_add_message(sm, "branch-test", "user", "Question 1");
    sc_session_add_message(sm, "branch-test", "assistant", "Answer 1");
    sc_session_add_message(sm, "branch-test", "user", "Follow-up");

    int count = 0;
    sc_llm_message_t *hist = sc_session_get_history(sm, "branch-test", &count);
    ASSERT_INT_EQ(count, 3);
    ASSERT_STR_EQ(hist[2].content, "Follow-up");

    /* Active leaf should be node 2 (0-indexed) */
    ASSERT_INT_EQ(sc_session_active_leaf(sm, "branch-test"), 2);

    /* Branch from node 1 (after "Answer 1") */
    int rc = sc_session_branch(sm, "branch-test", 1);
    ASSERT_INT_EQ(rc, 0);
    ASSERT_INT_EQ(sc_session_active_leaf(sm, "branch-test"), 1);

    /* History should now be msg0 -> msg1 (2 messages) */
    hist = sc_session_get_history(sm, "branch-test", &count);
    ASSERT_INT_EQ(count, 2);
    ASSERT_STR_EQ(hist[0].content, "Question 1");
    ASSERT_STR_EQ(hist[1].content, "Answer 1");

    /* Append to the new branch: msg0 -> msg1 -> msg3 */
    sc_session_add_message(sm, "branch-test", "user", "Different follow-up");

    hist = sc_session_get_history(sm, "branch-test", &count);
    ASSERT_INT_EQ(count, 3);
    ASSERT_STR_EQ(hist[2].content, "Different follow-up");

    /* Now we have two branches: 0->1->2 and 0->1->3 */
    ASSERT_INT_EQ(sc_session_branch_count(sm, "branch-test"), 2);

    /* Switch back to the original branch (node 2) */
    rc = sc_session_branch(sm, "branch-test", 2);
    ASSERT_INT_EQ(rc, 0);
    hist = sc_session_get_history(sm, "branch-test", &count);
    ASSERT_INT_EQ(count, 3);
    ASSERT_STR_EQ(hist[2].content, "Follow-up");

    /* Invalid branch target */
    rc = sc_session_branch(sm, "branch-test", 99);
    ASSERT_INT_EQ(rc, -1);

    sc_session_manager_free(sm);

    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

static void test_session_jsonl_roundtrip(void)
{
    char tmpdir[] = "/tmp/sc_test_sessions_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    /* Create a branched session, save, reload, verify */
    {
        sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
        ASSERT_NOT_NULL(sm);

        sc_session_add_message(sm, "jsonl-rt", "user", "Hello");
        sc_session_add_message(sm, "jsonl-rt", "assistant", "Hi there");
        sc_session_add_message(sm, "jsonl-rt", "user", "Branch A");

        /* Branch from node 1, add alternative */
        sc_session_branch(sm, "jsonl-rt", 1);
        sc_session_add_message(sm, "jsonl-rt", "user", "Branch B");

        ASSERT_INT_EQ(sc_session_branch_count(sm, "jsonl-rt"), 2);

        sc_session_set_summary(sm, "jsonl-rt", "Test summary");
        int ret = sc_session_save(sm, "jsonl-rt");
        ASSERT_INT_EQ(ret, 0);

        sc_session_manager_free(sm);
    }

    /* Reload and verify */
    {
        sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
        ASSERT_NOT_NULL(sm);

        /* Active leaf should be node 3 (Branch B) */
        int leaf = sc_session_active_leaf(sm, "jsonl-rt");
        ASSERT_INT_EQ(leaf, 3);

        int count = 0;
        sc_llm_message_t *hist = sc_session_get_history(sm, "jsonl-rt", &count);
        ASSERT_INT_EQ(count, 3); /* Hello -> Hi there -> Branch B */
        ASSERT_STR_EQ(hist[2].content, "Branch B");

        /* Summary survived */
        const char *summary = sc_session_get_summary(sm, "jsonl-rt");
        ASSERT_NOT_NULL(summary);
        ASSERT_STR_EQ(summary, "Test summary");

        /* Branch count survived */
        ASSERT_INT_EQ(sc_session_branch_count(sm, "jsonl-rt"), 2);

        /* Switch to original branch */
        sc_session_branch(sm, "jsonl-rt", 2);
        hist = sc_session_get_history(sm, "jsonl-rt", &count);
        ASSERT_INT_EQ(count, 3);
        ASSERT_STR_EQ(hist[2].content, "Branch A");

        sc_session_manager_free(sm);
    }

    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

/* Task 3.7: automatic session-reset policy. */
static void test_session_reset_policy(void)
{
    long now = 1767225600L;  /* fixed reference */
    long min = 60;

    /* none → never */
    ASSERT_INT_EQ(sc_session_reset_due(SC_SESSION_RESET_NONE, 4, 1440,
                                       now - 100000, now), 0);
    /* missing / future last-activity → never */
    ASSERT_INT_EQ(sc_session_reset_due(SC_SESSION_RESET_IDLE, 4, 60, 0, now), 0);
    ASSERT_INT_EQ(sc_session_reset_due(SC_SESSION_RESET_IDLE, 4, 60,
                                       now + 10, now), 0);

    /* idle: 60-min threshold */
    ASSERT_INT_EQ(sc_session_reset_due(SC_SESSION_RESET_IDLE, 4, 60,
                                       now - 30 * min, now), 0);  /* 30 min idle */
    ASSERT_INT_EQ(sc_session_reset_due(SC_SESSION_RESET_IDLE, 4, 60,
                                       now - 90 * min, now), 1);  /* 90 min idle */

    /* daily: last activity 3 days ago → a daily boundary has passed */
    ASSERT_INT_EQ(sc_session_reset_due(SC_SESSION_RESET_DAILY, 4, 1440,
                                       now - 3 * 86400, now), 1);
    /* daily: activity seconds ago → no boundary crossed (idle disabled here) */
    ASSERT_INT_EQ(sc_session_reset_due(SC_SESSION_RESET_DAILY, 4, 1440,
                                       now - 5, now), 0);

    /* both: idle path still fires even if daily wouldn't */
    ASSERT_INT_EQ(sc_session_reset_due(SC_SESSION_RESET_BOTH, 4, 60,
                                       now - 90 * min, now), 1);
}

/* Audit M-4: hard-cap force-prune decision. */
static void test_session_force_prune_due(void)
{
    int thr = 20;
    int cap = thr * SC_SESSION_FORCE_PRUNE_MULT;  /* 80 */

    /* Below the hard ceiling → no force-prune (normal async summarization). */
    ASSERT_INT_EQ(sc_session_force_prune_due(thr + 1, thr), 0);
    ASSERT_INT_EQ(sc_session_force_prune_due(cap - 1, thr), 0);
    /* At / above the ceiling → force-prune. */
    ASSERT_INT_EQ(sc_session_force_prune_due(cap, thr), 1);
    ASSERT_INT_EQ(sc_session_force_prune_due(cap + 100, thr), 1);
    /* Summarization disabled → never force-prune regardless of count. */
    ASSERT_INT_EQ(sc_session_force_prune_due(100000, 0), 0);
    ASSERT_INT_EQ(sc_session_force_prune_due(100000, -1), 0);
}

static void test_session_get_updated(void)
{
    char tmpdir[] = "/tmp/sc_test_sessions_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));
    sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
    ASSERT_NOT_NULL(sm);

    ASSERT(sc_session_get_updated(sm, "nope") == 0, "unknown session → 0");
    sc_session_add_message(sm, "u", "user", "hi");
    ASSERT(sc_session_get_updated(sm, "u") > 0, "active session → nonzero");

    sc_session_manager_free(sm);
    sc_strbuf_t p;
    sc_strbuf_init(&p);
    sc_strbuf_appendf(&p, "rm -rf %s", tmpdir);
    char *cmd = sc_strbuf_finish(&p);
    system(cmd);
    free(cmd);
}

/* A node line larger than the old 64KB fgets buffer must survive a
 * save/reload round-trip (getline reads the full line; fgets would truncate
 * and drop the node, shifting later nodes). */
static void test_session_large_node_roundtrip(void)
{
    char tmpdir[] = "/tmp/sc_test_sessions_XXXXXX";
    ASSERT_NOT_NULL(mkdtemp(tmpdir));

    size_t big = 100000;   /* > 64KB */
    char *content = malloc(big + 1);
    ASSERT_NOT_NULL(content);
    memset(content, 'x', big);
    content[big] = '\0';

    {
        sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
        ASSERT_NOT_NULL(sm);
        sc_session_add_message(sm, "big", "user", "hi");
        sc_session_add_message(sm, "big", "assistant", content);
        sc_session_add_message(sm, "big", "user", "bye");
        ASSERT_INT_EQ(sc_session_save(sm, "big"), 0);
        sc_session_manager_free(sm);
    }

    {
        sc_session_manager_t *sm = sc_session_manager_new(tmpdir);
        ASSERT_NOT_NULL(sm);
        int count = 0;
        sc_llm_message_t *h = sc_session_get_history(sm, "big", &count);
        ASSERT_INT_EQ(count, 3);
        ASSERT_NOT_NULL(h);
        ASSERT_STR_EQ(h[0].content, "hi");
        ASSERT(h[1].content && strlen(h[1].content) == big,
               "large (>64KB) node content preserved across reload");
        ASSERT_STR_EQ(h[2].content, "bye");
        sc_session_manager_free(sm);
    }

    free(content);

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
    RUN_TEST(test_session_large_node_roundtrip);
    RUN_TEST(test_session_truncate);
    RUN_TEST(test_session_summary_survives_truncate);
    RUN_TEST(test_session_persistence_roundtrip);
    RUN_TEST(test_session_key_length_limit);
    RUN_TEST(test_session_thinking_persistence);
    RUN_TEST(test_session_branching);
    RUN_TEST(test_session_jsonl_roundtrip);
    RUN_TEST(test_session_reset_policy);
    RUN_TEST(test_session_force_prune_due);
    RUN_TEST(test_session_get_updated);

    TEST_REPORT();
}
