/*
 * smolclaw — Stage-4 follow-up: gateway routing tests.
 *
 * Locks in the decision that gateway_process_message (src/main.c) uses to
 * pick between sc_agent_process_isolated and sc_agent_process_channel. The
 * decision is extracted as a one-liner in gateway_route.h so we can unit-
 * test it without dragging in the agent + channels + typing-thread setup.
 *
 * Why this file exists: the 2026-05-25 acceptance run surfaced a bug where
 * gateway_process_message always called sc_agent_process_channel, dropping
 * the web channel's isolation flag. test_session_isolation.c didn't catch
 * it because it calls sc_agent_process_isolated directly. The fix landed
 * in commit 7226204; this test prevents regression.
 *
 * Bus round-trip cases prove the flag and namespace_id survive
 * sc_bus_publish_inbound + sc_bus_try_consume_inbound intact, which is the
 * other half of the original integration concern ("bus -> gateway ->
 * process_channel path was untested").
 */

#include "test_main.h"

#include "bus.h"
#include "gateway_route.h"

#include <stddef.h>

/* ---- Pure decision-helper truth table ------------------------------- */

static void test_isolated_with_namespace_routes_isolated(void)
{
    sc_inbound_msg_t msg = {0};
    msg.isolated     = 1;
    msg.namespace_id = (char *)"abc1234567890def";
    ASSERT_INT_EQ(sc_gateway_should_isolate(&msg), 1);
}

static void test_isolated_with_null_namespace_falls_back_to_shared(void)
{
    /* Safety net: isolation requested but no namespace -> shared path.
     * Anything else would consolidate into "the NULL namespace", which
     * is a recipe for cross-session leakage. */
    sc_inbound_msg_t msg = {0};
    msg.isolated     = 1;
    msg.namespace_id = NULL;
    ASSERT_INT_EQ(sc_gateway_should_isolate(&msg), 0);
}

static void test_isolated_with_empty_namespace_falls_back_to_shared(void)
{
    sc_inbound_msg_t msg = {0};
    msg.isolated     = 1;
    msg.namespace_id = (char *)"";
    ASSERT_INT_EQ(sc_gateway_should_isolate(&msg), 0);
}

static void test_not_isolated_with_namespace_uses_shared(void)
{
    /* A stale namespace_id on a non-isolated message must NOT promote it
     * to the isolated path. Only the isolated flag is authoritative. */
    sc_inbound_msg_t msg = {0};
    msg.isolated     = 0;
    msg.namespace_id = (char *)"abc1234567890def";
    ASSERT_INT_EQ(sc_gateway_should_isolate(&msg), 0);
}

static void test_not_isolated_with_null_namespace_uses_shared(void)
{
    sc_inbound_msg_t msg = {0};
    msg.isolated     = 0;
    msg.namespace_id = NULL;
    ASSERT_INT_EQ(sc_gateway_should_isolate(&msg), 0);
}

static void test_null_message_is_not_isolated(void)
{
    ASSERT_INT_EQ(sc_gateway_should_isolate(NULL), 0);
}

/* ---- Bus round-trip: flag + namespace must survive publish/consume -- */

static void test_bus_preserves_isolation_flag(void)
{
    /* sc_bus_create accepts a NULL event_base — only outbound watching
     * needs one (bus.c:156-163). We use only inbound publish/consume so
     * the test stays free of libevent setup. */
    sc_bus_t *bus = sc_bus_create(NULL);
    ASSERT_NOT_NULL(bus);

    sc_inbound_msg_t *out = sc_inbound_msg_new(
        "web", "sender-x", "chat-y", "hello",
        "wf-test-key", NULL,
        /* isolated */ 1,
        /* namespace_id */ "feedfacedeadbeef",
        /* run_repo_dir */ NULL);
    ASSERT_NOT_NULL(out);

    sc_bus_publish_inbound(bus, out);
    /* After publish, the message belongs to the bus — do NOT touch `out`. */

    sc_inbound_msg_t *in = sc_bus_try_consume_inbound(bus);
    ASSERT_NOT_NULL(in);
    ASSERT_INT_EQ(in->isolated, 1);
    ASSERT_STR_EQ(in->namespace_id, "feedfacedeadbeef");
    ASSERT_NULL(in->run_repo_dir);
    ASSERT_STR_EQ(in->channel,      "web");
    ASSERT_STR_EQ(in->session_key,  "wf-test-key");
    ASSERT_INT_EQ(sc_gateway_should_isolate(in), 1);

    sc_inbound_msg_free(in);
    sc_bus_destroy(bus);
}

static void test_bus_preserves_shared_message(void)
{
    sc_bus_t *bus = sc_bus_create(NULL);
    ASSERT_NOT_NULL(bus);

    sc_inbound_msg_t *out = sc_inbound_msg_new(
        "telegram", "user-1", "chat-1", "hi",
        "tg:user-1", NULL,
        /* isolated */ 0,
        /* namespace_id */ NULL,
        /* run_repo_dir */ NULL);
    ASSERT_NOT_NULL(out);

    sc_bus_publish_inbound(bus, out);

    sc_inbound_msg_t *in = sc_bus_try_consume_inbound(bus);
    ASSERT_NOT_NULL(in);
    ASSERT_INT_EQ(in->isolated, 0);
    ASSERT_NULL(in->namespace_id);
    ASSERT_NULL(in->run_repo_dir);
    ASSERT_INT_EQ(sc_gateway_should_isolate(in), 0);

    sc_inbound_msg_free(in);
    sc_bus_destroy(bus);
}

/* ---- Phase 5: run_repo_dir safety check truth table ---------------- */

static void test_run_repo_dir_safe_accepts_normal_paths(void)
{
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe("runs/abc/repo"), 1);
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe("a"), 1);
    /* Segment-aware: ".." inside a name is fine, only a bare ".." segment
     * is path traversal. */
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe("runs/abc..def/x"), 1);
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe("foo..bar"), 1);
}

static void test_run_repo_dir_safe_rejects_null_and_empty(void)
{
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe(NULL), 0);
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe(""), 0);
}

static void test_run_repo_dir_safe_rejects_absolute(void)
{
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe("/etc/passwd"), 0);
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe("/"), 0);
}

static void test_run_repo_dir_safe_rejects_path_traversal(void)
{
    /* Bare ".." segment in any position. */
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe(".."), 0);
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe("../etc"), 0);
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe("runs/../etc"), 0);
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe("runs/abc/.."), 0);
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe("a/b/../c"), 0);
}

static void test_run_repo_dir_safe_rejects_oversize(void)
{
    /* > 1024 bytes is rejected. The validator is called per-turn so the
     * cost matters; bound the work. */
    char big[1100];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe(big), 0);
}

static void test_bus_preserves_run_repo_dir(void)
{
    sc_bus_t *bus = sc_bus_create(NULL);
    ASSERT_NOT_NULL(bus);

    sc_inbound_msg_t *out = sc_inbound_msg_new(
        "web", "web", "rid-1", "hello",
        "wf-researcher-abc", NULL,
        /* isolated */ 1,
        /* namespace_id */ "ns1234567890abcd",
        /* run_repo_dir */ "runs/15a2b3c4d5/repo");
    ASSERT_NOT_NULL(out);

    sc_bus_publish_inbound(bus, out);

    sc_inbound_msg_t *in = sc_bus_try_consume_inbound(bus);
    ASSERT_NOT_NULL(in);
    ASSERT_STR_EQ(in->run_repo_dir, "runs/15a2b3c4d5/repo");
    ASSERT_INT_EQ(sc_gateway_run_repo_dir_safe(in->run_repo_dir), 1);
    /* Isolation + per-turn workspace narrowing are orthogonal but commonly
     * coexist (an orchestrator sends both for delegate calls). */
    ASSERT_INT_EQ(sc_gateway_should_isolate(in), 1);

    sc_inbound_msg_free(in);
    sc_bus_destroy(bus);
}

static void test_empty_run_repo_dir_stored_as_null(void)
{
    /* sc_inbound_msg_new should treat "" the same as NULL — no override.
     * This keeps the safety check at one layer (the gateway can rely on
     * NULL meaning "no override" without also testing for ""). */
    sc_inbound_msg_t *msg = sc_inbound_msg_new(
        "web", "web", "rid", "hi", "k", NULL,
        0, NULL, "");
    ASSERT_NOT_NULL(msg);
    ASSERT_NULL(msg->run_repo_dir);
    sc_inbound_msg_free(msg);
}

int main(void)
{
    printf("test_gateway_routing:\n");
    RUN_TEST(test_isolated_with_namespace_routes_isolated);
    RUN_TEST(test_isolated_with_null_namespace_falls_back_to_shared);
    RUN_TEST(test_isolated_with_empty_namespace_falls_back_to_shared);
    RUN_TEST(test_not_isolated_with_namespace_uses_shared);
    RUN_TEST(test_not_isolated_with_null_namespace_uses_shared);
    RUN_TEST(test_null_message_is_not_isolated);
    RUN_TEST(test_bus_preserves_isolation_flag);
    RUN_TEST(test_bus_preserves_shared_message);
    RUN_TEST(test_run_repo_dir_safe_accepts_normal_paths);
    RUN_TEST(test_run_repo_dir_safe_rejects_null_and_empty);
    RUN_TEST(test_run_repo_dir_safe_rejects_absolute);
    RUN_TEST(test_run_repo_dir_safe_rejects_path_traversal);
    RUN_TEST(test_run_repo_dir_safe_rejects_oversize);
    RUN_TEST(test_bus_preserves_run_repo_dir);
    RUN_TEST(test_empty_run_repo_dir_stored_as_null);
    TEST_REPORT();
}
