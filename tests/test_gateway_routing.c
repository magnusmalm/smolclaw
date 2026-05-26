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
        /* namespace_id */ "feedfacedeadbeef");
    ASSERT_NOT_NULL(out);

    sc_bus_publish_inbound(bus, out);
    /* After publish, the message belongs to the bus — do NOT touch `out`. */

    sc_inbound_msg_t *in = sc_bus_try_consume_inbound(bus);
    ASSERT_NOT_NULL(in);
    ASSERT_INT_EQ(in->isolated, 1);
    ASSERT_STR_EQ(in->namespace_id, "feedfacedeadbeef");
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
        /* namespace_id */ NULL);
    ASSERT_NOT_NULL(out);

    sc_bus_publish_inbound(bus, out);

    sc_inbound_msg_t *in = sc_bus_try_consume_inbound(bus);
    ASSERT_NOT_NULL(in);
    ASSERT_INT_EQ(in->isolated, 0);
    ASSERT_NULL(in->namespace_id);
    ASSERT_INT_EQ(sc_gateway_should_isolate(in), 0);

    sc_inbound_msg_free(in);
    sc_bus_destroy(bus);
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
    TEST_REPORT();
}
