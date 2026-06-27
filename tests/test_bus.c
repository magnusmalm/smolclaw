/*
 * smolclaw - bus tests: queue-mode coalescing drain (task 3.8)
 */

#include "test_main.h"
#include "bus.h"

#include <event2/event.h>
#include <stdlib.h>
#include <string.h>

static sc_inbound_msg_t *mk(const char *chan, const char *chat, const char *content)
{
    return sc_inbound_msg_new(chan, "sender", chat, content, "sess",
                              NULL, 0, NULL, NULL);
}

static void test_drain_inbound_matching(void)
{
    struct event_base *base = event_base_new();
    ASSERT_NOT_NULL(base);
    sc_bus_t *bus = sc_bus_create(base);
    ASSERT_NOT_NULL(bus);

    /* Interleave two chats on the same channel plus a same-chat-id on another. */
    sc_bus_publish_inbound(bus, mk("tg", "A", "a1"));
    sc_bus_publish_inbound(bus, mk("tg", "B", "b1"));
    sc_bus_publish_inbound(bus, mk("tg", "A", "a2"));
    sc_bus_publish_inbound(bus, mk("discord", "A", "d1"));  /* same chat_id, diff channel */

    int n = 0;
    sc_inbound_msg_t **m = sc_bus_drain_inbound_matching(bus, "tg", "A", &n);
    ASSERT_INT_EQ(n, 2);
    ASSERT_STR_EQ(m[0]->content, "a1");   /* order preserved */
    ASSERT_STR_EQ(m[1]->content, "a2");
    for (int i = 0; i < n; i++) sc_inbound_msg_free(m[i]);
    free(m);

    /* Non-matching messages remain, in their original order. */
    sc_inbound_msg_t *r1 = sc_bus_try_consume_inbound(bus);
    ASSERT_NOT_NULL(r1);
    ASSERT_STR_EQ(r1->content, "b1");
    sc_inbound_msg_free(r1);

    sc_inbound_msg_t *r2 = sc_bus_try_consume_inbound(bus);
    ASSERT_NOT_NULL(r2);
    ASSERT_STR_EQ(r2->content, "d1");
    sc_inbound_msg_free(r2);

    sc_bus_destroy(bus);
    event_base_free(base);
}

static void test_drain_no_match(void)
{
    struct event_base *base = event_base_new();
    sc_bus_t *bus = sc_bus_create(base);
    ASSERT_NOT_NULL(bus);

    sc_bus_publish_inbound(bus, mk("tg", "X", "x1"));

    int n = -1;
    sc_inbound_msg_t **m = sc_bus_drain_inbound_matching(bus, "tg", "Y", &n);
    ASSERT_INT_EQ(n, 0);
    ASSERT_NULL(m);

    /* The unmatched message is still consumable. */
    sc_inbound_msg_t *r = sc_bus_try_consume_inbound(bus);
    ASSERT_NOT_NULL(r);
    ASSERT_STR_EQ(r->content, "x1");
    sc_inbound_msg_free(r);

    sc_bus_destroy(bus);
    event_base_free(base);
}

int main(void)
{
    printf("test_bus\n");

    RUN_TEST(test_drain_inbound_matching);
    RUN_TEST(test_drain_no_match);

    TEST_REPORT();
}
