#ifndef SC_GATEWAY_ROUTE_H
#define SC_GATEWAY_ROUTE_H

#include "bus.h"

/* Decide whether an inbound message should be routed to the isolated agent
 * path (sc_agent_process_isolated) instead of the shared path
 * (sc_agent_process_channel).
 *
 * Returns 1 iff msg->isolated is set AND msg->namespace_id is non-NULL and
 * non-empty. Returns 0 in all other cases, including for NULL msg.
 *
 * The empty/NULL-namespace guard is the safety net: isolation without a
 * namespace is meaningless, and the shared path is the safe fallback.
 *
 * Exposed in a header so tests/test_gateway_routing.c can exercise the
 * decision without needing to invoke gateway_process_message (which pulls
 * in the full agent, channels, and typing-thread machinery). The Stage-4
 * follow-up bug (gateway dropping the isolated flag, fixed in 7226204)
 * slipped past test_session_isolation.c precisely because the decision
 * lived inline in main.c with no test surface.
 */
static inline int sc_gateway_should_isolate(const sc_inbound_msg_t *msg)
{
    return msg && msg->isolated
        && msg->namespace_id && msg->namespace_id[0];
}

#endif /* SC_GATEWAY_ROUTE_H */
