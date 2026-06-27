/*
 * tools/compact.c - Agent-initiated session compaction (task 4.12)
 *
 * Registers a `compact` tool the agent can call mid-workflow to summarize and
 * shrink the current session. It routes through sc_agent_compact_session()
 * (the same path as the /compress slash command), guarded by a cooldown and a
 * budget check. Complements Phase 1's automatic compaction (reactive) with an
 * explicit, agent-driven option.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "tools/compact.h"
#include "tools/types.h"
#include "util/json_helpers.h"
#include "agent.h"
#include "session.h"
#include "logger.h"
#include "cJSON.h"

typedef struct {
    sc_agent_t *agent;   /* borrowed — not owned */
} compact_data_t;

static void compact_destroy(sc_tool_t *self)
{
    if (!self) return;
    free(self->data);
    free(self);
}

static cJSON *compact_parameters(sc_tool_t *self)
{
    (void)self;
    /* No parameters — compacts the current session. */
    return sc_schema_new();
}

static sc_tool_result_t *compact_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)args; (void)ctx;
    compact_data_t *d = self->data;
    if (!d || !d->agent)
        return sc_tool_result_error("compact tool not initialized");

    sc_agent_t *agent = d->agent;
    const char *sk = agent->active_session_key;
    if (!sk || !sk[0])
        return sc_tool_result_error("no active session to compact");

    /* Budget guard: refuse when the session is already small. */
    int count = 0;
    sc_session_get_history(agent->sessions, sk, &count);
    if (count <= agent->session_keep_last)
        return sc_tool_result_new(
            "Session is already compact; no summarization needed.");

    /* Cooldown guard: rate-limit agent-requested compactions. */
    long now = (long)time(NULL);
    if (!sc_compact_cooldown_ok(now, agent->last_compact_time,
                                agent->compact_cooldown_secs)) {
        long wait = (long)agent->compact_cooldown_secs - (now - agent->last_compact_time);
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "Compaction on cooldown; try again in ~%lds.", wait > 0 ? wait : 0);
        return sc_tool_result_new(msg);
    }

    if (sc_agent_compact_session(agent, sk) != 0)
        return sc_tool_result_new("Nothing to compact.");

    agent->last_compact_time = now;
    SC_LOG_INFO("compact", "Agent-initiated compaction of session '%s'", sk);
    return sc_tool_result_new(
        "Session compaction scheduled: older messages are being summarized; "
        "recent turns, scratchpad, and action log are preserved.");
}

sc_tool_t *sc_tool_compact_new(sc_agent_t *agent)
{
    if (!agent) return NULL;

    compact_data_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->agent = agent;

    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) { free(d); return NULL; }

    t->name = "compact";
    t->description =
        "Summarize and compact the current conversation to free context space. "
        "Use this proactively when the session has grown long and older details "
        "are no longer needed verbatim. Recent turns, your scratchpad, and the "
        "action log are preserved. Subject to a cooldown.";
    t->parameters = compact_parameters;
    t->execute = compact_execute;
    t->destroy = compact_destroy;
    t->needs_confirm = 0;
    t->data = d;
    return t;
}
