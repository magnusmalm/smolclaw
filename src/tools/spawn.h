#ifndef SC_TOOL_SPAWN_H
#define SC_TOOL_SPAWN_H

#include "tools/types.h"

/* Forward declaration */
typedef struct sc_agent sc_agent_t;

sc_tool_t *sc_tool_spawn_new(sc_agent_t *parent_agent);

/* Current spawn depth (thread-local, 0 = top-level agent) */
int sc_spawn_get_depth(void);

/* True if `tool` is denied for a subagent running at `depth` (0 = top-level,
 * nothing denied). depth>=1 blocks escalation tools (spawn/delegate/cron);
 * depth>=2 additionally blocks notify/converse/background. */
int sc_spawn_tool_denied_at_depth(const char *tool, int depth);

#endif /* SC_TOOL_SPAWN_H */
