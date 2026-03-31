#ifndef SC_TOOL_SPAWN_H
#define SC_TOOL_SPAWN_H

#include "tools/types.h"

/* Forward declaration */
typedef struct sc_agent sc_agent_t;

sc_tool_t *sc_tool_spawn_new(sc_agent_t *parent_agent);

/* Current spawn depth (thread-local, 0 = top-level agent) */
int sc_spawn_get_depth(void);

#endif /* SC_TOOL_SPAWN_H */
