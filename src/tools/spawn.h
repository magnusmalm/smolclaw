#ifndef SC_TOOL_SPAWN_H
#define SC_TOOL_SPAWN_H

#include "tools/types.h"

/* Forward declaration */
typedef struct sc_agent sc_agent_t;

sc_tool_t *sc_tool_spawn_new(sc_agent_t *parent_agent);

#endif /* SC_TOOL_SPAWN_H */
