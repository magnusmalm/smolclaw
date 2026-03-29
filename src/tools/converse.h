#ifndef SC_TOOL_CONVERSE_H
#define SC_TOOL_CONVERSE_H

#include "tools/types.h"
#include "config.h"

/*
 * Multi-turn conversation tool: two remote agents debate a topic.
 * Alternates messages between agent_a and agent_b for N rounds,
 * using session continuity on each side. Returns the full transcript.
 */
sc_tool_t *sc_tool_converse_new(sc_delegation_config_t *cfg,
                                 const char *workspace);

#endif /* SC_TOOL_CONVERSE_H */
