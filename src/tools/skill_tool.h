#ifndef SC_TOOL_SKILL_H
#define SC_TOOL_SKILL_H

#include "tools/types.h"
#include "skill.h"

/* Forward declaration */
typedef struct sc_agent sc_agent_t;

/* Create the skill invocation tool. Registry + agent are borrowed. */
sc_tool_t *sc_tool_skill_new(sc_skill_registry_t *skills, sc_agent_t *agent);

#endif /* SC_TOOL_SKILL_H */
