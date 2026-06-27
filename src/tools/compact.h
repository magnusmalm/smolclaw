#ifndef SC_TOOL_COMPACT_H
#define SC_TOOL_COMPACT_H

#include "tools/types.h"

/* Forward declaration */
typedef struct sc_agent sc_agent_t;

/*
 * Task 4.12: agent-initiated compaction. Lets the agent explicitly summarize
 * and shrink the *current* session mid-workflow (the proactive complement to
 * Phase 1's automatic compaction and the /compress slash command). Triggers
 * the same summarization path via sc_agent_compact_session(); guarded by a
 * cooldown (compact_cooldown_secs) and a budget check (refuses when the
 * session is already at/below keep_last).
 */
sc_tool_t *sc_tool_compact_new(sc_agent_t *agent);

#endif /* SC_TOOL_COMPACT_H */
