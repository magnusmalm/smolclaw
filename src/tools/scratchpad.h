#ifndef SC_TOOL_SCRATCHPAD_H
#define SC_TOOL_SCRATCHPAD_H

#include "tools/types.h"

/* note — write persistent working notes that survive context compaction.
 * Content is injected into the system prompt on every LLM call. */
sc_tool_t *sc_tool_scratchpad_new(const char *workspace);

#endif /* SC_TOOL_SCRATCHPAD_H */
