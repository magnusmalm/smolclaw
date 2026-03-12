#ifndef SC_TOOL_CONTEXT_TOOLS_H
#define SC_TOOL_CONTEXT_TOOLS_H

#include "tools/types.h"

struct sc_memory_index;

/* context_search — full-text search across context artifacts directory.
 * Only searches documents indexed with the "ctx:" source prefix. */
sc_tool_t *sc_tool_context_search_new(struct sc_memory_index *idx);

#endif /* SC_TOOL_CONTEXT_TOOLS_H */
