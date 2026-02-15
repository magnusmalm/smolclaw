#ifndef SC_TOOL_MEMORY_SEARCH_H
#define SC_TOOL_MEMORY_SEARCH_H

#include "tools/types.h"

struct sc_memory_index;

/* memory_search — full-text search across memory files via FTS5 */
sc_tool_t *sc_tool_memory_search_new(struct sc_memory_index *idx);

#endif /* SC_TOOL_MEMORY_SEARCH_H */
