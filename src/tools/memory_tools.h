#ifndef SC_TOOL_MEMORY_H
#define SC_TOOL_MEMORY_H

#include "tools/types.h"
#include "memory.h"

/* memory_read — read MEMORY.md and/or recent daily notes */
sc_tool_t *sc_tool_memory_read_new(const char *workspace);

/* memory_write — overwrite MEMORY.md (needs_confirm = 1) */
sc_tool_t *sc_tool_memory_write_new(const char *workspace);

/* memory_log — append to today's daily note */
sc_tool_t *sc_tool_memory_log_new(const char *workspace);

/* Set index callback on a memory tool's internal sc_memory_t.
 * Call after creating memory_write or memory_log tools. */
void sc_tool_memory_set_index_cb(sc_tool_t *tool, sc_memory_index_cb cb,
                                  void *ctx);

#endif /* SC_TOOL_MEMORY_H */
