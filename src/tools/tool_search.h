#ifndef SC_TOOL_SEARCH_H
#define SC_TOOL_SEARCH_H

#include "tools/types.h"
#include "tools/registry.h"

/* Create the tool_search tool. Registry is borrowed (not owned).
 * Supports two query modes:
 *   "select:name1,name2" — exact match, returns full schemas
 *   "keyword terms"      — scored keyword search across name + description */
sc_tool_t *sc_tool_search_new(sc_tool_registry_t *registry);

#endif /* SC_TOOL_SEARCH_H */
