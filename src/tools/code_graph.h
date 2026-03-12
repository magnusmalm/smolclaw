#ifndef SC_TOOL_CODE_GRAPH_H
#define SC_TOOL_CODE_GRAPH_H

#include "tools/types.h"

/* code_graph — regex-based import dependency graph.
 * Supports JS/TS, Python, C/C++, Go, Rust.
 * Actions: build, query, stats, cycles. */
sc_tool_t *sc_tool_code_graph_new(const char *workspace);

#endif /* SC_TOOL_CODE_GRAPH_H */
