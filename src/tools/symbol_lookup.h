#ifndef SC_TOOL_SYMBOL_LOOKUP_H
#define SC_TOOL_SYMBOL_LOOKUP_H

#include "tools/types.h"

/* symbol_lookup — Thin convenience wrapper for C/C++ symbol lookup.
 *
 * Designed specifically for researcher Drill-down prompts.
 * Internally delegates to code_graph with action="symbols" and
 * researcher-friendly defaults (max_results=30).
 *
 * Allows clean calls like:
 *   symbol_lookup with name is set_retention path is src
 *
 * Reuses the full code_graph symbols implementation (scanner, formatting,
 * limits, workspace safety) with zero duplication or behavior change to code_graph.
 *
 * Shares the SC_ENABLE_CODE_GRAPH Kconfig flag.
 */
sc_tool_t *sc_tool_symbol_lookup_new(const char *workspace);

#endif /* SC_TOOL_SYMBOL_LOOKUP_H */