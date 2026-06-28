#ifndef SC_TOOL_REPO_SEARCH_H
#define SC_TOOL_REPO_SEARCH_H

#include "tools/types.h"

/*
 * Task 4.5: repo_search tool (SC_ENABLE_PROJECT_MEMORY, default n).
 *
 * Wraps the per-workspace project-memory code index. Actions: build / refresh /
 * status / search. The index lives under {SMOLCLAW_HOME}/indexes/, never inside
 * the user's repo. `workspace` is copied.
 */
sc_tool_t *sc_tool_repo_search_new(const char *workspace);

#endif /* SC_TOOL_REPO_SEARCH_H */
