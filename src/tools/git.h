#ifndef SC_TOOL_GIT_H
#define SC_TOOL_GIT_H

#include "tools/types.h"

sc_tool_t *sc_tool_git_new(const char *working_dir, int restrict_to_workspace);

#endif /* SC_TOOL_GIT_H */
