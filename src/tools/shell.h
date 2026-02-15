#ifndef SC_TOOL_SHELL_H
#define SC_TOOL_SHELL_H

#include "tools/types.h"

sc_tool_t *sc_tool_exec_new(const char *working_dir, int restrict_to_workspace,
                            int max_output_chars, int timeout_secs);

/* Set exec allowlist (call after sc_tool_exec_new).
 * commands array is copied. use_allowlist=1 enables allowlist mode. */
void sc_tool_exec_set_allowlist(sc_tool_t *t, int use_allowlist,
                                 char *const *commands, int count);

/* Enable/disable OS-level sandbox (Landlock + seccomp) for exec children */
void sc_tool_exec_set_sandbox(sc_tool_t *t, int enabled);

#endif /* SC_TOOL_SHELL_H */
