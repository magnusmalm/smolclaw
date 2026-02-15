#ifndef SC_TOOL_BACKGROUND_H
#define SC_TOOL_BACKGROUND_H

#include "tools/types.h"

/* Background process management tools */
sc_tool_t *sc_tool_exec_bg_new(const char *workspace, int restrict_to_workspace,
                               int max_procs);
sc_tool_t *sc_tool_bg_poll_new(void);
sc_tool_t *sc_tool_bg_kill_new(void);

/* Kill all remaining background processes (call on agent shutdown) */
void sc_bg_cleanup_all(void);

/* Set exec allowlist on background tool (call after sc_tool_exec_bg_new) */
void sc_tool_exec_bg_set_allowlist(sc_tool_t *t, int use_allowlist,
                                    char *const *commands, int count);

/* Enable/disable OS-level sandbox (Landlock + seccomp) for bg exec children */
void sc_tool_exec_bg_set_sandbox(sc_tool_t *t, int enabled);

#endif /* SC_TOOL_BACKGROUND_H */
