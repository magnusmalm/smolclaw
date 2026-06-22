#ifndef SC_TOOL_GIT_H
#define SC_TOOL_GIT_H

#include "tools/types.h"

/* push_allowed_remotes: if non-NULL and count > 0, git push is restricted
 * to remotes whose normalized host/path matches an entry (not substring).
 * If NULL or count == 0, push is deny-by-default. */
sc_tool_t *sc_tool_git_new(const char *working_dir, int restrict_to_workspace,
                            const char **push_allowed_remotes,
                            int push_allowed_remote_count);

#endif /* SC_TOOL_GIT_H */
