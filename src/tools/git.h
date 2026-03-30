#ifndef SC_TOOL_GIT_H
#define SC_TOOL_GIT_H

#include "tools/types.h"

/* push_allowed_remotes: if non-NULL and count > 0, git push is restricted
 * to remotes whose URL contains one of the listed substrings.
 * If NULL or count == 0, push is unrestricted (but still needs confirmation). */
sc_tool_t *sc_tool_git_new(const char *working_dir, int restrict_to_workspace,
                            const char **push_allowed_remotes,
                            int push_allowed_remote_count);

#endif /* SC_TOOL_GIT_H */
