/*
 * tools/worktree.h - Git worktree isolation for safe parallel work
 *
 * Creates isolated git branches via worktrees. The agent works in the
 * worktree directory, and changes can be kept or discarded on exit.
 */

#ifndef SC_TOOL_WORKTREE_H
#define SC_TOOL_WORKTREE_H

#include "tools/types.h"

/* Forward declaration */
typedef struct sc_agent sc_agent_t;

/* Create the worktree_enter and worktree_exit tools.
 * Agent is borrowed (used to switch workspace on enter/exit). */
sc_tool_t *sc_tool_worktree_enter_new(sc_agent_t *agent);
sc_tool_t *sc_tool_worktree_exit_new(sc_agent_t *agent);

#endif /* SC_TOOL_WORKTREE_H */
