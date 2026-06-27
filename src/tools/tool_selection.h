/*
 * smolclaw - adaptive tool selection (Phase 1.5)
 *
 * In "auto" mode, a keyword heuristic on the user's message selects a subset
 * of the enabled tool definitions to send to the LLM, reducing prompt-eval
 * cost for constrained local models. Default is "fixed" (send all tools).
 */
#ifndef SC_TOOL_SELECTION_H
#define SC_TOOL_SELECTION_H

#include "providers/types.h"

typedef enum {
    SC_TOOL_SELECTION_FIXED = 0,  /* send all enabled tools (default, current behavior) */
    SC_TOOL_SELECTION_AUTO  = 1,  /* keyword-heuristic subset per turn */
} sc_tool_selection_mode_t;

sc_tool_selection_mode_t sc_tool_selection_from_str(const char *s);
const char *sc_tool_selection_to_str(sc_tool_selection_mode_t mode);

/*
 * In AUTO mode, compact `defs` (length `count`) in place to the subset of
 * tools relevant to `user_msg`, freeing the fields of dropped entries with
 * sc_tool_definition_free(). Returns the new count.
 *
 * In FIXED mode, or when `user_msg`/`defs` is NULL or `count <= 0`, returns
 * `count` unchanged. Unknown / custom / MCP tool names (not in the built-in
 * category map) are always kept, except for pure greetings.
 *
 * The caller still owns `defs` and frees the surviving entries [0, ret) with
 * sc_tool_definitions_free(defs, ret).
 */
int sc_tool_selection_apply(sc_tool_selection_mode_t mode, const char *user_msg,
                            sc_tool_definition_t *defs, int count);

#endif /* SC_TOOL_SELECTION_H */
