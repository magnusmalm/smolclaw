#ifndef SC_TOOL_REGISTRY_H
#define SC_TOOL_REGISTRY_H

#include "tools/types.h"
#include "providers/types.h"

/*
 * Tool execution hooks — called before/after every tool execution.
 *
 * Pre-tool hook: called after validation, before execute().
 *   Return 0 to proceed, non-zero to block (returns error result to LLM).
 *   Args are read-only (do not modify).
 *
 * Post-tool hook: called after execute(), before result enters context.
 *   The result pointer may be modified in-place (e.g., redact content,
 *   change is_error flag, append to for_user).
 *   Return value is ignored (reserved for future use).
 */
typedef int (*sc_pre_tool_fn)(const char *tool_name, const cJSON *args,
                               const char *channel, const char *chat_id,
                               void *userdata);
typedef int (*sc_post_tool_fn)(const char *tool_name, sc_tool_result_t *result,
                                const char *channel, const char *chat_id,
                                void *userdata);

typedef struct {
    sc_pre_tool_fn fn;
    void *userdata;
    const char *name;  /* for logging (borrowed) */
} sc_pre_tool_hook_t;

typedef struct {
    sc_post_tool_fn fn;
    void *userdata;
    const char *name;  /* for logging (borrowed) */
} sc_post_tool_hook_t;

typedef struct sc_tool_registry {
    sc_tool_t **tools;
    int count;
    int cap;
    int (*confirm_cb)(const char *tool_name, const char *args_summary, void *ctx);
    void *confirm_ctx;
    char **allowed_tools;   /* NULL = all allowed */
    int allowed_count;
    /* Pre/post tool hook chains */
    sc_pre_tool_hook_t *pre_hooks;
    int pre_hook_count;
    int pre_hook_cap;
    sc_post_tool_hook_t *post_hooks;
    int post_hook_count;
    int post_hook_cap;
    char *workspace;  /* current workspace path (owned, for oversized output persistence) */
    /* Per-turn denylist for isolated sessions (borrowed array, set/cleared
     * around the turn like set_workspace). NULL = none denied. */
    const char **denied_tools;
    int denied_count;
    /* Deferred tool discovery tracking */
    char **discovered_tools;  /* tools fetched via tool_search (owned names) */
    int    discovered_count;
    int    discovered_cap;
    /* Oversized-result spill thresholds (<=0 = built-in defaults) */
    int    max_result_chars;     /* spill a single result to disk above this */
    int    result_preview_chars; /* preview kept inline after spill */
    /* Approval policy (task 3.3): which tools trigger confirm_cb. */
    int    approval_policy;      /* sc_approval_policy_t */
    /* Session "always allow" cache: tools the user approved with "always". */
    char **always_allow;
    int    always_allow_count;
} sc_tool_registry_t;

/* Confirmation policy (task 3.3). */
typedef enum {
    SC_APPROVAL_DANGEROUS_ONLY = 0,  /* confirm only tools with needs_confirm */
    SC_APPROVAL_ALWAYS         = 1,  /* confirm every tool */
    SC_APPROVAL_NEVER          = 2,  /* never confirm (autonomous) */
} sc_approval_policy_t;

/* Whether a tool requires confirmation under `policy`. Pure / testable. */
int sc_approval_requires_confirm(int policy, int tool_needs_confirm);

/* Set the registry's approval policy. */
void sc_tool_registry_set_approval_policy(sc_tool_registry_t *reg, int policy);

/* Mark a tool as discovered (fetched via tool_search). */
void sc_tool_registry_mark_discovered(sc_tool_registry_t *reg, const char *name);

/* Check if a deferred tool has been discovered. */
int sc_tool_registry_is_discovered(sc_tool_registry_t *reg, const char *name);

/* Clear discovered set (e.g. on session compact). */
void sc_tool_registry_clear_discovered(sc_tool_registry_t *reg);

/* Get list of deferred tool names + descriptions for system prompt.
 * Caller owns result. */
char *sc_tool_registry_deferred_listing(sc_tool_registry_t *reg);

/* Create/destroy */
sc_tool_registry_t *sc_tool_registry_new(void);
void sc_tool_registry_free(sc_tool_registry_t *reg);

/* Register a tool (registry takes ownership) */
void sc_tool_registry_register(sc_tool_registry_t *reg, sc_tool_t *tool);

/* Get tool by name (returns borrowed pointer, or NULL) */
sc_tool_t *sc_tool_registry_get(sc_tool_registry_t *reg, const char *name);

/* Execute tool by name. Returns owned result. */
sc_tool_result_t *sc_tool_registry_execute(sc_tool_registry_t *reg,
                                            const char *name, cJSON *args,
                                            const char *channel, const char *chat_id,
                                            void *ctx);

/* Convert to provider tool definitions. Caller owns array and contents. */
sc_tool_definition_t *sc_tool_registry_to_defs(sc_tool_registry_t *reg, int *out_count);

/* Like to_defs, but applies an additional channel-level filter on top of the
 * registry's global allowlist. A tool must pass both to be included.
 * If channel_tools is NULL or channel_tool_count is 0, behaves like to_defs. */
sc_tool_definition_t *sc_tool_registry_to_defs_filtered(
    sc_tool_registry_t *reg, int *out_count,
    char **channel_tools, int channel_tool_count);

void sc_tool_definitions_free(sc_tool_definition_t *defs, int count);

/* Get tool summaries for system prompt. Caller owns result. */
char *sc_tool_registry_get_summaries(sc_tool_registry_t *reg);

/* Summaries restricted to a per-channel allowlist — must mirror the
 * filtering of sc_tool_registry_to_defs_filtered so the system prompt
 * never advertises tools absent from the request's tools[]. */
char *sc_tool_registry_get_summaries_filtered(sc_tool_registry_t *reg,
    char **channel_tools, int channel_tool_count);

/* Tool count */
int sc_tool_registry_count(sc_tool_registry_t *reg);

/* Set confirmation callback for tools with needs_confirm=1 */
void sc_tool_registry_set_confirm(sc_tool_registry_t *reg,
    int (*cb)(const char *, const char *, void *), void *ctx);

/* Set allowlist — only these tools are visible/executable. NULL = all allowed. */
void sc_tool_registry_set_allowed(sc_tool_registry_t *reg,
    char **tools, int count);

/* Check if a tool is allowed by the allowlist */
int sc_tool_registry_is_allowed(sc_tool_registry_t *reg, const char *name);

/* Set per-turn denylist — these tools are hidden from definitions and
 * blocked at execution, on top of the allowlist. Used for isolated
 * delegate turns to suppress tools whose handles are pinned to the
 * shared agent workspace (memory_*, note). The array is borrowed, not
 * copied: set it before the turn, clear with (NULL, 0) right after,
 * mirroring the set_workspace swap discipline. */
void sc_tool_registry_set_denied(sc_tool_registry_t *reg,
    const char **tools, int count);

/* Switch workspace for all tools that support it.
 * Calls set_workspace on each tool in the registry. */
void sc_tool_registry_set_workspace(sc_tool_registry_t *reg, const char *workspace);

/* Configure oversized-result spill thresholds. Values <=0 keep the built-in
 * defaults (SC_DEFAULT_MAX_TOOL_RESULT_CHARS / PREVIEW_CHARS). */
void sc_tool_registry_set_result_limits(sc_tool_registry_t *reg,
                                        int max_chars, int preview_chars);

/* Register pre-tool hook (called before execute, return non-zero to block).
 * name is borrowed (not copied). */
void sc_tool_registry_add_pre_hook(sc_tool_registry_t *reg, const char *name,
                                    sc_pre_tool_fn fn, void *userdata);

/* Register post-tool hook (called after execute, can modify result).
 * name is borrowed (not copied). */
void sc_tool_registry_add_post_hook(sc_tool_registry_t *reg, const char *name,
                                     sc_post_tool_fn fn, void *userdata);

#endif /* SC_TOOL_REGISTRY_H */
