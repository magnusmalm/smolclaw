#ifndef SC_TOOL_REGISTRY_H
#define SC_TOOL_REGISTRY_H

#include "tools/types.h"
#include "providers/types.h"

typedef struct sc_tool_registry {
    sc_tool_t **tools;
    int count;
    int cap;
    int (*confirm_cb)(const char *tool_name, const char *args_summary, void *ctx);
    void *confirm_ctx;
    char **allowed_tools;   /* NULL = all allowed */
    int allowed_count;
} sc_tool_registry_t;

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
void sc_tool_definitions_free(sc_tool_definition_t *defs, int count);

/* Get tool summaries for system prompt. Caller owns result. */
char *sc_tool_registry_get_summaries(sc_tool_registry_t *reg);

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

#endif /* SC_TOOL_REGISTRY_H */
