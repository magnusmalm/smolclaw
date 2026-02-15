#ifndef SC_CONTEXT_H
#define SC_CONTEXT_H

#include "providers/types.h"
#include "tools/types.h"
#include "memory.h"

/* Forward declarations */
typedef struct sc_tool_registry sc_tool_registry_t;

/* Context builder */
typedef struct {
    char *workspace;
    sc_memory_t *memory;
    sc_tool_registry_t *tools;
} sc_context_builder_t;

/* Create/destroy */
sc_context_builder_t *sc_context_builder_new(const char *workspace);
void sc_context_builder_free(sc_context_builder_t *cb);

/* Set tools registry for dynamic tool summaries */
void sc_context_builder_set_tools(sc_context_builder_t *cb, sc_tool_registry_t *tools);

/* Build complete system prompt. Caller owns result. */
char *sc_context_build_system_prompt(const sc_context_builder_t *cb);

/* Build full message array for LLM call.
 * Returns array of messages, sets *out_count.
 * Caller owns the returned array and its contents. */
sc_llm_message_t *sc_context_build_messages(const sc_context_builder_t *cb,
                                             sc_llm_message_t *history, int history_count,
                                             const char *summary,
                                             const char *current_msg,
                                             const char *channel, const char *chat_id,
                                             int *out_count);

/* Load bootstrap files (AGENTS.md, SOUL.md, etc). Caller owns result. */
char *sc_context_load_bootstrap(const sc_context_builder_t *cb);

#endif /* SC_CONTEXT_H */
