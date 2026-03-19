#ifndef SC_TOOL_TYPES_H
#define SC_TOOL_TYPES_H

#include <stdlib.h>
#include "cJSON.h"

/* Forward declaration */
typedef struct sc_tool sc_tool_t;

/*
 * Tool result — multiplexed output model.
 *
 * Each tool result carries separate payloads for the LLM and the user,
 * enabling five distinct delivery modes via the constructors below:
 *
 *   sc_tool_result_new(llm)      — for_llm sent to LLM context; user sees
 *                                  progress summary (default).
 *   sc_tool_result_user(content) — for_llm AND for_user set to content;
 *                                  user sees the content directly.
 *   sc_tool_result_silent(llm)   — for_llm sent to LLM context; nothing
 *                                  shown to user (silent=1). Use for
 *                                  bookkeeping tools (indexing, caching).
 *   sc_tool_result_async(llm)    — for_llm sent to LLM; agent does not
 *                                  wait for completion. Use for background
 *                                  processes (async=1).
 *   sc_tool_result_error(msg)    — for_llm carries the error; is_error=1
 *                                  triggers retry/escalation logic in the
 *                                  agent turn loop.
 *
 * The agent turn loop (agent_turn.c) checks these fields to decide:
 *   - What goes into the LLM message history   (for_llm, always)
 *   - What gets published to the user channel   (for_user, unless silent)
 *   - Whether to count toward the error budget  (is_error)
 *   - Whether to checkpoint after this result   (not is_error, not async)
 */
typedef struct {
    char *for_llm;   /* Content sent to LLM for context */
    char *for_user;  /* Content sent directly to user (NULL = none) */
    int silent;      /* If true, suppress user message entirely */
    int is_error;    /* Error flag — feeds error budget & escalation */
    int async;       /* Async operation — agent doesn't wait for completion */
} sc_tool_result_t;

/* Tool vtable */
struct sc_tool {
    const char *name;
    const char *description;

    /* Return JSON Schema for parameters. Caller owns result. */
    cJSON *(*parameters)(sc_tool_t *self);

    /* Execute tool. Returns owned result. */
    sc_tool_result_t *(*execute)(sc_tool_t *self, cJSON *args, void *ctx);

    /* Set channel/chatID context (optional, can be NULL) */
    void (*set_context)(sc_tool_t *self, const char *channel, const char *chat_id);

    /* Cleanup */
    void (*destroy)(sc_tool_t *self);

    int needs_confirm; /* requires user approval before execute */

    void *data; /* Tool-specific state */
};

/* Result constructors */
sc_tool_result_t *sc_tool_result_new(const char *for_llm);
sc_tool_result_t *sc_tool_result_silent(const char *for_llm);
sc_tool_result_t *sc_tool_result_error(const char *message);
sc_tool_result_t *sc_tool_result_user(const char *content);
sc_tool_result_t *sc_tool_result_async(const char *for_llm);

/* Free result */
void sc_tool_result_free(sc_tool_result_t *r);

/* Generic factory for tools with simple data pointer */
static inline sc_tool_t *sc_tool_new_simple(
    const char *name, const char *description,
    cJSON *(*parameters)(sc_tool_t *),
    sc_tool_result_t *(*execute)(sc_tool_t *, cJSON *, void *),
    void (*destroy)(sc_tool_t *),
    int needs_confirm, void *data)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) { free(data); return NULL; }
    t->name = name;
    t->description = description;
    t->parameters = parameters;
    t->execute = execute;
    t->destroy = destroy;
    t->needs_confirm = needs_confirm;
    t->data = data;
    return t;
}

#endif /* SC_TOOL_TYPES_H */
