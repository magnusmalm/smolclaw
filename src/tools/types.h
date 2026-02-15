#ifndef SC_TOOL_TYPES_H
#define SC_TOOL_TYPES_H

#include <stdlib.h>
#include "cJSON.h"

/* Forward declaration */
typedef struct sc_tool sc_tool_t;

/* Tool result */
typedef struct {
    char *for_llm;   /* Content sent to LLM for context */
    char *for_user;  /* Content sent directly to user (NULL = none) */
    int silent;      /* If true, suppress user message */
    int is_error;    /* Error flag */
    int async;       /* Async operation flag */
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
