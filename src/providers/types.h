#ifndef SC_PROVIDER_TYPES_H
#define SC_PROVIDER_TYPES_H

#include "cJSON.h"

/* Forward declarations */
typedef struct sc_provider sc_provider_t;

/* Tool call from LLM response */
typedef struct {
    char *id;          /* Unique call ID */
    char *name;        /* Tool/function name */
    cJSON *arguments;  /* Parsed arguments (owned) */
} sc_tool_call_t;

/* LLM message */
typedef struct {
    char *role;           /* "system", "user", "assistant", "tool" */
    char *content;        /* Message text */
    sc_tool_call_t *tool_calls;  /* Array of tool calls (assistant msgs) */
    int tool_call_count;
    char *tool_call_id;   /* For tool result messages */
} sc_llm_message_t;

/* Usage info */
typedef struct {
    int prompt_tokens;
    int completion_tokens;
    int total_tokens;
} sc_usage_info_t;

/* LLM response */
typedef struct {
    char *content;
    sc_tool_call_t *tool_calls;
    int tool_call_count;
    char *finish_reason;
    sc_usage_info_t usage;
    int http_status;       /* 0 = curl error, >0 = HTTP status code */
    int retry_after_secs;  /* From Retry-After header, 0 if absent */
} sc_llm_response_t;

/* Tool definition for provider APIs */
typedef struct {
    char *name;
    char *description;
    cJSON *parameters; /* JSON Schema object (owned) */
} sc_tool_definition_t;

/* Streaming callback: called with each text delta, NULL delta signals end */
typedef void (*sc_stream_cb)(const char *delta, void *ctx);

/* Provider vtable */
struct sc_provider {
    const char *name;

    sc_llm_response_t *(*chat)(sc_provider_t *self,
                                sc_llm_message_t *msgs, int msg_count,
                                sc_tool_definition_t *tools, int tool_count,
                                const char *model, cJSON *options);

    /* Streaming variant: calls stream_cb with text deltas, returns full response */
    sc_llm_response_t *(*chat_stream)(sc_provider_t *self,
                                       sc_llm_message_t *msgs, int msg_count,
                                       sc_tool_definition_t *tools, int tool_count,
                                       const char *model, cJSON *options,
                                       sc_stream_cb stream_cb, void *stream_ctx);

    const char *(*get_default_model)(sc_provider_t *self);

    void (*destroy)(sc_provider_t *self);

    void *data; /* Provider-specific state */
};

/* Message construction helpers */
sc_llm_message_t sc_msg_system(const char *content);
sc_llm_message_t sc_msg_user(const char *content);
sc_llm_message_t sc_msg_assistant(const char *content);
sc_llm_message_t sc_msg_tool_result(const char *tool_call_id, const char *content);
sc_llm_message_t sc_msg_assistant_with_tools(const char *content,
                                              sc_tool_call_t *calls, int count);

/* Free helpers */
void sc_llm_message_free_fields(sc_llm_message_t *msg);
void sc_llm_message_array_free(sc_llm_message_t *msgs, int count);
void sc_llm_response_free(sc_llm_response_t *resp);
void sc_tool_call_free_fields(sc_tool_call_t *tc);
void sc_tool_definition_free(sc_tool_definition_t *def);

/* Clone a message (deep copy) */
sc_llm_message_t sc_llm_message_clone(const sc_llm_message_t *msg);

#endif /* SC_PROVIDER_TYPES_H */
