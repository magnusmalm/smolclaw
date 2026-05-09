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
    char *thinking;       /* Extended thinking text (NULL if none) */
} sc_llm_message_t;

/* Usage info */
typedef struct {
    int prompt_tokens;
    int completion_tokens;
    int total_tokens;
    /* Provider-reported actual USD billed for this call. -1 means the
     * provider didn't report it (e.g. Anthropic, raw OpenAI); cost
     * tracker falls back to the rate-table estimate in that case.
     * OpenRouter populates this from usage.cost. */
    double cost_usd;
} sc_usage_info_t;

/* LLM response */
typedef struct {
    char *content;
    sc_tool_call_t *tool_calls;
    int tool_call_count;
    char *finish_reason;
    char *thinking;        /* Extended thinking text (NULL if none) */
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

/* Streaming event types */
typedef enum {
    SC_STREAM_TEXT,            /* Regular text delta */
    SC_STREAM_TOOL_START,      /* Tool call started (name known) */
    SC_STREAM_TOOL_ARGS,       /* Partial tool argument JSON */
    SC_STREAM_TOOL_END,        /* Tool call definition complete */
    SC_STREAM_THINKING_START,  /* Extended thinking block started */
    SC_STREAM_THINKING,        /* Thinking text delta */
    SC_STREAM_THINKING_END,    /* Thinking block ended */
} sc_stream_event_type_t;

/* Streaming event passed to stream callback */
typedef struct {
    sc_stream_event_type_t type;
    const char *data;          /* Text/JSON delta (NULL for start/end markers) */
    const char *tool_name;     /* Tool name (for TOOL_START, NULL otherwise) */
    const char *tool_id;       /* Tool call ID (for TOOL_START, NULL otherwise) */
} sc_stream_event_t;

/* Streaming callback: called with each event during LLM response.
 * A NULL event pointer signals end of stream. */
typedef void (*sc_stream_cb)(const sc_stream_event_t *event, void *ctx);

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

    /* Clone provider for use in a separate thread (own curl handle, etc.) */
    sc_provider_t *(*clone)(sc_provider_t *self);

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
