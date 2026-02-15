#ifndef SC_TOOL_MESSAGE_H
#define SC_TOOL_MESSAGE_H

#include "tools/types.h"

typedef int (*sc_send_callback_t)(const char *channel, const char *chat_id,
                                   const char *content, void *ctx);

/* Message tool data (accessible for HasSentInRound check) */
typedef struct {
    sc_send_callback_t send_callback;
    void *callback_ctx;
    char *default_channel;
    char *default_chat_id;
    int sent_in_round;
    int restrict_to_source; /* only allow sending to the context channel+chat */
} sc_message_tool_data_t;

sc_tool_t *sc_tool_message_new(void);

/* Set send callback (must be called before use) */
void sc_tool_message_set_callback(sc_tool_t *tool, sc_send_callback_t cb, void *ctx);

/* Check if message was sent in current round */
int sc_tool_message_has_sent(sc_tool_t *tool);

/* Set restrict_to_source mode (only send to context channel+chat) */
void sc_tool_message_set_restrict(sc_tool_t *tool, int restrict_flag);

#endif /* SC_TOOL_MESSAGE_H */
