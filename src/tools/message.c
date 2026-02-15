/*
 * tools/message.c - Message tool
 *
 * Sends messages to users via a callback. Tracks whether a message
 * was sent in the current processing round.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "tools/message.h"
#include "tools/types.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "logger.h"
#include "cJSON.h"

/* ---------- Tool implementation ---------- */

static void message_destroy(sc_tool_t *self)
{
    if (!self) return;
    sc_message_tool_data_t *d = self->data;
    if (d) {
        free(d->default_channel);
        free(d->default_chat_id);
        free(d);
    }
    free(self);
}

static void message_set_context(sc_tool_t *self, const char *channel, const char *chat_id)
{
    sc_message_tool_data_t *d = self->data;
    if (!d) return;

    free(d->default_channel);
    free(d->default_chat_id);
    d->default_channel = sc_strdup(channel);
    d->default_chat_id = sc_strdup(chat_id);
    d->sent_in_round = 0;
}

static cJSON *message_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "content", "The message content to send", 1);
    sc_schema_add_string(schema, "channel",
                         "Optional: target channel (telegram, etc.)", 0);
    sc_schema_add_string(schema, "chat_id",
                         "Optional: target chat/user ID", 0);
    return schema;
}

static sc_tool_result_t *message_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    sc_message_tool_data_t *d = self->data;
    if (!d)
        return sc_tool_result_error("message tool not initialized");

    const char *content = sc_json_get_string(args, "content", NULL);
    if (!content)
        return sc_tool_result_error("content is required");

    /* Resolve channel and chat_id from args or defaults */
    const char *channel = sc_json_get_string(args, "channel", NULL);
    const char *chat_id = sc_json_get_string(args, "chat_id", NULL);

    if (!channel || !*channel)
        channel = d->default_channel;
    if (!chat_id || !*chat_id)
        chat_id = d->default_chat_id;

    if (!channel || !*channel || !chat_id || !*chat_id)
        return sc_tool_result_error("No target channel/chat specified");

    /* Restrict to source: only allow sending to the context channel/chat_id */
    if (d->restrict_to_source && d->default_channel && d->default_chat_id) {
        if (strcmp(channel, d->default_channel) != 0 ||
            strcmp(chat_id, d->default_chat_id) != 0) {
            return sc_tool_result_error(
                "message restricted to source channel (restrict_message_tool is enabled)");
        }
    }

    if (!d->send_callback)
        return sc_tool_result_error("Message sending not configured");

    int rc = d->send_callback(channel, chat_id, content, d->callback_ctx);
    if (rc != 0) {
        return sc_tool_result_error("failed to send message");
    }

    d->sent_in_round = 1;

    /* Build silent result - user already received the message directly */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Message sent to %s:%s", channel, chat_id);
    char *msg = sc_strbuf_finish(&sb);
    sc_tool_result_t *result = sc_tool_result_silent(msg);
    free(msg);
    return result;
}

sc_tool_t *sc_tool_message_new(void)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    sc_message_tool_data_t *d = calloc(1, sizeof(*d));
    if (!d) { free(t); return NULL; }

    t->name = "message";
    t->description = "Send a message to user on a chat channel. Use this when you want to communicate something.";
    t->parameters = message_parameters;
    t->execute = message_execute;
    t->set_context = message_set_context;
    t->destroy = message_destroy;
    t->data = d;
    return t;
}

void sc_tool_message_set_callback(sc_tool_t *tool, sc_send_callback_t cb, void *ctx)
{
    if (!tool) return;
    sc_message_tool_data_t *d = tool->data;
    if (!d) return;
    d->send_callback = cb;
    d->callback_ctx = ctx;
}

int sc_tool_message_has_sent(sc_tool_t *tool)
{
    if (!tool) return 0;
    sc_message_tool_data_t *d = tool->data;
    return d ? d->sent_in_round : 0;
}

void sc_tool_message_set_restrict(sc_tool_t *tool, int restrict_flag)
{
    if (!tool) return;
    sc_message_tool_data_t *d = tool->data;
    if (d) d->restrict_to_source = restrict_flag;
}
