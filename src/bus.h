#ifndef SC_BUS_H
#define SC_BUS_H

#include <event2/event.h>
#include <pthread.h>

/* Inbound message (from channels to agent) */
typedef struct {
    char *channel;
    char *sender_id;
    char *chat_id;
    char *content;
    char *session_key;
} sc_inbound_msg_t;

/* Outbound message (from agent to channels) */
typedef struct {
    char *channel;
    char *chat_id;
    char *content;
} sc_outbound_msg_t;

/* Message handler callback */
typedef void (*sc_msg_handler_t)(sc_outbound_msg_t *msg, void *ctx);

/* Message bus node (linked list) */
typedef struct sc_msg_node {
    void *msg;
    struct sc_msg_node *next;
} sc_msg_node_t;

/* Message queue (thread-safe via mutex) */
typedef struct {
    sc_msg_node_t *head;
    sc_msg_node_t *tail;
    int count;
    pthread_mutex_t lock;
} sc_msg_queue_t;

/* Message bus */
typedef struct {
    struct event_base *base;

    /* Inbound queue + pipe for libevent notification */
    sc_msg_queue_t inbound;
    int inbound_pipe[2];
    struct event *inbound_event;

    /* Outbound queue + pipe */
    sc_msg_queue_t outbound;
    int outbound_pipe[2];
    struct event *outbound_event;

    /* Outbound handler */
    sc_msg_handler_t outbound_handler;
    void *outbound_handler_ctx;
} sc_bus_t;

/* Create/destroy bus */
sc_bus_t *sc_bus_create(struct event_base *base);
void sc_bus_destroy(sc_bus_t *bus);

/* Publish messages */
void sc_bus_publish_inbound(sc_bus_t *bus, sc_inbound_msg_t *msg);
void sc_bus_publish_outbound(sc_bus_t *bus, sc_outbound_msg_t *msg);

/* Consume inbound (blocking, for agent loop thread) */
sc_inbound_msg_t *sc_bus_consume_inbound(sc_bus_t *bus);

/* Set outbound handler (called by libevent when outbound messages arrive) */
void sc_bus_set_outbound_handler(sc_bus_t *bus, sc_msg_handler_t handler, void *ctx);

/* Free messages */
void sc_inbound_msg_free(sc_inbound_msg_t *msg);
void sc_outbound_msg_free(sc_outbound_msg_t *msg);

/* Helper: create inbound message (all strings are copied) */
sc_inbound_msg_t *sc_inbound_msg_new(const char *channel, const char *sender_id,
                                      const char *chat_id, const char *content,
                                      const char *session_key);

/* Helper: create outbound message (all strings are copied) */
sc_outbound_msg_t *sc_outbound_msg_new(const char *channel, const char *chat_id,
                                        const char *content);

#endif /* SC_BUS_H */
