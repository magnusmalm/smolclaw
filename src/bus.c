#include "bus.h"
#include "constants.h"
#include "logger.h"
#include "util/str.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#define LOG_TAG "bus"
#define SC_BUS_MAX_QUEUE_DEPTH 256

/* ---- Queue helpers ---- */

static void queue_init(sc_msg_queue_t *q)
{
    q->head = NULL;
    q->tail = NULL;
    q->count = 0;
    pthread_mutex_init(&q->lock, NULL);
}

/* Returns 0 on success, -1 if queue is full (message not enqueued). */
static int queue_push(sc_msg_queue_t *q, void *msg)
{
    sc_msg_node_t *node = malloc(sizeof(*node));
    if (!node) return -1;
    node->msg  = msg;
    node->next = NULL;

    pthread_mutex_lock(&q->lock);
    if (q->count >= SC_BUS_MAX_QUEUE_DEPTH) {
        pthread_mutex_unlock(&q->lock);
        free(node);
        return -1;
    }
    if (q->tail) {
        q->tail->next = node;
    } else {
        q->head = node;
    }
    q->tail = node;
    q->count++;
    pthread_mutex_unlock(&q->lock);
    return 0;
}

static void *queue_pop(sc_msg_queue_t *q)
{
    pthread_mutex_lock(&q->lock);
    if (!q->head) {
        pthread_mutex_unlock(&q->lock);
        return NULL;
    }

    sc_msg_node_t *node = q->head;
    void *msg = node->msg;
    q->head = node->next;
    if (!q->head) q->tail = NULL;
    q->count--;
    pthread_mutex_unlock(&q->lock);
    free(node);
    return msg;
}

static void queue_free(sc_msg_queue_t *q, void (*free_msg)(void *))
{
    void *msg;
    while ((msg = queue_pop(q)) != NULL) {
        if (free_msg) free_msg(msg);
    }
    pthread_mutex_destroy(&q->lock);
}

/* ---- Pipe notification helpers ---- */

static int make_pipe_blocking(int fds[2])
{
    if (pipe(fds) < 0) return -1;
    return 0;
}

static int make_pipe_nonblock_read(int fds[2])
{
    if (pipe(fds) < 0) return -1;
    /* Set read end to non-blocking for libevent */
    int flags = fcntl(fds[0], F_GETFL, 0);
    if (flags >= 0) fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);
    return 0;
}

static void notify_pipe(int fd)
{
    char c = 1;
    /* Ignore EAGAIN -- pipe is full means reader already notified */
    while (write(fd, &c, 1) < 0 && errno == EINTR)
        ;
}

static void drain_pipe(int fd)
{
    char buf[64];
    /* Drain all notification bytes */
    while (read(fd, buf, sizeof(buf)) > 0)
        ;
}

/* ---- Libevent callbacks ---- */

static void on_outbound_readable(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    sc_bus_t *bus = arg;

    drain_pipe(fd);

    /* Dispatch all queued outbound messages */
    sc_outbound_msg_t *msg;
    while ((msg = queue_pop(&bus->outbound)) != NULL) {
        if (bus->outbound_handler) {
            bus->outbound_handler(msg, bus->outbound_handler_ctx);
        }
        sc_outbound_msg_free(msg);
    }
}

/* ---- Public API ---- */

sc_bus_t *sc_bus_create(struct event_base *base)
{
    sc_bus_t *bus = calloc(1, sizeof(*bus));
    if (!bus) return NULL;

    bus->base = base;
    queue_init(&bus->inbound);
    queue_init(&bus->outbound);

    /* Inbound pipe: blocking read for agent loop thread */
    if (make_pipe_blocking(bus->inbound_pipe) < 0) {
        free(bus);
        return NULL;
    }

    /* Outbound pipe: non-blocking read for libevent */
    if (make_pipe_nonblock_read(bus->outbound_pipe) < 0) {
        close(bus->inbound_pipe[0]);
        close(bus->inbound_pipe[1]);
        free(bus);
        return NULL;
    }

    /* Set up libevent watcher on outbound pipe read end */
    if (base) {
        bus->outbound_event = event_new(base, bus->outbound_pipe[0],
                                        EV_READ | EV_PERSIST,
                                        on_outbound_readable, bus);
        if (bus->outbound_event) {
            event_add(bus->outbound_event, NULL);
        }
    }

    SC_LOG_DEBUG(LOG_TAG, "message bus created");
    return bus;
}

void sc_bus_destroy(sc_bus_t *bus)
{
    if (!bus) return;

    if (bus->inbound_event) {
        event_del(bus->inbound_event);
        event_free(bus->inbound_event);
    }
    if (bus->outbound_event) {
        event_del(bus->outbound_event);
        event_free(bus->outbound_event);
    }

    queue_free(&bus->inbound,  (void (*)(void *))sc_inbound_msg_free);
    queue_free(&bus->outbound, (void (*)(void *))sc_outbound_msg_free);

    close(bus->inbound_pipe[0]);
    close(bus->inbound_pipe[1]);
    close(bus->outbound_pipe[0]);
    close(bus->outbound_pipe[1]);

    free(bus);
    SC_LOG_DEBUG(LOG_TAG, "message bus destroyed");
}

void sc_bus_publish_inbound(sc_bus_t *bus, sc_inbound_msg_t *msg)
{
    if (!bus || !msg) return;
    if (queue_push(&bus->inbound, msg) != 0) {
        SC_LOG_WARN(LOG_TAG, "Inbound queue full (%d), dropping message from %s",
                    SC_BUS_MAX_QUEUE_DEPTH, msg->channel ? msg->channel : "?");
        sc_inbound_msg_free(msg);
        return;
    }
    notify_pipe(bus->inbound_pipe[1]);
}

sc_inbound_msg_t *sc_bus_consume_inbound(sc_bus_t *bus)
{
    if (!bus) return NULL;

    /* Block on pipe until notified, but break out on shutdown */
    char c;
    ssize_t n;
    do {
        n = read(bus->inbound_pipe[0], &c, 1);
    } while (n < 0 && errno == EINTR && !sc_shutdown_requested());

    if (n <= 0) return NULL;

    return queue_pop(&bus->inbound);
}

void sc_bus_publish_outbound(sc_bus_t *bus, sc_outbound_msg_t *msg)
{
    if (!bus || !msg) return;
    if (queue_push(&bus->outbound, msg) != 0) {
        SC_LOG_WARN(LOG_TAG, "Outbound queue full (%d), dropping message to %s",
                    SC_BUS_MAX_QUEUE_DEPTH, msg->channel ? msg->channel : "?");
        sc_outbound_msg_free(msg);
        return;
    }
    notify_pipe(bus->outbound_pipe[1]);
}

void sc_bus_set_outbound_handler(sc_bus_t *bus, sc_msg_handler_t handler, void *ctx)
{
    if (!bus) return;
    bus->outbound_handler     = handler;
    bus->outbound_handler_ctx = ctx;
}

/* ---- Message create/free ---- */

sc_inbound_msg_t *sc_inbound_msg_new(const char *channel, const char *sender_id,
                                      const char *chat_id, const char *content,
                                      const char *session_key)
{
    sc_inbound_msg_t *msg = calloc(1, sizeof(*msg));
    if (!msg) return NULL;

    msg->channel     = sc_strdup(channel);
    msg->sender_id   = sc_strdup(sender_id);
    msg->chat_id     = sc_strdup(chat_id);
    msg->content     = sc_strdup(content);
    msg->session_key = sc_strdup(session_key);

    return msg;
}

sc_outbound_msg_t *sc_outbound_msg_new(const char *channel, const char *chat_id,
                                        const char *content)
{
    sc_outbound_msg_t *msg = calloc(1, sizeof(*msg));
    if (!msg) return NULL;

    msg->channel = sc_strdup(channel);
    msg->chat_id = sc_strdup(chat_id);
    msg->content = sc_strdup(content);

    return msg;
}

void sc_inbound_msg_free(sc_inbound_msg_t *msg)
{
    if (!msg) return;
    free(msg->channel);
    free(msg->sender_id);
    free(msg->chat_id);
    free(msg->content);
    free(msg->session_key);
    free(msg);
}

void sc_outbound_msg_free(sc_outbound_msg_t *msg)
{
    if (!msg) return;
    free(msg->channel);
    free(msg->chat_id);
    free(msg->content);
    free(msg);
}
