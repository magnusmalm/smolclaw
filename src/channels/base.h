#ifndef SC_CHANNEL_BASE_H
#define SC_CHANNEL_BASE_H

#include <pthread.h>
#include <unistd.h>

#include "bus.h"
#include "pairing.h"
#include "rate_limit.h"

/* Interruptible sleep: returns early if *running becomes 0. */
static inline void sc_channel_sleep(volatile int *running, int seconds)
{
    for (int i = 0; i < seconds * 10 && *running; i++)
        usleep(100000);  /* 100ms */
}

/* Forward declaration — avoids hard dependency on voice module */
typedef struct sc_transcriber sc_transcriber_t;

/* Forward declaration */
typedef struct sc_channel sc_channel_t;

/* Channel vtable */
struct sc_channel {
    const char *name;

    int (*start)(sc_channel_t *self);
    int (*stop)(sc_channel_t *self);
    int (*send)(sc_channel_t *self, sc_outbound_msg_t *msg);
    int (*send_typing)(sc_channel_t *self, const char *chat_id); /* optional */
    int (*is_running)(sc_channel_t *self);
    void (*destroy)(sc_channel_t *self);

    /* Common state */
    sc_bus_t *bus;
    char **allow_list;
    int allow_list_count;
    sc_dm_policy_t dm_policy;
    sc_pairing_store_t *pairing_store; /* NULL unless policy==pairing */
    sc_rate_limiter_t *rate_limiter;   /* NULL = no rate limiting */
    pthread_mutex_t security_mutex;    /* protects allow_list + rate_limiter */
    volatile int running;
    void *data;

    /* Optional voice transcriber (shared, not owned) */
    sc_transcriber_t *transcriber;
};

/* Initialize common security fields: allow list, DM policy, pairing store */
void sc_channel_init_security(sc_channel_t *ch, const char *dm_policy,
                               char **allow_from, int allow_from_count,
                               const char *channel_name);

/* Check if sender is in allow list (empty list = allow all) */
int sc_channel_is_allowed(sc_channel_t *ch, const char *sender_id);

/* Handle inbound message (builds InboundMessage and publishes to bus) */
void sc_channel_handle_message(sc_channel_t *ch, const char *sender_id,
                                const char *chat_id, const char *content);

/* Free base channel resources */
void sc_channel_base_free(sc_channel_t *ch);

#endif /* SC_CHANNEL_BASE_H */
