#ifndef SC_HEARTBEAT_SERVICE_H
#define SC_HEARTBEAT_SERVICE_H

#include "bus.h"
#include "state.h"
#include "tools/types.h"
#include <event2/event.h>

/* Heartbeat handler: called with prompt content, returns response */
typedef char *(*sc_heartbeat_handler_t)(const char *prompt, const char *channel,
                                         const char *chat_id, void *ctx);

typedef struct {
    char *workspace;
    int interval_min;     /* Check interval in minutes */
    int enabled;
    struct event *timer_event;
    struct event_base *base;
    sc_bus_t *bus;
    sc_state_t *state;
    sc_heartbeat_handler_t handler;
    void *handler_ctx;
    int running;
} sc_heartbeat_service_t;

sc_heartbeat_service_t *sc_heartbeat_service_new(const char *workspace,
                                                   int interval_min, int enabled,
                                                   struct event_base *base);
void sc_heartbeat_service_free(sc_heartbeat_service_t *hs);

void sc_heartbeat_service_set_bus(sc_heartbeat_service_t *hs, sc_bus_t *bus);
void sc_heartbeat_service_set_state(sc_heartbeat_service_t *hs, sc_state_t *state);
void sc_heartbeat_service_set_handler(sc_heartbeat_service_t *hs,
                                       sc_heartbeat_handler_t handler, void *ctx);

int sc_heartbeat_service_start(sc_heartbeat_service_t *hs);
void sc_heartbeat_service_stop(sc_heartbeat_service_t *hs);

#endif /* SC_HEARTBEAT_SERVICE_H */
