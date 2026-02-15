#ifndef SC_CHANNEL_MANAGER_H
#define SC_CHANNEL_MANAGER_H

#include "channels/base.h"
#include "config.h"

typedef struct {
    sc_channel_t **channels;
    int count;
    sc_bus_t *bus;
    sc_config_t *config;
    sc_transcriber_t *transcriber; /* Shared, owned by manager */
} sc_channel_manager_t;

sc_channel_manager_t *sc_channel_manager_new(sc_config_t *cfg, sc_bus_t *bus);
void sc_channel_manager_free(sc_channel_manager_t *mgr);

int sc_channel_manager_start_all(sc_channel_manager_t *mgr);
void sc_channel_manager_stop_all(sc_channel_manager_t *mgr);

sc_channel_t *sc_channel_manager_get(sc_channel_manager_t *mgr, const char *name);
int sc_channel_manager_send(sc_channel_manager_t *mgr, const char *channel,
                            const char *chat_id, const char *content);
int sc_channel_manager_send_typing(sc_channel_manager_t *mgr,
                                   const char *channel, const char *chat_id);

/* Hot-reload config: update allow_from lists, dm_policy, rate limits */
void sc_channel_manager_reload_config(sc_channel_manager_t *mgr,
                                       const sc_config_t *cfg);

#endif /* SC_CHANNEL_MANAGER_H */
