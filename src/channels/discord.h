#ifndef SC_CHANNEL_DISCORD_H
#define SC_CHANNEL_DISCORD_H

#include "channels/base.h"
#include "config.h"

/* Create Discord channel (Gateway WebSocket + REST API) */
sc_channel_t *sc_channel_discord_new(sc_discord_config_t *cfg, sc_bus_t *bus);

#endif /* SC_CHANNEL_DISCORD_H */
