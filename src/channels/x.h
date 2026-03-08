#ifndef SC_CHANNEL_X_H
#define SC_CHANNEL_X_H

#include "channels/base.h"
#include "config.h"

/* Create X (Twitter) channel (REST polling via libcurl + OAuth 1.0a) */
sc_channel_t *sc_channel_x_new(sc_x_config_t *cfg, sc_bus_t *bus);

#endif /* SC_CHANNEL_X_H */
