#ifndef SC_CHANNEL_WEB_H
#define SC_CHANNEL_WEB_H

#include "channels/base.h"
#include "config.h"

/* Create Web channel (HTTP REST API + embedded chat UI) */
sc_channel_t *sc_channel_web_new(sc_web_config_t *cfg, sc_bus_t *bus);

#endif /* SC_CHANNEL_WEB_H */
