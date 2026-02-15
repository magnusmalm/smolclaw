#ifndef SC_CHANNEL_TELEGRAM_H
#define SC_CHANNEL_TELEGRAM_H

#include "channels/base.h"
#include "config.h"

/* Create Telegram channel (long polling via libcurl) */
sc_channel_t *sc_channel_telegram_new(sc_telegram_config_t *cfg, sc_bus_t *bus);

#endif /* SC_CHANNEL_TELEGRAM_H */
