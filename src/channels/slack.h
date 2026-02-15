#ifndef SC_CHANNEL_SLACK_H
#define SC_CHANNEL_SLACK_H

#include "channels/base.h"
#include "config.h"

/* Create Slack channel (Socket Mode WSS + Web API) */
sc_channel_t *sc_channel_slack_new(sc_slack_config_t *cfg, sc_bus_t *bus);

#endif /* SC_CHANNEL_SLACK_H */
