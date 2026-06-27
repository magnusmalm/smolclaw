#ifndef SC_CHANNEL_SIGNAL_H
#define SC_CHANNEL_SIGNAL_H

#include "channels/base.h"
#include "config.h"

/*
 * Signal channel (task 3.1) — talks JSON-RPC to an EXTERNAL signal-cli daemon
 * (or the bbernhard/signal-cli-rest-api container). smolclaw does not
 * implement the Signal protocol or manage the daemon process.
 *
 * MVP: text-only DMs + groups, polling receive, full pairing/allow_from
 * security via channels/base.c. See docs/design/signal-channel.md and
 * docs/channels/signal.md.
 *
 * Returns NULL if cfg is NULL or cfg->account is missing.
 */
sc_channel_t *sc_channel_signal_new(sc_signal_config_t *cfg, sc_bus_t *bus);

#endif /* SC_CHANNEL_SIGNAL_H */
