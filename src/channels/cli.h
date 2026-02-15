#ifndef SC_CHANNEL_CLI_H
#define SC_CHANNEL_CLI_H

#include "channels/base.h"

/* Create CLI channel (interactive readline) */
sc_channel_t *sc_channel_cli_new(sc_bus_t *bus);

/* Confirmation prompt for dangerous tool calls (returns 1=approved, 0=denied) */
int sc_cli_confirm_tool(const char *tool, const char *args, void *ctx);

#endif /* SC_CHANNEL_CLI_H */
