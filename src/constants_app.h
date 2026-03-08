#ifndef SC_CONSTANTS_APP_H
#define SC_CONSTANTS_APP_H

#include <string.h>

#include "sc_version.h"
#define SC_NAME    "smolclaw"
#define SC_LOGO    "\xF0\x9F\xA6\x9E" /* lobster emoji */

/* Config schema version — bump when adding security-relevant fields.
 * Older binaries warn (or refuse in strict mode) if config is newer. */
#define SC_CONFIG_VERSION 1

/* Channel name constants */
#define SC_CHANNEL_CLI      "cli"
#define SC_CHANNEL_TELEGRAM "telegram"
#define SC_CHANNEL_DISCORD  "discord"
#define SC_CHANNEL_IRC      "irc"
#define SC_CHANNEL_SLACK    "slack"
#define SC_CHANNEL_WEB      "web"
#define SC_CHANNEL_SYSTEM   "system"

/* Internal channels that don't route to external users */
static inline int sc_is_internal_channel(const char *channel) {
    if (!channel) return 1;
    return (strcmp(channel, SC_CHANNEL_CLI) == 0 ||
            strcmp(channel, SC_CHANNEL_SYSTEM) == 0);
}

/* Graceful shutdown — strong definition in main.c, weak fallback in logger.c */
int sc_shutdown_requested(void);

#endif /* SC_CONSTANTS_APP_H */
