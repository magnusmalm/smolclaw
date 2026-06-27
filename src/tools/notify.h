#ifndef SC_TOOL_NOTIFY_H
#define SC_TOOL_NOTIFY_H

#include "tools/types.h"

/*
 * Notify tool — sends notifications to external services via HTTP POST.
 *
 * Supported URL schemes (Apprise-compatible):
 *   discord://webhook_id/webhook_token
 *   tg://bottoken/chatid
 *   json://https://example.com/hook
 *   slack://T00000000/B00000000/XXXXXXXXXXXX   (incoming webhook path)
 *   ntfy://topic            (ntfy.sh)
 *   ntfy://host/topic       (self-hosted ntfy, https)
 *
 * Config: "notify_urls" in config.json or SMOLCLAW_NOTIFY_URLS env var.
 * The agent calls this tool when it wants to ping the user externally.
 */
sc_tool_t *sc_tool_notify_new(const char *notify_urls);

#endif /* SC_TOOL_NOTIFY_H */
