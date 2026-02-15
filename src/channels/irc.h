#ifndef SC_CHANNEL_IRC_H
#define SC_CHANNEL_IRC_H

#include "channels/base.h"
#include "config.h"

/* Create IRC channel (TCP/TLS socket + PRIVMSG) */
sc_channel_t *sc_channel_irc_new(sc_irc_config_t *cfg, sc_bus_t *bus);

/*
 * IRC message parsing (exposed for testing).
 * Parse a raw IRC line into prefix, command, and params.
 * Returns 0 on success. prefix may be NULL. params is a single trailing string.
 */
int sc_irc_parse_message(const char *line, char *prefix, size_t prefix_sz,
                         char *command, size_t command_sz,
                         char *params, size_t params_sz);

/*
 * Check if text starts with "nick:" or "nick," (highlight).
 * Returns pointer to content after the nick prefix (trimmed), or NULL if no match.
 */
const char *sc_irc_check_highlight(const char *text, const char *nick);

/*
 * Check if nick is mentioned anywhere in text (case-insensitive, word boundary).
 * Matches "nick", "@nick", "hey nick!", etc. but not "nickname".
 * Returns 1 if found, 0 if not.
 */
int sc_irc_check_mention(const char *text, const char *nick);

/*
 * Split a long message into chunks of at most max_len bytes.
 * Returns an array of newly allocated strings. Sets *count.
 * Caller must free each string and the array.
 */
char **sc_irc_split_message(const char *text, int max_len, int *count);

#endif /* SC_CHANNEL_IRC_H */
