#ifndef SC_CHANNEL_SIGNAL_INTERNAL_H
#define SC_CHANNEL_SIGNAL_INTERNAL_H

/*
 * Internal seam for the Signal channel (task 3.1).
 *
 * The polling thread itself is not deterministically unit-testable (it runs a
 * background pthread against an external signal-cli daemon), so the
 * security-critical logic the design doc emphasizes — identifier
 * normalization, group-id handling, group-trigger filtering, and recipient
 * decomposition for send — is factored into the PURE functions below and
 * exercised by tests/test_signal.c without any I/O.
 *
 * See docs/design/signal-channel.md §6.2 (identifier normalization is
 * "critical for reliable allow_from and pairing") and §7.6 (untrusted ids
 * from the daemon must be length/charset validated).
 */

#include "cJSON.h"

/* A text message extracted from a signal-cli `receive` envelope. */
typedef struct {
    char *sender;    /* normalized: "uuid:<uuid>" preferred, else "+<phone>" */
    char *chat_id;   /* DM: equals sender; group: "signal:group:<groupId>"   */
    char *content;   /* message text                                          */
    int   is_group;
} sc_signal_inbound_t;

/* Free the owned strings in *in and zero them. Safe on a zeroed struct. */
void sc_signal_inbound_free(sc_signal_inbound_t *in);

/* Normalize a sender identifier. Prefers the UUID form (returns
 * "uuid:<source_uuid>") when source_uuid is non-empty, otherwise returns the
 * phone form (source, expected E.164 like "+15551234567"). Returns a malloc'd
 * string the caller frees, or NULL if both inputs are NULL/empty or invalid. */
char *sc_signal_normalize_sender(const char *source, const char *source_uuid);

/* Build a group chat_id "signal:group:<group_id>". Returns malloc'd string or
 * NULL if group_id is NULL/empty/invalid. */
char *sc_signal_normalize_group_chat_id(const char *group_id);

/* Group-trigger policy: returns 1 if the agent should act on a group message.
 * When group_trigger is NULL/empty, always 1. Otherwise 1 iff content contains
 * group_trigger as a substring (case-sensitive). */
int sc_signal_group_should_handle(const char *content, const char *group_trigger);

/* Bound untrusted ids (UUIDs, base64 group ids, phone numbers) from the daemon
 * before they reach logs/config. Returns 1 if s is non-empty, <= 512 bytes, and
 * contains only [A-Za-z0-9 + / = _ - : .]. Returns 0 otherwise. */
int sc_signal_id_looks_valid(const char *s);

/* Extract a usable text message from one signal-cli `envelope` object (the
 * value of the "envelope" key in a receive-result element). Returns 1 and
 * populates *out (caller frees with sc_signal_inbound_free) when the envelope
 * carries a non-empty dataMessage text from a valid sender; returns 0 for
 * anything else (sync messages, receipts, typing, empty/attachment-only,
 * malformed or invalid ids). */
int sc_signal_envelope_extract(const cJSON *envelope, sc_signal_inbound_t *out);

/* Decompose a stored chat_id into the bare recipient for a `send` call.
 * Sets *is_group to 1 for "signal:group:<id>" (returns the bare groupId),
 * else 0 for a DM (returns the bare phone, or the UUID with the "uuid:"
 * prefix stripped). Returns a pointer INTO chat_id (no allocation), or NULL
 * if chat_id is NULL/empty. */
const char *sc_signal_recipient_from_chat_id(const char *chat_id, int *is_group);

/* Build the JSON-RPC base URL. If http_url is non-empty it wins verbatim
 * (trailing slash trimmed); otherwise "http://<host>:<port>" using host
 * (default "127.0.0.1") and port. Returns malloc'd string the caller frees. */
char *sc_signal_build_base_url(const char *http_url, const char *host, int port);

#endif /* SC_CHANNEL_SIGNAL_INTERNAL_H */
