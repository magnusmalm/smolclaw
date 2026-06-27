#ifndef SC_SLASH_H
#define SC_SLASH_H

/* Gateway slash commands (MVP).
 *
 * Inbound chat messages that begin with a recognized "/command" are handled
 * locally — without an LLM turn — and answered on the same channel. Messages
 * that start with "/" but are not a recognized command are NOT intercepted
 * (return 0) so legitimate slash-prefixed content still reaches the agent.
 *
 * MVP commands: /help, /status, /reset (alias /new), /model [alias], /compress.
 * (/background, /voice, /insights, /reasoning, /rollback, /approve, /deny are
 * deferred to Phase 5.)
 */

typedef struct sc_agent sc_agent_t;

/* Dispatch a possible slash command for `session_key`.
 *
 * Returns 1 if `content` was a recognized slash command (handled): *out_reply
 * receives a malloc'd reply string to send back on the channel (caller frees),
 * or NULL if no reply is warranted. Returns 0 if `content` is not a recognized
 * slash command — the caller should proceed with the normal agent turn. */
int sc_slash_dispatch(sc_agent_t *agent, const char *session_key,
                      const char *content, char **out_reply);

#endif /* SC_SLASH_H */
