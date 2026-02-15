/*
 * util/secrets.h - Secret scanning and redaction
 *
 * Detects API keys, PEM private keys, and key=value secrets in text.
 * Used to prevent LLM from echoing secrets back to channels.
 */

#ifndef SC_SECRETS_H
#define SC_SECRETS_H

/* Count secret pattern matches in text. Returns 0 if none found. */
int sc_scan_secrets(const char *text);

/* Redact secrets from text. Returns new string with matches replaced
 * by [REDACTED]. Caller owns result. Returns NULL if no matches. */
char *sc_redact_secrets(const char *text);

#endif /* SC_SECRETS_H */
