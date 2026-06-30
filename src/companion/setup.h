#ifndef SC_COMPANION_SETUP_H
#define SC_COMPANION_SETUP_H

#include "config.h"

/* Percent-encode s for use in smolclaw:// query values. Returns malloc'd string. */
char *sc_companion_uri_encode(const char *s);

/* Build smolclaw://v1/connect?url=...&token=... (malloc'd). */
char *sc_companion_build_connect_uri(const char *origin, const char *token);

/* Derive http(s) origin from web config; override_url wins if set. */
char *sc_companion_origin_from_web(const sc_web_config_t *web,
                                    const char *override_url);

/* 1 if origin uses https or is LAN-local http (RFC1918/localhost/.local). */
int sc_companion_origin_tls_ok(const char *origin);

/* Print ASCII QR for text to stdout (half-block glyphs). */
void sc_companion_print_qr_ascii(const char *text);

/* Run `smolclaw companion qr [--url ORIGIN] [--force]`. */
int sc_companion_cmd_qr(int argc, char **argv);

#endif /* SC_COMPANION_SETUP_H */