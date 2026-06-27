#ifndef SC_TOOL_NOTIFY_INTERNAL_H
#define SC_TOOL_NOTIFY_INTERNAL_H

/*
 * Internal seam for the notify tool's URL parser.
 *
 * parse_one_url() is a pure function (no I/O) that classifies an
 * Apprise-compatible notification URL into a scheme + up to two params.
 * Exposed here — rather than kept static in notify.c — so tests/test_notify.c
 * can lock the scheme truth table without sending any HTTP. The send path
 * (curl) stays private to notify.c.
 */

typedef enum {
    SCHEME_DISCORD,
    SCHEME_TELEGRAM,
    SCHEME_JSON,
    SCHEME_SLACK,   /* slack://T.../B.../secret  (incoming webhook path) */
    SCHEME_NTFY,    /* ntfy://topic  or  ntfy://host/topic               */
} notify_scheme_t;

typedef struct {
    notify_scheme_t scheme;
    char *param1;
    char *param2;
} parsed_url_t;

/* Free param1/param2 and NULL them. Safe on a zero-initialized struct. */
void parsed_url_free(parsed_url_t *u);

/* Parse one URL into *out. Returns 0 on success (out owns its strings; caller
 * must parsed_url_free), -1 on unrecognized scheme or malformed input (out is
 * left zeroed/cleaned — no allocation leaks on the -1 path). */
int parse_one_url(const char *s, parsed_url_t *out);

#endif /* SC_TOOL_NOTIFY_INTERNAL_H */
