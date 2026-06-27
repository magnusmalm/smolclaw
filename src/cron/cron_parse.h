#ifndef SC_CRON_PARSE_H
#define SC_CRON_PARSE_H

#include <stdint.h>

/*
 * Standard 5-field cron expression parser: "min hour dom month dow".
 *
 * Each field supports: '*', a single value, a-b ranges, comma lists, and
 * '/' step suffixes (e.g. "*\/15", "0-30/10"). Day-of-week is 0-6 (Sunday=0);
 * 7 is also accepted as Sunday. Months are 1-12, day-of-month 1-31.
 *
 * Vixie day semantics: when BOTH day-of-month and day-of-week are restricted
 * (neither is '*'), a time matches if EITHER field matches; otherwise the
 * non-'*' field must match (the '*' field always matches).
 */

typedef struct {
    uint8_t minute[60];
    uint8_t hour[24];
    uint8_t dom[32];    /* index 1..31 used */
    uint8_t month[13];  /* index 1..12 used */
    uint8_t dow[7];     /* index 0..6 (Sunday=0) */
    int dom_star;       /* 1 if day-of-month field was '*' */
    int dow_star;       /* 1 if day-of-week field was '*' */
} sc_cron_expr_t;

/* Parse `expr` into `out`. Returns 0 on success, -1 on a malformed expression
 * (wrong field count, out-of-range value, bad step, etc.). */
int sc_cron_parse(const char *expr, sc_cron_expr_t *out);

/* Return the next unix time (seconds) strictly after `after_sec` that matches
 * `e`, interpreting wall-clock fields in timezone `tz` (an IANA name like
 * "Europe/Stockholm"; NULL/empty uses the process-local timezone). Returns -1
 * if no match within ~366 days (e.g. an impossible date like Feb 31). */
long sc_cron_next_after(const sc_cron_expr_t *e, long after_sec, const char *tz);

#endif /* SC_CRON_PARSE_H */
