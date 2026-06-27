#include "cron/cron_parse.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "util/str.h"

/* Parse the decimal integer in [s, end) into *out. Returns 0 on success. */
static int parse_int(const char *s, const char *end, int *out)
{
    if (s >= end) return -1;
    int v = 0;
    for (const char *p = s; p < end; p++) {
        if (!isdigit((unsigned char)*p)) return -1;
        v = v * 10 + (*p - '0');
        if (v > 100000) return -1;  /* runaway guard */
    }
    *out = v;
    return 0;
}

/* Parse one cron field spec into a bit table covering [lo, hi].
 * is_dow enables 7-as-Sunday mapping. *is_star (optional) is set to 1 when the
 * field is "*". Returns 0 on success, -1 on a malformed field. */
static int parse_field(const char *spec, uint8_t *bits, int lo, int hi,
                       int is_dow, int *is_star)
{
    memset(&bits[lo], 0, (size_t)(hi - lo + 1));
    if (is_star) *is_star = 0;
    if (!spec || !spec[0]) return -1;

    if (strcmp(spec, "*") == 0) {
        for (int v = lo; v <= hi; v++) bits[v] = 1;
        if (is_star) *is_star = 1;
        return 0;
    }

    const char *p = spec;
    while (*p) {
        const char *comma = strchr(p, ',');
        const char *item_end = comma ? comma : p + strlen(p);
        if (item_end == p) return -1;  /* empty list element */

        /* Optional "/step" suffix. */
        const char *slash = memchr(p, '/', (size_t)(item_end - p));
        int step = 1;
        const char *range_end = item_end;
        if (slash) {
            if (parse_int(slash + 1, item_end, &step) != 0 || step <= 0)
                return -1;
            range_end = slash;
        }

        int start, end;
        if (range_end - p == 1 && p[0] == '*') {
            start = lo;
            end = hi;
        } else {
            const char *dash = memchr(p, '-', (size_t)(range_end - p));
            if (dash) {
                if (parse_int(p, dash, &start) != 0) return -1;
                if (parse_int(dash + 1, range_end, &end) != 0) return -1;
            } else {
                if (parse_int(p, range_end, &start) != 0) return -1;
                /* A bare "N" matches just N; "N/step" runs N..hi by step. */
                end = slash ? hi : start;
            }
        }

        if (is_dow) {            /* 7 == Sunday (single values / endpoints) */
            if (start == 7) start = 0;
            if (end == 7) end = 0;
        }

        if (start < lo || end > hi || start > end) return -1;
        for (int v = start; v <= end; v += step) bits[v] = 1;

        p = comma ? comma + 1 : item_end;
    }
    return 0;
}

int sc_cron_parse(const char *expr, sc_cron_expr_t *out)
{
    if (!expr || !out) return -1;

    /* Split into exactly 5 whitespace-separated fields. */
    char buf[256];
    size_t n = strlen(expr);
    if (n == 0 || n >= sizeof(buf)) return -1;
    memcpy(buf, expr, n + 1);

    char *fields[6];
    int fc = 0;
    char *save = NULL;
    for (char *tok = strtok_r(buf, " \t", &save);
         tok; tok = strtok_r(NULL, " \t", &save)) {
        if (fc >= 6) return -1;  /* too many fields */
        fields[fc++] = tok;
    }
    if (fc != 5) return -1;

    memset(out, 0, sizeof(*out));
    if (parse_field(fields[0], out->minute, 0, 59, 0, NULL) != 0) return -1;
    if (parse_field(fields[1], out->hour, 0, 23, 0, NULL) != 0) return -1;
    if (parse_field(fields[2], out->dom, 1, 31, 0, &out->dom_star) != 0) return -1;
    if (parse_field(fields[3], out->month, 1, 12, 0, NULL) != 0) return -1;
    if (parse_field(fields[4], out->dow, 0, 6, 1, &out->dow_star) != 0) return -1;
    return 0;
}

static int tm_matches(const sc_cron_expr_t *e, const struct tm *tm)
{
    if (!e->minute[tm->tm_min]) return 0;
    if (!e->hour[tm->tm_hour]) return 0;
    if (!e->month[tm->tm_mon + 1]) return 0;

    int dm = e->dom_star ? 1 : e->dom[tm->tm_mday];
    int dw = e->dow_star ? 1 : e->dow[tm->tm_wday];
    /* Vixie rule: both restricted → OR; otherwise AND (the '*' side is 1). */
    if (!e->dom_star && !e->dow_star)
        return dm || dw;
    return dm && dw;
}

long sc_cron_next_after(const sc_cron_expr_t *e, long after_sec, const char *tz)
{
    if (!e) return -1;

    /* Start on the next whole-minute boundary strictly after after_sec. */
    long t = after_sec + 1;
    long rem = t % 60;
    if (rem) t += (60 - rem);

    /* Interpret wall-clock fields in tz by temporarily setting TZ. Cron runs
     * on the single-threaded gateway loop, so the global TZ mutation is safe
     * here. */
    int mutated = 0, had = 0;
    char *saved = NULL;
    if (tz && tz[0]) {
        const char *cur = getenv("TZ");
        had = (cur != NULL);
        if (had) saved = sc_strdup(cur);
        setenv("TZ", tz, 1);
        tzset();
        mutated = 1;
    }

    long result = -1;
    const long max_iter = 366L * 24 * 60;  /* one year of minutes */
    for (long i = 0; i < max_iter; i++, t += 60) {
        time_t tt = (time_t)t;
        struct tm tm;
        localtime_r(&tt, &tm);
        if (tm_matches(e, &tm)) { result = t; break; }
    }

    if (mutated) {
        if (had) { setenv("TZ", saved, 1); free(saved); }
        else unsetenv("TZ");
        tzset();
    }
    return result;
}
