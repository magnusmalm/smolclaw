/*
 * util/sse.c - Server-Sent Events line parser
 */

#include "util/sse.h"

#include <stdlib.h>
#include <string.h>

#include "constants.h"

#define SSE_INIT_CAP 256

void sc_sse_init(sc_sse_parser_t *p, sc_sse_event_cb cb, void *ctx)
{
    p->buf = malloc(SSE_INIT_CAP);
    p->len = 0;
    p->cap = SSE_INIT_CAP;
    p->cb = cb;
    p->ctx = ctx;
}

static void process_line(sc_sse_parser_t *p, const char *line, size_t len)
{
    /* Skip empty lines and non-data fields (event:, id:, retry:) */
    if (len == 0) return;

    const char *prefix = "data: ";
    size_t prefix_len = 6;

    /* Also handle "data:" without space */
    if (len >= 5 && strncmp(line, "data:", 5) == 0) {
        const char *payload = line + 5;
        size_t payload_len = len - 5;
        /* Skip optional leading space */
        if (payload_len > 0 && payload[0] == ' ') {
            payload++;
            payload_len--;
        }

        /* Null-terminate and deliver */
        char *copy = malloc(payload_len + 1);
        memcpy(copy, payload, payload_len);
        copy[payload_len] = '\0';

        p->cb(copy, p->ctx);
        free(copy);
    }
    (void)prefix;
    (void)prefix_len;
}

void sc_sse_feed(sc_sse_parser_t *p, const char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        char c = data[i];

        if (c == '\n' || c == '\r') {
            /* Process the accumulated line */
            process_line(p, p->buf, p->len);
            p->len = 0;

            /* Skip \r\n pair */
            if (c == '\r' && i + 1 < len && data[i + 1] == '\n')
                i++;
            continue;
        }

        /* Append to buffer, growing if needed */
        if (p->len + 1 >= p->cap) {
            if (p->cap >= (size_t)SC_SSE_MAX_LINE) {
                /* Line too long — discard and reset */
                p->len = 0;
                continue;
            }
            p->cap *= 2;
            if (p->cap > (size_t)SC_SSE_MAX_LINE) p->cap = (size_t)SC_SSE_MAX_LINE;
            p->buf = realloc(p->buf, p->cap);
        }
        p->buf[p->len++] = c;
    }
}

void sc_sse_free(sc_sse_parser_t *p)
{
    free(p->buf);
    p->buf = NULL;
    p->len = 0;
    p->cap = 0;
}
