#ifndef SC_SSE_H
#define SC_SSE_H

#include <stddef.h>

/*
 * SSE (Server-Sent Events) line parser.
 *
 * Feed raw bytes from an HTTP response via sc_sse_feed().
 * The parser calls event_cb for each complete "data: ..." line,
 * stripping the "data: " prefix. "[DONE]" lines are delivered as-is.
 */

typedef void (*sc_sse_event_cb)(const char *data, void *ctx);

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
    sc_sse_event_cb cb;
    void *ctx;
} sc_sse_parser_t;

void sc_sse_init(sc_sse_parser_t *p, sc_sse_event_cb cb, void *ctx);
void sc_sse_feed(sc_sse_parser_t *p, const char *data, size_t len);
void sc_sse_free(sc_sse_parser_t *p);

#endif /* SC_SSE_H */
