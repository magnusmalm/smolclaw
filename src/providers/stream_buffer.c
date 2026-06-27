/*
 * smolclaw - streaming inline tool-call buffer (Phase 1.6)
 */
#include "providers/stream_buffer.h"
#include "util/str.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

enum buf_state {
    STATE_UNDECIDED = 0,  /* haven't seen the first non-whitespace char yet */
    STATE_PASSTHROUGH,    /* first char wasn't '{' — forward everything */
    STATE_BUFFERING,      /* first char was '{' — hold until end of stream */
};

struct sc_stream_buffer {
    sc_stream_cb downstream;
    void        *downstream_ctx;
    enum buf_state state;
    sc_strbuf_t  buf;       /* accumulated leading text */
    int          done;      /* end-of-stream already processed */
};

sc_stream_buffer_t *sc_stream_buffer_new(sc_stream_cb downstream,
                                         void *downstream_ctx)
{
    if (!downstream) return NULL;
    sc_stream_buffer_t *sb = calloc(1, sizeof(*sb));
    if (!sb) return NULL;
    sb->downstream = downstream;
    sb->downstream_ctx = downstream_ctx;
    sb->state = STATE_UNDECIDED;
    sc_strbuf_init(&sb->buf);
    return sb;
}

int sc_stream_looks_like_tool_call(const char *text)
{
    if (!text) return 0;
    while (*text && isspace((unsigned char)*text)) text++;
    if (*text != '{') return 0;
    /* Must name a tool and carry an argument object under a known alias. */
    if (!strstr(text, "\"name\"")) return 0;
    return strstr(text, "\"arguments\"") != NULL ||
           strstr(text, "\"parameters\"") != NULL ||
           strstr(text, "\"args\"") != NULL;
}

static void emit_text(sc_stream_buffer_t *sb, const char *s)
{
    if (!s || !*s) return;
    sc_stream_event_t ev = {0};
    ev.type = SC_STREAM_TEXT;
    ev.data = s;
    sb->downstream(&ev, sb->downstream_ctx);
}

static void finish_internal(sc_stream_buffer_t *sb)
{
    if (sb->done) return;
    sb->done = 1;
    if (sb->state == STATE_BUFFERING) {
        const char *held = sb->buf.data ? sb->buf.data : "";
        if (!sc_stream_looks_like_tool_call(held))
            emit_text(sb, held);   /* not a tool call — flush the held text */
        /* else suppress: the post-hoc extractor will turn it into a tool call */
    }
    /* propagate end-of-stream to the real callback */
    sb->downstream(NULL, sb->downstream_ctx);
}

void sc_stream_buffer_cb(const sc_stream_event_t *ev, void *ctx)
{
    sc_stream_buffer_t *sb = ctx;
    if (!sb) return;

    if (!ev) {                 /* end of stream */
        finish_internal(sb);
        return;
    }

    if (ev->type != SC_STREAM_TEXT) {
        /* structural / thinking / native tool-call events pass through */
        sb->downstream(ev, sb->downstream_ctx);
        return;
    }

    const char *d = ev->data ? ev->data : "";

    switch (sb->state) {
    case STATE_PASSTHROUGH:
        sb->downstream(ev, sb->downstream_ctx);
        break;

    case STATE_BUFFERING:
        sc_strbuf_append(&sb->buf, d);
        break;

    case STATE_UNDECIDED:
    default: {
        sc_strbuf_append(&sb->buf, d);
        const char *p = sb->buf.data ? sb->buf.data : "";
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\0')
            break;             /* only whitespace so far — keep waiting */
        if (*p == '{') {
            sb->state = STATE_BUFFERING;   /* hold it */
        } else {
            sb->state = STATE_PASSTHROUGH; /* prose — flush accumulated, then stream */
            emit_text(sb, sb->buf.data);
            /* buf is no longer read in PASSTHROUGH; freed at _free() */
        }
        break;
    }
    }
}

void sc_stream_buffer_finish(sc_stream_buffer_t *sb)
{
    if (sb) finish_internal(sb);
}

void sc_stream_buffer_free(sc_stream_buffer_t *sb)
{
    if (!sb) return;
    sc_strbuf_free(&sb->buf);
    free(sb);
}
