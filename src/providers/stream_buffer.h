/*
 * smolclaw - streaming inline tool-call buffer (Phase 1.6)
 *
 * Some local models emit tool calls as plain text (e.g. `{"name":"read_file",
 * "arguments":{...}}`) in the SC_STREAM_TEXT channel instead of native
 * tool-call events. Without buffering, that raw JSON flashes to the user/
 * channel during streaming before the post-hoc extractor turns it into a tool
 * call. This wrapper sits between the provider and the real stream callback:
 * when the streamed text starts with '{', it withholds the text until end of
 * stream, then suppresses it if it looks like a tool call (or flushes it
 * otherwise). Non-`{` text passes through immediately.
 */
#ifndef SC_STREAM_BUFFER_H
#define SC_STREAM_BUFFER_H

#include "providers/types.h"

typedef struct sc_stream_buffer sc_stream_buffer_t;

/* Create a buffer that forwards to `downstream`/`downstream_ctx`. Returns NULL
 * on OOM (caller should fall back to the raw downstream callback). */
sc_stream_buffer_t *sc_stream_buffer_new(sc_stream_cb downstream,
                                         void *downstream_ctx);

/* The wrapper callback: pass this as the stream_cb and the sc_stream_buffer_t*
 * as the stream_ctx to provider->chat_stream(). */
void sc_stream_buffer_cb(const sc_stream_event_t *ev, void *ctx);

/* Flush/decide any held text and forward end-of-stream if the provider did not
 * already send a NULL event. Idempotent. Call after chat_stream() returns. */
void sc_stream_buffer_finish(sc_stream_buffer_t *sb);

void sc_stream_buffer_free(sc_stream_buffer_t *sb);

/* Exposed for testing: does the buffered text look like an inline tool call? */
int sc_stream_looks_like_tool_call(const char *text);

#endif /* SC_STREAM_BUFFER_H */
