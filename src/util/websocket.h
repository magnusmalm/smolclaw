#ifndef SC_WEBSOCKET_H
#define SC_WEBSOCKET_H

#include <stddef.h>

/*
 * Minimal WebSocket (WSS) client using OpenSSL.
 * Supports text frames only. Handles ping/pong automatically.
 */

typedef struct sc_ws sc_ws_t;

/* Connect to a wss:// URL. Returns NULL on failure. */
sc_ws_t *sc_ws_connect(const char *url);

/* Send a text frame. Returns 0 on success, -1 on error. */
int sc_ws_send_text(sc_ws_t *ws, const char *data, size_t len);

/* Receive next text frame (blocking). Returns heap-allocated string, NULL on close/error. */
char *sc_ws_recv(sc_ws_t *ws);

/* Close the connection gracefully. */
void sc_ws_close(sc_ws_t *ws);

/* Check if connected. */
int sc_ws_is_connected(sc_ws_t *ws);

#endif /* SC_WEBSOCKET_H */
