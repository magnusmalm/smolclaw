/*
 * util/websocket.c - Minimal WebSocket (WSS) client
 *
 * Implements RFC 6455 WebSocket over TLS using OpenSSL.
 * Only supports text frames. Handles ping/pong and close frames.
 * Client frames are masked as required by the spec.
 */

#include "util/websocket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "constants.h"
#include "logger.h"
#include "util/str.h"
#include "util/base64.h"

#define WS_TAG "websocket"

/* WebSocket opcodes */
#define WS_OP_TEXT  0x1
#define WS_OP_CLOSE 0x8
#define WS_OP_PING  0x9
#define WS_OP_PONG  0xA

struct sc_ws {
    int fd;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int connected;
};

/* Parse URL: wss://host[:port]/path */
static int parse_url(const char *url, char **host, int *port, char **path)
{
    *host = NULL;
    *path = NULL;
    *port = 443;

    const char *p = url;
    if (strncmp(p, "wss://", 6) == 0) {
        p += 6;
    } else if (strncmp(p, "ws://", 5) == 0) {
        p += 5;
        *port = 80;
    } else {
        return -1;
    }

    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');

    size_t host_len;
    if (colon && (!slash || colon < slash)) {
        host_len = colon - p;
        *port = atoi(colon + 1);
    } else if (slash) {
        host_len = slash - p;
    } else {
        host_len = strlen(p);
    }

    *host = malloc(host_len + 1);
    if (!*host) return -1;
    memcpy(*host, p, host_len);
    (*host)[host_len] = '\0';

    if (slash) {
        *path = sc_strdup(slash);
    } else {
        *path = sc_strdup("/");
    }

    return 0;
}

/* Generate 4-byte random mask */
static void generate_mask(unsigned char mask[4])
{
    if (RAND_bytes(mask, 4) != 1) {
        /* Fallback: /dev/urandom */
        FILE *f = fopen("/dev/urandom", "rb");
        if (f) { fread(mask, 1, 4, f); fclose(f); }
    }
}

/* Generate 16-byte random key, base64 encoded */
static char *generate_ws_key(void)
{
    unsigned char raw[16];
    if (RAND_bytes(raw, 16) != 1) {
        FILE *f = fopen("/dev/urandom", "rb");
        if (f) { fread(raw, 1, 16, f); fclose(f); }
    }
    return sc_base64_encode(raw, 16);
}

/* Read exactly n bytes from SSL */
static int ssl_read_full(SSL *ssl, void *buf, size_t n)
{
    size_t total = 0;
    while (total < n) {
        int r = SSL_read(ssl, (char *)buf + total, (int)(n - total));
        if (r <= 0) return -1;
        total += (size_t)r;
    }
    return 0;
}

/* Write all bytes to SSL */
static int ssl_write_full(SSL *ssl, const void *buf, size_t n)
{
    size_t total = 0;
    while (total < n) {
        int w = SSL_write(ssl, (const char *)buf + total, (int)(n - total));
        if (w <= 0) return -1;
        total += (size_t)w;
    }
    return 0;
}

sc_ws_t *sc_ws_connect(const char *url)
{
    char *host = NULL, *path = NULL;
    int port = 443;

    if (parse_url(url, &host, &port, &path) != 0) {
        SC_LOG_ERROR(WS_TAG, "Failed to parse URL: %s", url);
        return NULL;
    }

    SC_LOG_DEBUG(WS_TAG, "Connecting to %s:%d%s", host, port, path);

    /* DNS resolve */
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
        SC_LOG_ERROR(WS_TAG, "DNS resolution failed for %s", host);
        free(host);
        free(path);
        return NULL;
    }

    /* TCP connect */
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        free(host);
        free(path);
        return NULL;
    }

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        SC_LOG_ERROR(WS_TAG, "TCP connect failed: %s", strerror(errno));
        close(fd);
        freeaddrinfo(res);
        free(host);
        free(path);
        return NULL;
    }
    freeaddrinfo(res);

    /* Read timeout — prevents SSL_read from blocking indefinitely */
    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* TLS handshake */
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        close(fd);
        free(host);
        free(path);
        return NULL;
    }

    SSL_CTX_set_default_verify_paths(ssl_ctx);
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);       /* SNI */
    SSL_set1_host(ssl, host);                   /* hostname verification */

    if (SSL_connect(ssl) != 1) {
        SC_LOG_ERROR(WS_TAG, "TLS handshake failed");
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        close(fd);
        free(host);
        free(path);
        return NULL;
    }

    /* WebSocket HTTP Upgrade handshake */
    char *ws_key = generate_ws_key();
    sc_strbuf_t req;
    sc_strbuf_init(&req);
    sc_strbuf_appendf(&req,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        path, host, ws_key);
    char *req_str = sc_strbuf_finish(&req);
    free(ws_key);

    if (ssl_write_full(ssl, req_str, strlen(req_str)) != 0) {
        SC_LOG_ERROR(WS_TAG, "Failed to send handshake");
        free(req_str);
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        close(fd);
        free(host);
        free(path);
        return NULL;
    }
    free(req_str);

    /* Read HTTP response (look for 101 Switching Protocols) */
    char resp_buf[4096];
    size_t resp_len = 0;
    while (resp_len < sizeof(resp_buf) - 1) {
        int r = SSL_read(ssl, resp_buf + resp_len, 1);
        if (r <= 0) break;
        resp_len++;
        if (resp_len >= 4 &&
            resp_buf[resp_len-4] == '\r' && resp_buf[resp_len-3] == '\n' &&
            resp_buf[resp_len-2] == '\r' && resp_buf[resp_len-1] == '\n') {
            break;
        }
    }
    resp_buf[resp_len] = '\0';

    if (strstr(resp_buf, "101") == NULL) {
        int ws_status = 0;
        if (resp_len > 12)
            sscanf(resp_buf, "HTTP/%*d.%*d %d", &ws_status);
        SC_LOG_ERROR(WS_TAG, "WebSocket upgrade rejected (HTTP %d)", ws_status);
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        close(fd);
        free(host);
        free(path);
        return NULL;
    }

    SC_LOG_INFO(WS_TAG, "WebSocket connected to %s:%d%s", host, port, path);

    free(host);
    free(path);

    sc_ws_t *ws = calloc(1, sizeof(*ws));
    if (!ws) {
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        close(fd);
        return NULL;
    }
    ws->fd = fd;
    ws->ssl_ctx = ssl_ctx;
    ws->ssl = ssl;
    ws->connected = 1;

    return ws;
}

int sc_ws_send_text(sc_ws_t *ws, const char *data, size_t len)
{
    if (!ws || !ws->connected) return -1;

    /* Build WebSocket frame: FIN + TEXT opcode, MASK bit set, payload length, mask, masked data */
    unsigned char header[14]; /* max header: 2 + 8 + 4 */
    size_t hlen = 0;

    header[0] = 0x80 | WS_OP_TEXT; /* FIN + TEXT */
    hlen++;

    if (len <= 125) {
        header[1] = 0x80 | (unsigned char)len; /* MASK + length */
        hlen++;
    } else if (len <= 65535) {
        header[1] = 0x80 | 126;
        header[2] = (unsigned char)((len >> 8) & 0xFF);
        header[3] = (unsigned char)(len & 0xFF);
        hlen += 3;
    } else {
        header[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++) {
            header[2 + i] = (unsigned char)((len >> (56 - 8 * i)) & 0xFF);
        }
        hlen += 9;
    }

    /* Masking key */
    unsigned char mask[4];
    generate_mask(mask);
    memcpy(header + hlen, mask, 4);
    hlen += 4;

    /* Send header */
    if (ssl_write_full(ws->ssl, header, hlen) != 0) {
        ws->connected = 0;
        return -1;
    }

    /* Send masked payload */
    unsigned char *masked = malloc(len);
    if (!masked) return -1;
    for (size_t i = 0; i < len; i++) {
        masked[i] = (unsigned char)data[i] ^ mask[i & 3];
    }
    int ret = ssl_write_full(ws->ssl, masked, len);
    free(masked);

    if (ret != 0) {
        ws->connected = 0;
        return -1;
    }

    return 0;
}

/* Send a pong frame (in response to ping) */
static int ws_send_pong(sc_ws_t *ws, const char *data, size_t len)
{
    if (!ws || !ws->connected) return -1;

    unsigned char header[6 + 125]; /* small pong */
    if (len > 125) len = 125;

    header[0] = 0x80 | WS_OP_PONG;
    header[1] = 0x80 | (unsigned char)len;

    unsigned char mask[4];
    generate_mask(mask);
    memcpy(header + 2, mask, 4);

    for (size_t i = 0; i < len; i++) {
        header[6 + i] = (unsigned char)data[i] ^ mask[i & 3];
    }

    return ssl_write_full(ws->ssl, header, 6 + len);
}

char *sc_ws_recv(sc_ws_t *ws)
{
    if (!ws || !ws->connected) return NULL;

    for (;;) {
        /* Read frame header (2 bytes) */
        unsigned char hdr[2];
        if (ssl_read_full(ws->ssl, hdr, 2) != 0) {
            ws->connected = 0;
            return NULL;
        }

        int opcode = hdr[0] & 0x0F;
        int masked = (hdr[1] >> 7) & 1;
        size_t payload_len = hdr[1] & 0x7F;

        if (payload_len == 126) {
            unsigned char ext[2];
            if (ssl_read_full(ws->ssl, ext, 2) != 0) {
                ws->connected = 0;
                return NULL;
            }
            payload_len = ((size_t)ext[0] << 8) | ext[1];
        } else if (payload_len == 127) {
            unsigned char ext[8];
            if (ssl_read_full(ws->ssl, ext, 8) != 0) {
                ws->connected = 0;
                return NULL;
            }
            payload_len = 0;
            for (int i = 0; i < 8; i++) {
                payload_len = (payload_len << 8) | ext[i];
            }
        }

        /* Cap payload size to prevent OOM from malicious server */
        if (payload_len > SC_WS_MAX_PAYLOAD) {
            SC_LOG_ERROR(WS_TAG, "Frame too large: %zu bytes", payload_len);
            ws->connected = 0;
            return NULL;
        }

        /* Read mask key if present (server frames usually aren't masked) */
        unsigned char mask_key[4] = {0};
        if (masked) {
            if (ssl_read_full(ws->ssl, mask_key, 4) != 0) {
                ws->connected = 0;
                return NULL;
            }
        }

        /* Read payload */
        char *payload = malloc(payload_len + 1);
        if (!payload) {
            ws->connected = 0;
            return NULL;
        }

        if (payload_len > 0) {
            if (ssl_read_full(ws->ssl, payload, payload_len) != 0) {
                free(payload);
                ws->connected = 0;
                return NULL;
            }
        }

        /* Unmask if needed */
        if (masked) {
            for (size_t i = 0; i < payload_len; i++) {
                payload[i] ^= (char)mask_key[i & 3];
            }
        }
        payload[payload_len] = '\0';

        switch (opcode) {
        case WS_OP_TEXT:
            return payload;

        case WS_OP_PING:
            ws_send_pong(ws, payload, payload_len);
            free(payload);
            continue; /* Wait for next frame */

        case WS_OP_CLOSE:
            SC_LOG_INFO(WS_TAG, "Received close frame");
            free(payload);
            ws->connected = 0;
            return NULL;

        case WS_OP_PONG:
            free(payload);
            continue; /* Ignore pongs */

        default:
            SC_LOG_WARN(WS_TAG, "Unknown opcode %d, skipping", opcode);
            free(payload);
            continue;
        }
    }
}

void sc_ws_close(sc_ws_t *ws)
{
    if (!ws) return;

    if (ws->connected) {
        /* Send close frame */
        unsigned char close_frame[6];
        close_frame[0] = 0x80 | WS_OP_CLOSE;
        close_frame[1] = 0x80 | 0; /* masked, zero length */
        unsigned char mask[4];
        generate_mask(mask);
        memcpy(close_frame + 2, mask, 4);
        ssl_write_full(ws->ssl, close_frame, 6);
        ws->connected = 0;
    }

    if (ws->ssl) {
        SSL_shutdown(ws->ssl);
        SSL_free(ws->ssl);
    }
    if (ws->ssl_ctx) {
        SSL_CTX_free(ws->ssl_ctx);
    }
    if (ws->fd >= 0) {
        close(ws->fd);
    }
    free(ws);
}

int sc_ws_is_connected(sc_ws_t *ws)
{
    return ws ? ws->connected : 0;
}
