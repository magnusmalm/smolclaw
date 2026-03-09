/*
 * smolclaw - IRC channel
 * Plain IRC over TCP with optional TLS. Responds to highlights in channels
 * and all direct messages.
 */

#include "channels/irc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "constants.h"
#include "logger.h"
#include "pairing.h"
#include "util/str.h"

#define IRC_TAG "irc"
#define IRC_MAX_LINE 512
#define IRC_MSG_CHUNK 400  /* safe PRIVMSG content limit */
#define IRC_RECV_BUF 4096
#define IRC_RECONNECT_DELAY     5   /* initial backoff seconds */
#define IRC_RECONNECT_MAX_DELAY 300 /* cap at 5 minutes */
#define IRC_KEEPALIVE_INTERVAL  120 /* send PING after this many seconds idle */
#define IRC_KEEPALIVE_TIMEOUT   30  /* disconnect if no PONG within this */

typedef struct {
    char *hostname;
    int port;
    char *nick;
    char *username;
    char *password;
    char *group_trigger;
    char **channels;
    int channel_count;
    int use_tls;
    int sockfd;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    pthread_t recv_thread;
    int thread_started;
    /* Line buffer for recv_line */
    char recvbuf[IRC_RECV_BUF];
    int recvbuf_len;
    char linebuf[IRC_RECV_BUF];  /* output buffer for irc_recv_line */
} irc_data_t;

/* ------------------------------------------------------------------ */
/* Parsing helpers (also used by tests)                                */
/* ------------------------------------------------------------------ */

int sc_irc_parse_message(const char *line, char *prefix, size_t prefix_sz,
                         char *command, size_t command_sz,
                         char *params, size_t params_sz)
{
    if (!line || !command || !params) return -1;
    if (prefix) prefix[0] = '\0';
    command[0] = '\0';
    params[0] = '\0';

    /* Compute effective length, ignoring trailing \r\n (no allocation) */
    size_t line_len = strlen(line);
    while (line_len > 0 && (line[line_len - 1] == '\r' || line[line_len - 1] == '\n'))
        line_len--;
    if (line_len == 0) return -1;

    /* Work within line[0..line_len) using pointer+bounds */
    const char *end = line + line_len;
    const char *p = line;

    /* Parse prefix (starts with :) */
    if (*p == ':') {
        p++;
        const char *space = memchr(p, ' ', (size_t)(end - p));
        if (!space) return -1;
        if (prefix) {
            size_t len = (size_t)(space - p);
            if (len >= prefix_sz) len = prefix_sz - 1;
            memcpy(prefix, p, len);
            prefix[len] = '\0';
        }
        p = space + 1;
    }

    /* Skip whitespace */
    while (*p == ' ') p++;

    /* Parse command */
    const char *cmd_end = memchr(p, ' ', (size_t)(end - p));
    if (cmd_end) {
        size_t len = (size_t)(cmd_end - p);
        if (len >= command_sz) len = command_sz - 1;
        memcpy(command, p, len);
        command[len] = '\0';
        p = cmd_end + 1;
    } else {
        /* Command with no params */
        size_t len = (size_t)(end - p);
        if (len >= command_sz) len = command_sz - 1;
        memcpy(command, p, len);
        command[len] = '\0';
        return 0;
    }

    /* Skip whitespace */
    while (*p == ' ') p++;

    /* Parse params — find trailing (starts with :) */
    const char *trailing = NULL;
    const char *scan = p;
    while (scan < end) {
        if (*scan == ':' && (scan == p || *(scan - 1) == ' ')) {
            trailing = scan + 1;
            break;
        }
        scan++;
    }

    if (trailing) {
        /* Middle params + trailing */
        size_t mid_len = (size_t)(scan - p);
        /* Trim trailing spaces from middle */
        while (mid_len > 0 && p[mid_len - 1] == ' ') mid_len--;

        size_t trail_len = (size_t)(end - trailing);
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        if (mid_len > 0) {
            char *mid = malloc(mid_len + 1);
            if (mid) {
                memcpy(mid, p, mid_len);
                mid[mid_len] = '\0';
                sc_strbuf_append(&sb, mid);
                sc_strbuf_append(&sb, " ");
                free(mid);
            }
        }
        /* Append trailing with known length */
        char *trail_str = malloc(trail_len + 1);
        if (trail_str) {
            memcpy(trail_str, trailing, trail_len);
            trail_str[trail_len] = '\0';
            sc_strbuf_append(&sb, trail_str);
            free(trail_str);
        }
        char *result = sc_strbuf_finish(&sb);
        if (result) {
            size_t len = strlen(result);
            if (len >= params_sz) len = params_sz - 1;
            memcpy(params, result, len);
            params[len] = '\0';
            free(result);
        }
    } else {
        /* No trailing, all middle params */
        size_t len = (size_t)(end - p);
        if (len >= params_sz) len = params_sz - 1;
        memcpy(params, p, len);
        params[len] = '\0';
    }

    return 0;
}

const char *sc_irc_check_highlight(const char *text, const char *nick)
{
    if (!text || !nick) return NULL;
    size_t nick_len = strlen(nick);
    if (nick_len == 0) return NULL;

    if (strncasecmp(text, nick, nick_len) != 0) return NULL;

    char sep = text[nick_len];
    if (sep != ':' && sep != ',') return NULL;

    const char *content = text + nick_len + 1;
    while (*content == ' ') content++;
    return content;
}

int sc_irc_check_mention(const char *text, const char *nick)
{
    if (!text || !nick) return 0;
    size_t nick_len = strlen(nick);
    if (nick_len == 0) return 0;

    const char *p = text;
    while (*p) {
        /* Case-insensitive search for nick */
        const char *found = p;
        while (*found) {
            if (strncasecmp(found, nick, nick_len) == 0)
                break;
            found++;
        }
        if (*found == '\0') return 0;

        /* Check preceding char: start-of-string, space, or @ */
        if (found != text) {
            char before = found[-1];
            if (before != ' ' && before != '@') {
                p = found + 1;
                continue;
            }
        }

        /* Check following char: end-of-string, space, or punctuation */
        char after = found[nick_len];
        if (after == '\0' || after == ' ' || after == ':' ||
            after == ',' || after == '!' || after == '?' || after == '.') {
            return 1;
        }

        p = found + 1;
    }
    return 0;
}

char **sc_irc_split_message(const char *text, int max_len, int *count)
{
    if (!text || !count || max_len <= 0) {
        if (count) *count = 0;
        return NULL;
    }

    /* Split by newlines first, then by max_len within each line.
     * IRC treats \n as a line terminator so each PRIVMSG must be
     * a single line. */
    int cap = 16;
    char **chunks = calloc((size_t)cap, sizeof(char *));
    if (!chunks) { *count = 0; return NULL; }

    *count = 0;
    const char *p = text;

    while (*p) {
        /* Find end of this line */
        const char *eol = strchr(p, '\n');
        size_t line_len = eol ? (size_t)(eol - p) : strlen(p);

        /* Strip trailing \r */
        while (line_len > 0 && p[line_len - 1] == '\r') line_len--;

        /* Skip blank lines */
        if (line_len == 0) {
            p = eol ? eol + 1 : p + strlen(p);
            continue;
        }

        /* Split this line into max_len chunks */
        size_t offset = 0;
        while (offset < line_len) {
            size_t chunk_len = line_len - offset;
            if (chunk_len > (size_t)max_len) chunk_len = (size_t)max_len;

            /* Grow array if needed */
            if (*count >= cap) {
                int new_cap = cap * 2;
                char **tmp = realloc(chunks, (size_t)new_cap * sizeof(char *));
                if (!tmp) {
                    for (int k = 0; k < *count; k++) free(chunks[k]);
                    free(chunks);
                    *count = 0;
                    return NULL;
                }
                chunks = tmp;
                cap = new_cap;
            }

            chunks[*count] = malloc(chunk_len + 1);
            if (!chunks[*count]) return chunks;
            memcpy(chunks[*count], p + offset, chunk_len);
            chunks[*count][chunk_len] = '\0';
            (*count)++;
            offset += chunk_len;
        }

        p = eol ? eol + 1 : p + strlen(p);
    }

    return chunks;
}

/* ------------------------------------------------------------------ */
/* Socket I/O                                                          */
/* ------------------------------------------------------------------ */

static int irc_send_raw(irc_data_t *id, const char *line)
{
    size_t len = strlen(line);
    if (id->ssl) {
        int written = SSL_write(id->ssl, line, (int)len);
        return (written > 0) ? 0 : -1;
    }
    ssize_t written = write(id->sockfd, line, len);
    return (written > 0) ? 0 : -1;
}

static int irc_send_line(irc_data_t *id, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static int irc_send_line(irc_data_t *id, const char *fmt, ...)
{
    char buf[IRC_MAX_LINE];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf) - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    /* Ensure \r\n termination */
    if (n > (int)sizeof(buf) - 3) n = (int)sizeof(buf) - 3;
    buf[n] = '\r';
    buf[n + 1] = '\n';
    buf[n + 2] = '\0';
    return irc_send_raw(id, buf);
}

/* Read one \r\n-terminated line with poll() timeout.
 * Returns instance buffer, or NULL on error/EOF.
 * Sets *timed_out to 1 if the call returned due to timeout (no data). */
static char *irc_recv_line_timeout(irc_data_t *id, int timeout_ms,
                                    int *timed_out)
{
    if (timed_out) *timed_out = 0;

    for (;;) {
        /* Check if we already have a complete line in the buffer */
        for (int i = 0; i < id->recvbuf_len - 1; i++) {
            if (id->recvbuf[i] == '\r' && id->recvbuf[i + 1] == '\n') {
                int line_len = i;
                if (line_len >= IRC_RECV_BUF) line_len = IRC_RECV_BUF - 1;
                memcpy(id->linebuf, id->recvbuf, (size_t)line_len);
                id->linebuf[line_len] = '\0';
                /* Shift buffer */
                int consumed = i + 2;
                id->recvbuf_len -= consumed;
                if (id->recvbuf_len > 0)
                    memmove(id->recvbuf, id->recvbuf + consumed, (size_t)id->recvbuf_len);
                return id->linebuf;
            }
        }

        /* Also check for bare \n (some servers use that) */
        for (int i = 0; i < id->recvbuf_len; i++) {
            if (id->recvbuf[i] == '\n') {
                int line_len = i;
                if (line_len > 0 && id->recvbuf[line_len - 1] == '\r') line_len--;
                if (line_len >= IRC_RECV_BUF) line_len = IRC_RECV_BUF - 1;
                memcpy(id->linebuf, id->recvbuf, (size_t)line_len);
                id->linebuf[line_len] = '\0';
                int consumed = i + 1;
                id->recvbuf_len -= consumed;
                if (id->recvbuf_len > 0)
                    memmove(id->recvbuf, id->recvbuf + consumed, (size_t)id->recvbuf_len);
                return id->linebuf;
            }
        }

        /* Need more data */
        if (id->recvbuf_len >= IRC_RECV_BUF - 1) {
            /* Buffer full without a newline — discard */
            id->recvbuf_len = 0;
        }

        /* Wait for data with timeout (skip poll for TLS — SSL may have
         * buffered data that poll() can't see) */
        if (!id->ssl && timeout_ms > 0) {
            struct pollfd pfd = { .fd = id->sockfd, .events = POLLIN };
            int pr = poll(&pfd, 1, timeout_ms);
            if (pr == 0) {
                if (timed_out) *timed_out = 1;
                return NULL; /* timeout */
            }
            if (pr < 0) return NULL; /* error */
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
                return NULL;
        }

        int space = IRC_RECV_BUF - 1 - id->recvbuf_len;
        int n;
        if (id->ssl) {
            n = SSL_read(id->ssl, id->recvbuf + id->recvbuf_len, space);
        } else {
            n = (int)read(id->sockfd, id->recvbuf + id->recvbuf_len, (size_t)space);
        }
        if (n <= 0) return NULL;
        id->recvbuf_len += n;
    }
}

/* Backwards-compatible wrapper */
static char *irc_recv_line(irc_data_t *id)
{
    return irc_recv_line_timeout(id, -1, NULL);
}

/* ------------------------------------------------------------------ */
/* Connection                                                          */
/* ------------------------------------------------------------------ */

static void irc_close_socket(irc_data_t *id)
{
    if (id->ssl) {
        SSL_shutdown(id->ssl);
        SSL_free(id->ssl);
        id->ssl = NULL;
    }
    if (id->ssl_ctx) {
        SSL_CTX_free(id->ssl_ctx);
        id->ssl_ctx = NULL;
    }
    if (id->sockfd >= 0) {
        close(id->sockfd);
        id->sockfd = -1;
    }
    id->recvbuf_len = 0;
}

static int irc_connect(irc_data_t *id)
{
    /* Resolve hostname */
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", id->port);

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int err = getaddrinfo(id->hostname, port_str, &hints, &res);
    if (err != 0 || !res) {
        SC_LOG_ERROR(IRC_TAG, "DNS resolution failed for %s: %s",
                     id->hostname, gai_strerror(err));
        return -1;
    }

    /* Connect */
    id->sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (id->sockfd < 0) {
        SC_LOG_ERROR(IRC_TAG, "socket() failed: %s", strerror(errno));
        freeaddrinfo(res);
        return -1;
    }

    if (connect(id->sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        SC_LOG_ERROR(IRC_TAG, "connect() to %s:%d failed: %s",
                     id->hostname, id->port, strerror(errno));
        close(id->sockfd);
        id->sockfd = -1;
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    SC_LOG_INFO(IRC_TAG, "TCP connected to %s:%d", id->hostname, id->port);

    /* TLS handshake */
    if (id->use_tls) {
        id->ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!id->ssl_ctx) {
            SC_LOG_ERROR(IRC_TAG, "SSL_CTX_new failed");
            close(id->sockfd);
            id->sockfd = -1;
            return -1;
        }

        SSL_CTX_set_default_verify_paths(id->ssl_ctx);
        SSL_CTX_set_verify(id->ssl_ctx, SSL_VERIFY_PEER, NULL);

        id->ssl = SSL_new(id->ssl_ctx);
        if (!id->ssl) {
            SC_LOG_ERROR(IRC_TAG, "SSL_new failed");
            irc_close_socket(id);
            return -1;
        }

        SSL_set_fd(id->ssl, id->sockfd);
        SSL_set_tlsext_host_name(id->ssl, id->hostname);
        SSL_set1_host(id->ssl, id->hostname);

        if (SSL_connect(id->ssl) != 1) {
            SC_LOG_ERROR(IRC_TAG, "TLS handshake failed");
            irc_close_socket(id);
            return -1;
        }

        SC_LOG_INFO(IRC_TAG, "TLS handshake completed");
    }

    /* IRC registration */
    if (id->password && id->password[0]) {
        irc_send_line(id, "PASS %s", id->password);
    }
    irc_send_line(id, "NICK %s", id->nick);
    irc_send_line(id, "USER %s 0 * :%s",
                  id->username ? id->username : id->nick, id->nick);

    /* Wait for RPL_WELCOME (001) */
    int registered = 0;
    for (int i = 0; i < 100 && !registered; i++) {
        char *line = irc_recv_line(id);
        if (!line) {
            SC_LOG_ERROR(IRC_TAG, "Connection lost during registration");
            irc_close_socket(id);
            return -1;
        }

        SC_LOG_DEBUG(IRC_TAG, "< %s", line);

        char prefix[256], command[32], params[IRC_RECV_BUF];
        if (sc_irc_parse_message(line, prefix, sizeof(prefix),
                                 command, sizeof(command),
                                 params, sizeof(params)) == 0) {
            if (strcmp(command, "PING") == 0) {
                irc_send_line(id, "PONG :%s", params);
            } else if (strcmp(command, "001") == 0) {
                registered = 1;
            } else if (strcmp(command, "433") == 0) {
                /* Nick in use — try with underscore */
                sc_strbuf_t sb;
                sc_strbuf_init(&sb);
                sc_strbuf_appendf(&sb, "%s_", id->nick);
                free(id->nick);
                id->nick = sc_strbuf_finish(&sb);
                irc_send_line(id, "NICK %s", id->nick);
                SC_LOG_WARN(IRC_TAG, "Nick in use, trying %s", id->nick);
            }
        }
    }

    if (!registered) {
        SC_LOG_ERROR(IRC_TAG, "Failed to register with IRC server");
        irc_close_socket(id);
        return -1;
    }

    SC_LOG_INFO(IRC_TAG, "Registered as %s", id->nick);

    /* Join configured channels */
    for (int i = 0; i < id->channel_count; i++) {
        if (id->channels[i] && id->channels[i][0]) {
            irc_send_line(id, "JOIN %s", id->channels[i]);
            SC_LOG_INFO(IRC_TAG, "Joining %s", id->channels[i]);
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Receive thread                                                      */
/* ------------------------------------------------------------------ */

/* Extract nick from IRC prefix "nick!user@host" */
static char *extract_nick(const char *prefix)
{
    if (!prefix) return NULL;
    const char *bang = strchr(prefix, '!');
    if (bang) {
        size_t len = (size_t)(bang - prefix);
        char *nick = malloc(len + 1);
        if (nick) {
            memcpy(nick, prefix, len);
            nick[len] = '\0';
        }
        return nick;
    }
    return sc_strdup(prefix);
}

/* Extract target and content from PRIVMSG params: "<target> <content>" */
static int parse_privmsg(const char *params, char *target, size_t target_sz,
                         char *content, size_t content_sz)
{
    if (!params) return -1;

    const char *space = strchr(params, ' ');
    if (!space) return -1;

    size_t tlen = (size_t)(space - params);
    if (tlen >= target_sz) tlen = target_sz - 1;
    memcpy(target, params, tlen);
    target[tlen] = '\0';

    /* Content is after space, skip leading : if present */
    const char *c = space + 1;
    while (*c == ' ') c++;
    /* The params already have trailing joined — content is what's left */
    size_t clen = strlen(c);
    if (clen >= content_sz) clen = content_sz - 1;
    memcpy(content, c, clen);
    content[clen] = '\0';

    return 0;
}

static void *recv_thread(void *arg)
{
    sc_channel_t *ch = arg;
    irc_data_t *id = ch->data;

    SC_LOG_INFO(IRC_TAG, "Receive thread started");

    int backoff = IRC_RECONNECT_DELAY;
    time_t last_recv = 0;
    int ping_pending = 0;

    while (ch->running) {
        if (id->sockfd < 0) {
            /* Need to connect/reconnect */
            SC_LOG_INFO(IRC_TAG, "Connecting to %s:%d...", id->hostname, id->port);
            if (irc_connect(id) != 0) {
                SC_LOG_WARN(IRC_TAG, "Connection failed, retrying in %ds", backoff);
                sc_channel_sleep(&ch->running, backoff);
                if (backoff < IRC_RECONNECT_MAX_DELAY)
                    backoff *= 2;
                if (backoff > IRC_RECONNECT_MAX_DELAY)
                    backoff = IRC_RECONNECT_MAX_DELAY;
                continue;
            }
            backoff = IRC_RECONNECT_DELAY; /* reset on success */
            last_recv = time(NULL);
            ping_pending = 0;
        }

        /* Use keepalive timeout for poll:
         * - If ping is pending, wait KEEPALIVE_TIMEOUT for PONG
         * - Otherwise, wait KEEPALIVE_INTERVAL before sending PING */
        int timeout_ms = ping_pending
            ? IRC_KEEPALIVE_TIMEOUT * 1000
            : IRC_KEEPALIVE_INTERVAL * 1000;

        int timed_out = 0;
        char *line = irc_recv_line_timeout(id, timeout_ms, &timed_out);

        if (!line && timed_out) {
            if (ping_pending) {
                /* No PONG received — connection is dead */
                SC_LOG_WARN(IRC_TAG, "No PONG received in %ds — connection dead",
                            IRC_KEEPALIVE_TIMEOUT);
                irc_close_socket(id);
                sc_channel_sleep(&ch->running, backoff);
                continue;
            }
            /* Idle too long — send keepalive PING */
            SC_LOG_DEBUG(IRC_TAG, "Idle %ds, sending keepalive PING",
                         IRC_KEEPALIVE_INTERVAL);
            if (irc_send_line(id, "PING :smolclaw-keepalive") != 0) {
                SC_LOG_WARN(IRC_TAG, "Failed to send keepalive PING");
                irc_close_socket(id);
                sc_channel_sleep(&ch->running, backoff);
                continue;
            }
            ping_pending = 1;
            continue;
        }

        if (!line) {
            if (!ch->running) break;
            SC_LOG_WARN(IRC_TAG, "Connection lost, reconnecting in %ds", backoff);
            irc_close_socket(id);
            sc_channel_sleep(&ch->running, backoff);
            if (backoff < IRC_RECONNECT_MAX_DELAY)
                backoff *= 2;
            if (backoff > IRC_RECONNECT_MAX_DELAY)
                backoff = IRC_RECONNECT_MAX_DELAY;
            continue;
        }

        /* Got data — reset keepalive state */
        last_recv = time(NULL);
        (void)last_recv; /* used for debugging; keepalive is timer-based */
        ping_pending = 0;

        SC_LOG_DEBUG(IRC_TAG, "< %s", line);

        char prefix[256], command[32], params[IRC_RECV_BUF];
        if (sc_irc_parse_message(line, prefix, sizeof(prefix),
                                 command, sizeof(command),
                                 params, sizeof(params)) != 0) {
            continue;
        }

        /* PING keepalive */
        if (strcmp(command, "PING") == 0) {
            irc_send_line(id, "PONG :%s", params);
            continue;
        }

        /* PRIVMSG — channel messages and DMs */
        if (strcmp(command, "PRIVMSG") == 0) {
            char target[256], content[IRC_RECV_BUF];
            if (parse_privmsg(params, target, sizeof(target),
                              content, sizeof(content)) != 0) {
                continue;
            }

            char *sender_nick = extract_nick(prefix);
            if (!sender_nick) continue;

            /* Skip messages from ourselves */
            if (strcasecmp(sender_nick, id->nick) == 0) {
                free(sender_nick);
                continue;
            }

            const char *msg_content = content;
            int is_channel = (target[0] == '#' || target[0] == '&');

            if (is_channel) {
                /* Channel message — respond to highlights, mentions, and group trigger */
                const char *highlighted = sc_irc_check_highlight(content, id->nick);
                if (highlighted) {
                    msg_content = highlighted;  /* prefix match — strip nick */
                } else if (id->group_trigger && id->group_trigger[0]) {
                    const char *group_hit = sc_irc_check_highlight(content, id->group_trigger);
                    if (group_hit)
                        msg_content = group_hit;  /* group trigger — strip trigger word */
                    else if (sc_irc_check_mention(content, id->nick))
                        msg_content = content;
                    else { free(sender_nick); continue; }
                } else if (sc_irc_check_mention(content, id->nick)) {
                    msg_content = content;      /* mid-message mention — full text */
                } else {
                    free(sender_nick);
                    continue;
                }
            }

            /* For DMs, target is our nick — use sender as chat_id for replies */
            const char *chat_id = is_channel ? target : sender_nick;

            sc_channel_handle_message(ch, sender_nick, chat_id, msg_content);
            free(sender_nick);
        }
    }

    SC_LOG_INFO(IRC_TAG, "Receive thread stopped");
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Channel vtable                                                      */
/* ------------------------------------------------------------------ */

static int irc_start(sc_channel_t *self)
{
    irc_data_t *id = self->data;

    self->running = 1;
    id->thread_started = 1;

    int ret = pthread_create(&id->recv_thread, NULL, recv_thread, self);
    if (ret != 0) {
        SC_LOG_ERROR(IRC_TAG, "Failed to create receive thread");
        self->running = 0;
        id->thread_started = 0;
        return -1;
    }

    SC_LOG_INFO(IRC_TAG, "IRC channel started");
    return 0;
}

static int irc_stop(sc_channel_t *self)
{
    irc_data_t *id = self->data;

    self->running = 0;

    /* Unblock recv by shutting down socket */
    if (id->sockfd >= 0) {
        shutdown(id->sockfd, SHUT_RDWR);
    }

    if (id->thread_started)
        pthread_join(id->recv_thread, NULL);

    SC_LOG_INFO(IRC_TAG, "IRC channel stopped");
    return 0;
}

/* Strip control characters to prevent IRC command injection.
 * Removes 0x00-0x1F (except tab 0x09) and DEL (0x7F). */
static void sanitize_irc_string(char *s)
{
    char *dst = s;
    for (const char *src = s; *src; src++) {
        unsigned char c = (unsigned char)*src;
        if (c < 0x20 && c != 0x09) continue; /* strip control chars except tab */
        if (c == 0x7F) continue; /* DEL */
        *dst++ = *src;
    }
    *dst = '\0';
}

static int irc_send(sc_channel_t *self, sc_outbound_msg_t *msg)
{
    if (!self->running) return -1;
    irc_data_t *id = self->data;

    if (id->sockfd < 0) return -1;

    /* Sanitize chat_id to prevent CRLF injection */
    char *safe_chat_id = sc_strdup(msg->chat_id);
    if (!safe_chat_id) return -1;
    sanitize_irc_string(safe_chat_id);

    int chunk_count = 0;
    char **chunks = sc_irc_split_message(msg->content, IRC_MSG_CHUNK, &chunk_count);
    if (!chunks) { free(safe_chat_id); return -1; }

    int ret = 0;
    for (int i = 0; i < chunk_count; i++) {
        if (irc_send_line(id, "PRIVMSG %s :%s", safe_chat_id, chunks[i]) != 0) {
            ret = -1;
            break;
        }
    }

    for (int i = 0; i < chunk_count; i++)
        free(chunks[i]);
    free(chunks);
    free(safe_chat_id);

    return ret;
}

static int irc_is_running(sc_channel_t *self)
{
    return self ? self->running : 0;
}

static void irc_destroy(sc_channel_t *self)
{
    if (!self) return;
    irc_data_t *id = self->data;
    if (id) {
        irc_close_socket(id);
        free(id->hostname);
        free(id->nick);
        free(id->username);
        free(id->password);
        free(id->group_trigger);
        for (int i = 0; i < id->channel_count; i++)
            free(id->channels[i]);
        free(id->channels);
        free(id);
    }
    self->data = NULL;
    sc_channel_base_free(self);
}

/* ------------------------------------------------------------------ */
/* Constructor                                                         */
/* ------------------------------------------------------------------ */

sc_channel_t *sc_channel_irc_new(sc_irc_config_t *cfg, sc_bus_t *bus)
{
    if (!cfg || !cfg->hostname || !cfg->nick) return NULL;

    sc_channel_t *ch = calloc(1, sizeof(*ch));
    if (!ch) return NULL;

    irc_data_t *id = calloc(1, sizeof(*id));
    if (!id) { free(ch); return NULL; }

    id->hostname = sc_strdup(cfg->hostname);
    id->port = cfg->port > 0 ? cfg->port : 6667;
    id->nick = sc_strdup(cfg->nick);
    id->username = sc_strdup(cfg->username ? cfg->username : cfg->nick);
    id->password = sc_strdup(cfg->password);
    id->group_trigger = sc_strdup(cfg->group_trigger);
    id->use_tls = cfg->use_tls;
    id->sockfd = -1;
    id->recvbuf_len = 0;

    /* Copy join channels */
    if (cfg->join_channel_count > 0 && cfg->join_channels) {
        id->channel_count = cfg->join_channel_count;
        id->channels = calloc((size_t)cfg->join_channel_count, sizeof(char *));
        for (int i = 0; i < cfg->join_channel_count; i++) {
            id->channels[i] = sc_strdup(cfg->join_channels[i]);
        }
    }

    ch->name = SC_CHANNEL_IRC;
    ch->start = irc_start;
    ch->stop = irc_stop;
    ch->send = irc_send;
    ch->is_running = irc_is_running;
    ch->destroy = irc_destroy;
    ch->bus = bus;
    ch->running = 0;
    ch->data = id;

    sc_channel_init_security(ch, cfg->dm_policy, cfg->allow_from,
                              cfg->allow_from_count, "irc");

    return ch;
}
