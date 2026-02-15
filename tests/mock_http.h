/*
 * mock_http.h - Header-only mock HTTP server for tests
 *
 * Uses libevent evhttp (already linked via smolclaw_lib).
 * Runs in a background thread, serves canned responses based on routes.
 */

#ifndef SC_MOCK_HTTP_H
#define SC_MOCK_HTTP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/thread.h>
#include <event2/keyvalq_struct.h>

/* Route definition: method + path -> status + body */
typedef struct {
    const char *method;       /* "GET", "POST", or NULL for any */
    const char *path;         /* "/v1/chat/completions", NULL = catch-all */
    int status;               /* HTTP status code */
    const char *content_type; /* NULL defaults to "application/json" */
    const char *body;         /* Response body string */
} sc_mock_route_t;

/* Captured request */
typedef struct {
    char *method;
    char *uri;
    char *body;
} sc_mock_request_t;

/* Mock server state */
typedef struct {
    struct event_base *base;
    struct evhttp *http;
    struct event *stop_event;
    int stop_pipe[2];         /* write to [1] to trigger stop */
    pthread_t thread;
    int port;
    char url[64];             /* "http://127.0.0.1:<port>" */
    sc_mock_route_t *routes;
    int route_count;
    pthread_mutex_t lock;
    sc_mock_request_t last_request;
    int request_count;
} sc_mock_http_t;

static const char *mock_method_str(enum evhttp_cmd_type cmd)
{
    switch (cmd) {
    case EVHTTP_REQ_GET:    return "GET";
    case EVHTTP_REQ_POST:   return "POST";
    case EVHTTP_REQ_PUT:    return "PUT";
    case EVHTTP_REQ_DELETE: return "DELETE";
    default:                return "UNKNOWN";
    }
}

static void mock_generic_cb(struct evhttp_request *req, void *arg)
{
    sc_mock_http_t *mock = arg;
    enum evhttp_cmd_type cmd = evhttp_request_get_command(req);
    const char *uri = evhttp_request_get_uri(req);
    const char *method = mock_method_str(cmd);

    /* Read request body */
    struct evbuffer *input = evhttp_request_get_input_buffer(req);
    size_t body_len = evbuffer_get_length(input);
    char *body = NULL;
    if (body_len > 0) {
        body = malloc(body_len + 1);
        evbuffer_copyout(input, body, body_len);
        body[body_len] = '\0';
    }

    /* Record request under lock */
    pthread_mutex_lock(&mock->lock);
    free(mock->last_request.method);
    free(mock->last_request.uri);
    free(mock->last_request.body);
    mock->last_request.method = strdup(method);
    mock->last_request.uri = strdup(uri);
    mock->last_request.body = body ? strdup(body) : NULL;
    mock->request_count++;
    pthread_mutex_unlock(&mock->lock);

    /* Match route (first match wins) */
    sc_mock_route_t *matched = NULL;
    for (int i = 0; i < mock->route_count; i++) {
        sc_mock_route_t *r = &mock->routes[i];
        if (r->method && strcmp(r->method, method) != 0)
            continue;
        if (r->path && strcmp(r->path, uri) != 0)
            continue;
        matched = r;
        break;
    }

    struct evbuffer *buf = evbuffer_new();
    if (matched) {
        const char *ct = matched->content_type ? matched->content_type : "application/json";
        evhttp_add_header(evhttp_request_get_output_headers(req),
                          "Content-Type", ct);
        if (matched->body)
            evbuffer_add(buf, matched->body, strlen(matched->body));
        evhttp_send_reply(req, matched->status, "OK", buf);
    } else {
        evhttp_send_reply(req, 404, "Not Found", buf);
    }
    evbuffer_free(buf);
    free(body);
}

/* Pipe read callback: stop the event loop */
static void mock_stop_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    char buf[1];
    (void)read(fd, buf, 1);
    event_base_loopbreak(((sc_mock_http_t *)arg)->base);
}

static void *mock_thread_fn(void *arg)
{
    sc_mock_http_t *mock = arg;
    event_base_dispatch(mock->base);
    return NULL;
}

static sc_mock_http_t *sc_mock_http_start(sc_mock_route_t *routes, int count)
{
    sc_mock_http_t *mock = calloc(1, sizeof(*mock));
    if (!mock) return NULL;

    pthread_mutex_init(&mock->lock, NULL);
    mock->routes = routes;
    mock->route_count = count;

    /* Enable threading for thread-safe event base operations */
    evthread_use_pthreads();

    mock->base = event_base_new();
    if (!mock->base) { free(mock); return NULL; }

    mock->http = evhttp_new(mock->base);
    if (!mock->http) {
        event_base_free(mock->base);
        free(mock);
        return NULL;
    }

    /* Stop pipe: writing to [1] triggers the stop callback in the event loop */
    if (pipe(mock->stop_pipe) != 0) {
        evhttp_free(mock->http);
        event_base_free(mock->base);
        free(mock);
        return NULL;
    }
    mock->stop_event = event_new(mock->base, mock->stop_pipe[0],
                                  EV_READ | EV_PERSIST, mock_stop_cb, mock);
    event_add(mock->stop_event, NULL);

    /* Bind to random port on localhost */
    struct evhttp_bound_socket *bound =
        evhttp_bind_socket_with_handle(mock->http, "127.0.0.1", 0);
    if (!bound) {
        event_free(mock->stop_event);
        close(mock->stop_pipe[0]);
        close(mock->stop_pipe[1]);
        evhttp_free(mock->http);
        event_base_free(mock->base);
        free(mock);
        return NULL;
    }

    /* Get the assigned port */
    evutil_socket_t fd = evhttp_bound_socket_get_fd(bound);
    struct sockaddr_in sin;
    socklen_t slen = sizeof(sin);
    getsockname(fd, (struct sockaddr *)&sin, &slen);
    mock->port = ntohs(sin.sin_port);
    snprintf(mock->url, sizeof(mock->url), "http://127.0.0.1:%d", mock->port);

    evhttp_set_gencb(mock->http, mock_generic_cb, mock);

    /* Socket is listening before thread starts — no race */
    pthread_create(&mock->thread, NULL, mock_thread_fn, mock);

    return mock;
}

__attribute__((unused))
static const char *sc_mock_http_url(sc_mock_http_t *mock)
{
    return mock->url;
}

__attribute__((unused))
static sc_mock_request_t sc_mock_http_last_request(sc_mock_http_t *mock)
{
    sc_mock_request_t copy = {0};
    pthread_mutex_lock(&mock->lock);
    copy.method = mock->last_request.method ? strdup(mock->last_request.method) : NULL;
    copy.uri = mock->last_request.uri ? strdup(mock->last_request.uri) : NULL;
    copy.body = mock->last_request.body ? strdup(mock->last_request.body) : NULL;
    pthread_mutex_unlock(&mock->lock);
    return copy;
}

__attribute__((unused))
static void sc_mock_request_free(sc_mock_request_t *req)
{
    free(req->method);
    free(req->uri);
    free(req->body);
    req->method = NULL;
    req->uri = NULL;
    req->body = NULL;
}

static void sc_mock_http_stop(sc_mock_http_t *mock)
{
    if (!mock) return;

    /* Write to stop pipe — this reliably wakes the event loop thread */
    (void)write(mock->stop_pipe[1], "x", 1);
    pthread_join(mock->thread, NULL);

    event_free(mock->stop_event);
    close(mock->stop_pipe[0]);
    close(mock->stop_pipe[1]);
    evhttp_free(mock->http);
    event_base_free(mock->base);
    free(mock->last_request.method);
    free(mock->last_request.uri);
    free(mock->last_request.body);
    pthread_mutex_destroy(&mock->lock);
    free(mock);
}

#endif /* SC_MOCK_HTTP_H */
