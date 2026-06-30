#ifndef SC_COMPANION_ROUTES_H
#define SC_COMPANION_ROUTES_H

struct evhttp_request;

void sc_companion_handle_capabilities(struct evhttp_request *req, void *arg);
void sc_companion_handle_snap(struct evhttp_request *req, void *arg);

#endif /* SC_COMPANION_ROUTES_H */