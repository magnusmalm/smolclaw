#ifndef SC_COMPANION_ROUTES_H
#define SC_COMPANION_ROUTES_H

struct evhttp_request;

void sc_companion_handle_capabilities(struct evhttp_request *req, void *arg);
void sc_companion_handle_snap(struct evhttp_request *req, void *arg);

/* P2.2 library (companion/library.c): GET list|image / DELETE on
 * /api/companion/snaps, GET / DELETE on /api/companion/notes. */
void sc_companion_handle_snaps(struct evhttp_request *req, void *arg);
void sc_companion_handle_notes(struct evhttp_request *req, void *arg);

#endif /* SC_COMPANION_ROUTES_H */