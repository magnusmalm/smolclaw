/*
 * updater/transport_http.h — HTTP transport for self-update
 */

#ifndef SC_UPDATER_TRANSPORT_HTTP_H
#define SC_UPDATER_TRANSPORT_HTTP_H

#include "updater/types.h"

/* Create an HTTP transport that fetches manifest from the given URL.
 * Binary URLs come from the manifest itself. */
sc_update_transport_t *sc_update_transport_http_new(const char *manifest_url);

#endif /* SC_UPDATER_TRANSPORT_HTTP_H */
