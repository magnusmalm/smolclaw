/*
 * updater/updater.h — Self-update public API
 */

#ifndef SC_UPDATER_H
#define SC_UPDATER_H

#include "updater/types.h"

/* Updater instance */
typedef struct sc_updater {
    sc_update_transport_t *transport;
    char *binary_path;    /* resolved path to current binary */
} sc_updater_t;

/* Create updater with a transport. Takes ownership of transport. */
sc_updater_t *sc_updater_new(sc_update_transport_t *transport);

/* Free updater (and its transport). */
void sc_updater_free(sc_updater_t *u);

/* Semver parsing and comparison */
int sc_semver_parse(const char *str, sc_semver_t *out);
int sc_semver_compare(const sc_semver_t *a, const sc_semver_t *b);

/* Get architecture string from uname (e.g. "x86_64", "aarch64") */
const char *sc_updater_get_arch(void);

/* Parse manifest JSON, resolve artifact for given arch.
 * Returns NULL on error (invalid JSON, missing fields, no matching arch). */
sc_update_manifest_t *sc_updater_parse_manifest(const char *json,
                                                 const char *arch);

/* Verify downloaded file matches expected SHA-256 hash.
 * Returns 0 on match, -1 on mismatch or error. */
int sc_updater_verify(const char *path, const sc_update_artifact_t *artifact);

/* Atomically replace the running binary.
 * Creates a .bak backup, verifies ELF magic, renames new binary into place.
 * Returns 0 on success, -1 on error. */
int sc_updater_apply(const char *new_path);

/* Restore previous binary from .bak backup.
 * Returns 0 on success, -1 on error. */
int sc_updater_rollback(void);

/* Check for update: fetch manifest, compare versions.
 * Returns manifest if update available, NULL if current or error. */
sc_update_manifest_t *sc_updater_check(sc_updater_t *u);

/* Download and verify update binary. Returns staged temp path or NULL. */
sc_fetch_result_t *sc_updater_download(sc_updater_t *u,
                                        const sc_update_manifest_t *manifest);

#endif /* SC_UPDATER_H */
