/*
 * updater/types.h — Transport vtable and data types for self-update
 */

#ifndef SC_UPDATER_TYPES_H
#define SC_UPDATER_TYPES_H

#include <stddef.h>

/* Semantic version */
typedef struct sc_semver {
    int major;
    int minor;
    int patch;
} sc_semver_t;

/* Single binary artifact for a specific architecture */
typedef struct sc_update_artifact {
    char *arch;
    char *url;
    char *sha256;
    size_t size;
} sc_update_artifact_t;

/* Parsed update manifest */
typedef struct sc_update_manifest {
    char *latest;              /* latest version string, e.g. "0.2.0" */
    sc_semver_t latest_ver;    /* parsed semver */
    char *changelog;           /* changelog for latest version */
    sc_update_artifact_t artifact;  /* resolved artifact for current arch */
} sc_update_manifest_t;

/* Result of fetching a binary */
typedef struct sc_fetch_result {
    char *path;        /* path to downloaded temp file */
    size_t size;       /* file size in bytes */
    int success;
    char *error;       /* error message if !success */
} sc_fetch_result_t;

/* Transport vtable — abstraction for manifest + binary fetching */
typedef struct sc_update_transport {
    const char *name;  /* "http", "tftp", "uart" */
    sc_update_manifest_t *(*fetch_manifest)(struct sc_update_transport *self);
    sc_fetch_result_t *(*fetch_binary)(struct sc_update_transport *self,
                                       const sc_update_artifact_t *artifact);
    void (*destroy)(struct sc_update_transport *self);
    void *data;
} sc_update_transport_t;

/* Free functions */
void sc_update_manifest_free(sc_update_manifest_t *m);
void sc_fetch_result_free(sc_fetch_result_t *r);

#endif /* SC_UPDATER_TYPES_H */
