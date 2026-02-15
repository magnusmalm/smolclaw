#ifndef SC_SANDBOX_H
#define SC_SANDBOX_H

typedef struct {
    const char *workspace;    /* Full path to workspace dir (rw access) */
    const char *tmpdir;       /* Temp dir (rw access), NULL = /tmp */
} sc_sandbox_opts_t;

/* Apply Landlock + seccomp sandbox. Call in child between FD cleanup and exec.
 * Returns 0 on success or graceful fallback, -1 on fatal error. */
int sc_sandbox_apply(const sc_sandbox_opts_t *opts);

/* Probe: returns bitmask of available sandbox features */
int sc_sandbox_available(void);
#define SC_SANDBOX_LANDLOCK  (1 << 0)
#define SC_SANDBOX_SECCOMP   (1 << 1)

#endif /* SC_SANDBOX_H */
