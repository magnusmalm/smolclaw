#ifndef SC_PORT_DIAG_H
#define SC_PORT_DIAG_H

/* Best-effort diagnostic: identify the process holding a TCP listening socket
 * on `port`. Returns a malloc'd description like "smolclaw (pid 1234)" (caller
 * frees), or NULL if the holder can't be determined (no listener found, the
 * owning PID is unresolvable due to permissions, or the platform isn't Linux).
 *
 * Linux-only: parses /proc/net/tcp{,6} for the listening socket's inode, then
 * scans /proc/<pid>/fd for the matching socket. Intended for the rare
 * bind-failure path, so the /proc scan cost is acceptable. */
char *sc_port_holder(int port);

#endif /* SC_PORT_DIAG_H */
