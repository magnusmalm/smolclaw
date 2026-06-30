#ifndef SC_COMPANION_RANDOM_H
#define SC_COMPANION_RANDOM_H

#include <stddef.h>

/* Fill buf with nbytes from getrandom(2), falling back to /dev/urandom.
 * Returns 0 on success, -1 on failure. */
int sc_companion_random_bytes(unsigned char *buf, size_t nbytes);

#endif /* SC_COMPANION_RANDOM_H */