#include "companion/random.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

int sc_companion_random_bytes(unsigned char *buf, size_t nbytes)
{
    if (!buf || nbytes == 0) return -1;

    size_t done = 0;
#if defined(__linux__)
    while (done < nbytes) {
        ssize_t n = getrandom(buf + done, nbytes - done, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        done += (size_t)n;
    }
#endif
    if (done == nbytes) return 0;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    while (done < nbytes) {
        ssize_t n = read(fd, buf + done, nbytes - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (n == 0) break;
        done += (size_t)n;
    }
    close(fd);
    return (done == nbytes) ? 0 : -1;
}