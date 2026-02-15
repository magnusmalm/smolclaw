#include "uuid.h"

#include <stdio.h>
#include <stdlib.h>

char *sc_generate_id(void)
{
    unsigned char buf[8];
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
        return NULL;

    if (fread(buf, 1, sizeof(buf), f) != sizeof(buf)) {
        fclose(f);
        return NULL;
    }
    fclose(f);

    /* 8 bytes -> 16 hex chars + NUL */
    char *id = malloc(17);
    if (!id)
        return NULL;

    snprintf(id, 17, "%02x%02x%02x%02x%02x%02x%02x%02x",
             buf[0], buf[1], buf[2], buf[3],
             buf[4], buf[5], buf[6], buf[7]);
    return id;
}
