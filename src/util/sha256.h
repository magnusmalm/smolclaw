#ifndef SC_SHA256_H
#define SC_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} sc_sha256_ctx_t;

void sc_sha256_init(sc_sha256_ctx_t *ctx);
void sc_sha256_update(sc_sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void sc_sha256_final(sc_sha256_ctx_t *ctx, uint8_t hash[32]);

/* Compute SHA256 of a file. Returns malloc'd 65-byte hex string, NULL on error. */
char *sc_sha256_file(const char *path);

#endif /* SC_SHA256_H */
