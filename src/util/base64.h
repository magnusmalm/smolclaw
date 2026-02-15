#ifndef SC_BASE64_H
#define SC_BASE64_H

#include <stddef.h>

/* Encode data to base64. Returns newly allocated string. */
char *sc_base64_encode(const unsigned char *data, size_t len);

/* Decode base64 string. Returns newly allocated buffer, sets out_len. */
unsigned char *sc_base64_decode(const char *b64, size_t *out_len);

#endif /* SC_BASE64_H */
