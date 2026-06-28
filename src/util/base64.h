#ifndef SC_BASE64_H
#define SC_BASE64_H

#include <stddef.h>

/* Encode data to base64. Returns newly allocated string. */
char *sc_base64_encode(const unsigned char *data, size_t len);

/* Decode base64 string. Returns newly allocated buffer, sets out_len. */
unsigned char *sc_base64_decode(const char *b64, size_t *out_len);

/* base64url (RFC 4648 §5): '+'->'-', '/'->'_', no '=' padding.
 * Used for OAuth PKCE / JWT (task 2.1). Returns newly allocated string. */
char *sc_base64url_encode(const unsigned char *data, size_t len);

/* Decode a base64url string (padding optional). Returns newly allocated
 * buffer, sets out_len. NULL on error. */
unsigned char *sc_base64url_decode(const char *b64url, size_t *out_len);

#endif /* SC_BASE64_H */
