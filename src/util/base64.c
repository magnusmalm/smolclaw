#include "base64.h"

#include <stdlib.h>
#include <string.h>

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *sc_base64_encode(const unsigned char *data, size_t len)
{
    if (!data && len > 0)
        return NULL;

    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    if (!out)
        return NULL;

    size_t i, j;
    for (i = 0, j = 0; i + 2 < len; i += 3) {
        unsigned int v = ((unsigned int)data[i] << 16) |
                         ((unsigned int)data[i + 1] << 8) |
                         (unsigned int)data[i + 2];
        out[j++] = b64_table[(v >> 18) & 0x3F];
        out[j++] = b64_table[(v >> 12) & 0x3F];
        out[j++] = b64_table[(v >> 6) & 0x3F];
        out[j++] = b64_table[v & 0x3F];
    }

    if (i < len) {
        unsigned int v = (unsigned int)data[i] << 16;
        if (i + 1 < len)
            v |= (unsigned int)data[i + 1] << 8;

        out[j++] = b64_table[(v >> 18) & 0x3F];
        out[j++] = b64_table[(v >> 12) & 0x3F];
        if (i + 1 < len)
            out[j++] = b64_table[(v >> 6) & 0x3F];
        else
            out[j++] = '=';
        out[j++] = '=';
    }

    out[j] = '\0';
    return out;
}

/* Decode table: maps ASCII byte to 6-bit value, 0xFF = invalid, 0xFE = padding */
static const unsigned char b64_decode_table[256] = {
    ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,
    ['G'] = 6,  ['H'] = 7,  ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11,
    ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
    ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
    ['Y'] = 24, ['Z'] = 25,
    ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31,
    ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37,
    ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41, ['q'] = 42, ['r'] = 43,
    ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47, ['w'] = 48, ['x'] = 49,
    ['y'] = 50, ['z'] = 51,
    ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57,
    ['6'] = 58, ['7'] = 59, ['8'] = 60, ['9'] = 61,
    ['+'] = 62, ['/'] = 63,
    ['='] = 0xFE,
    /* All other entries are 0 from zero-initialization */
};

/* Check if a byte is a valid base64 character */
static int b64_valid(unsigned char c)
{
    if (c == '+' || c == '/' || c == '=')
        return 1;
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= '0' && c <= '9') return 1;
    return 0;
}

unsigned char *sc_base64_decode(const char *b64, size_t *out_len)
{
    if (!b64 || !out_len)
        return NULL;

    *out_len = 0;

    /* Strip whitespace and count valid chars */
    size_t input_len = strlen(b64);
    char *clean = malloc(input_len + 1);
    if (!clean)
        return NULL;

    size_t clean_len = 0;
    for (size_t i = 0; i < input_len; i++) {
        unsigned char c = (unsigned char)b64[i];
        if (b64_valid(c))
            clean[clean_len++] = (char)c;
        /* Skip whitespace silently */
    }

    if (clean_len == 0) {
        free(clean);
        unsigned char *empty = malloc(1);
        if (empty) *out_len = 0;
        return empty;
    }

    /* Must be multiple of 4 */
    if (clean_len % 4 != 0) {
        free(clean);
        return NULL;
    }

    /* Calculate output size */
    size_t n_blocks = clean_len / 4;
    size_t decoded_len = n_blocks * 3;
    if (clean_len >= 1 && clean[clean_len - 1] == '=') decoded_len--;
    if (clean_len >= 2 && clean[clean_len - 2] == '=') decoded_len--;

    unsigned char *out = malloc(decoded_len + 1);
    if (!out) {
        free(clean);
        return NULL;
    }

    size_t j = 0;
    for (size_t i = 0; i < clean_len; i += 4) {
        unsigned char a = b64_decode_table[(unsigned char)clean[i]];
        unsigned char b = b64_decode_table[(unsigned char)clean[i + 1]];
        unsigned char c = b64_decode_table[(unsigned char)clean[i + 2]];
        unsigned char d = b64_decode_table[(unsigned char)clean[i + 3]];

        /* Replace padding marker with 0 for decoding */
        if (c == 0xFE) c = 0;
        if (d == 0xFE) d = 0;

        unsigned int triple = ((unsigned int)a << 18) |
                              ((unsigned int)b << 12) |
                              ((unsigned int)c << 6) |
                              (unsigned int)d;

        if (j < decoded_len) out[j++] = (unsigned char)((triple >> 16) & 0xFF);
        if (j < decoded_len) out[j++] = (unsigned char)((triple >> 8) & 0xFF);
        if (j < decoded_len) out[j++] = (unsigned char)(triple & 0xFF);
    }

    free(clean);
    out[decoded_len] = '\0'; /* NUL-terminate for convenience */
    *out_len = decoded_len;
    return out;
}
