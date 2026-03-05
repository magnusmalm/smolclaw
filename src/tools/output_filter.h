#ifndef SC_OUTPUT_FILTER_H
#define SC_OUTPUT_FILTER_H

#include <stddef.h>

typedef enum {
    SC_FILTER_NONE = 0,
    SC_FILTER_CARGO_TEST,
    SC_FILTER_CARGO_BUILD,
    SC_FILTER_GIT_STATUS,
    SC_FILTER_GIT_DIFF,
    SC_FILTER_PYTEST,
    SC_FILTER_NPM_TEST,
} sc_filter_type_t;

/* Detect filter type from command string. Returns SC_FILTER_NONE if no match. */
sc_filter_type_t sc_filter_detect(const char *command);

/* Apply filter to raw output. Returns allocated filtered string, or NULL
 * if filtering would not significantly reduce size (<50% reduction). */
char *sc_filter_apply(sc_filter_type_t type, const char *raw, size_t len);

#endif /* SC_OUTPUT_FILTER_H */
