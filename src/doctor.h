#ifndef SC_DOCTOR_H
#define SC_DOCTOR_H

#include "config.h"

/* Doctor output macros (also used by selftest in main.c). */
#define DOC_PASS(pass, ...) do { \
    printf("  \033[32m[PASS]\033[0m "); printf(__VA_ARGS__); printf("\n"); (*(pass))++; \
} while(0)
#define DOC_FAIL(fail, ...) do { \
    printf("  \033[31m[FAIL]\033[0m "); printf(__VA_ARGS__); printf("\n"); (*(fail))++; \
} while(0)

/* Run all doctor checks. Returns loaded config (caller must free) or NULL. */
sc_config_t *sc_run_doctor_checks(int argc, char **argv,
                                   int *out_pass, int *out_fail);

int sc_cmd_doctor(int argc, char **argv);

#endif /* SC_DOCTOR_H */