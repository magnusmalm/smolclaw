#ifndef SC_TEE_H
#define SC_TEE_H

#include <stddef.h>

typedef struct sc_tee_config {
    char *tee_dir;          /* {workspace}/tee/ */
    int max_files;          /* ring buffer limit, default 50 */
    size_t max_file_size;   /* per-file cap, default 10 MB */
} sc_tee_config_t;

/* Initialize tee config: creates {workspace}/tee/ directory, sets defaults. */
int sc_tee_init(sc_tee_config_t *cfg, const char *workspace);

/* Save full output to disk. Returns relative path "tee/{filename}" (caller frees)
 * or NULL on error. Output is capped at max_file_size. */
char *sc_tee_save(const sc_tee_config_t *cfg, const char *output,
                  size_t output_len, const char *tool_name);

/* Free tee config fields. */
void sc_tee_config_free(sc_tee_config_t *cfg);

#endif /* SC_TEE_H */
