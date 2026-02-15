#ifndef SC_JSON_HELPERS_H
#define SC_JSON_HELPERS_H

#include "cJSON.h"

/* Safe getters (return default on missing/wrong type) */
const char *sc_json_get_string(const cJSON *obj, const char *key, const char *def);
int sc_json_get_int(const cJSON *obj, const char *key, int def);
double sc_json_get_double(const cJSON *obj, const char *key, double def);
int sc_json_get_bool(const cJSON *obj, const char *key, int def);
cJSON *sc_json_get_array(const cJSON *obj, const char *key);
cJSON *sc_json_get_object(const cJSON *obj, const char *key);

/* Load JSON from file. Returns NULL on error. Caller owns result. */
cJSON *sc_json_load_file(const char *path);

/* Save JSON to file atomically (write tmp + rename).
 * Returns 0 on success, -1 on error. */
int sc_json_save_file(const char *path, const cJSON *json);

/* Get string array from cJSON array. Returns count, fills out array.
 * Strings are borrowed from cJSON (do not free individually). */
int sc_json_get_string_array(const cJSON *arr, const char **out, int max);

/* Parse a cJSON string array into a newly-allocated char** (sc_strdup'd).
 * Sets *out_count. Returns the array (caller frees each element + array). */
char **sc_json_parse_string_list(const cJSON *arr, int *out_count);

/* JSON Schema helpers for tool parameter definitions */
cJSON *sc_schema_new(void);
void sc_schema_add_string(cJSON *schema, const char *name,
                          const char *desc, int required);
void sc_schema_add_integer(cJSON *schema, const char *name,
                           const char *desc, int required);

#endif /* SC_JSON_HELPERS_H */
