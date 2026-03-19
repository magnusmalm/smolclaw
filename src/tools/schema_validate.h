#ifndef SC_SCHEMA_VALIDATE_H
#define SC_SCHEMA_VALIDATE_H

#include "cJSON.h"

/* Validation result */
typedef struct {
    int valid;
    char error[512]; /* Human-readable error for LLM retry */
} sc_schema_result_t;

/*
 * Validate a cJSON value against a JSON Schema (subset).
 *
 * Supported schema keywords:
 *   type       — "string", "integer", "number", "boolean", "object", "array"
 *   required   — array of required property names (on objects)
 *   properties — per-property sub-schemas (on objects)
 *   items      — element schema (on arrays)
 *   enum       — array of allowed values (strings or numbers)
 *   minimum    — minimum numeric value (inclusive)
 *   maximum    — maximum numeric value (inclusive)
 *
 * Returns { .valid = 1 } on success, or { .valid = 0, .error = "..." }
 * with an LLM-friendly error message on failure.
 */
sc_schema_result_t sc_schema_validate(const cJSON *schema, const cJSON *value);

#endif /* SC_SCHEMA_VALIDATE_H */
