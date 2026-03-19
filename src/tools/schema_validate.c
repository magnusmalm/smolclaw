#include "schema_validate.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* ---------- Helpers ---------- */

static sc_schema_result_t ok(void)
{
    return (sc_schema_result_t){ .valid = 1, .error = "" };
}

static sc_schema_result_t fail(const char *path, const char *fmt, ...)
{
    sc_schema_result_t r = { .valid = 0 };
    int off = 0;

    if (path && path[0]) {
        off = snprintf(r.error, sizeof(r.error), "Validation error at '%s': ", path);
    } else {
        off = snprintf(r.error, sizeof(r.error), "Validation error: ");
    }

    if (off > 0 && (size_t)off < sizeof(r.error)) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(r.error + off, sizeof(r.error) - (size_t)off, fmt, ap);
        va_end(ap);
    }
    return r;
}

/* Build dotted path like "foo.bar" for nested error messages */
static void path_push(char *buf, size_t bufsz, const char *parent, const char *child)
{
    if (parent && parent[0])
        snprintf(buf, bufsz, "%s.%s", parent, child);
    else
        snprintf(buf, bufsz, "%s", child);
}

/* ---------- Type checking ---------- */

static const char *cjson_type_name(const cJSON *v)
{
    if (!v)                      return "null";
    if (cJSON_IsString(v))       return "string";
    if (cJSON_IsBool(v))         return "boolean";
    if (cJSON_IsNumber(v))       return "number";
    if (cJSON_IsObject(v))       return "object";
    if (cJSON_IsArray(v))        return "array";
    if (cJSON_IsNull(v))         return "null";
    return "unknown";
}

static int type_matches(const cJSON *value, const char *expected)
{
    if (!value || !expected) return 0;

    if (strcmp(expected, "string")  == 0) return cJSON_IsString(value);
    if (strcmp(expected, "boolean") == 0) return cJSON_IsBool(value);
    if (strcmp(expected, "object")  == 0) return cJSON_IsObject(value);
    if (strcmp(expected, "array")   == 0) return cJSON_IsArray(value);

    if (strcmp(expected, "number") == 0)
        return cJSON_IsNumber(value);

    /* "integer" accepts numbers that are whole */
    if (strcmp(expected, "integer") == 0) {
        if (!cJSON_IsNumber(value)) return 0;
        double d = value->valuedouble;
        return d == (double)(int)d;
    }

    return 0;
}

/* ---------- Core validation (recursive) ---------- */

static sc_schema_result_t validate_impl(const cJSON *schema, const cJSON *value,
                                         const char *path);

/* Check enum constraint */
static sc_schema_result_t check_enum(const cJSON *enum_arr, const cJSON *value,
                                      const char *path)
{
    const cJSON *item;
    cJSON_ArrayForEach(item, enum_arr) {
        if (cJSON_IsString(item) && cJSON_IsString(value)) {
            if (strcmp(item->valuestring, value->valuestring) == 0)
                return ok();
        }
        if (cJSON_IsNumber(item) && cJSON_IsNumber(value)) {
            if (item->valuedouble == value->valuedouble)
                return ok();
        }
    }

    /* Build allowed list for error message */
    char allowed[384] = "";
    int off = 0;
    cJSON_ArrayForEach(item, enum_arr) {
        if (off > 0 && (size_t)off < sizeof(allowed) - 2) {
            allowed[off++] = ',';
            allowed[off++] = ' ';
        }
        if (cJSON_IsString(item) && (size_t)off < sizeof(allowed) - 40) {
            off += snprintf(allowed + off, sizeof(allowed) - (size_t)off,
                            "\"%s\"", item->valuestring);
        } else if (cJSON_IsNumber(item) && (size_t)off < sizeof(allowed) - 20) {
            off += snprintf(allowed + off, sizeof(allowed) - (size_t)off,
                            "%g", item->valuedouble);
        }
    }

    if (cJSON_IsString(value))
        return fail(path, "value \"%s\" is not one of [%s]",
                    value->valuestring, allowed);
    return fail(path, "value is not one of [%s]", allowed);
}

/* Check numeric constraints */
static sc_schema_result_t check_numeric(const cJSON *schema, const cJSON *value,
                                          const char *path)
{
    const cJSON *min_node = cJSON_GetObjectItemCaseSensitive(schema, "minimum");
    if (min_node && cJSON_IsNumber(min_node)) {
        if (value->valuedouble < min_node->valuedouble)
            return fail(path, "value %g is less than minimum %g",
                        value->valuedouble, min_node->valuedouble);
    }

    const cJSON *max_node = cJSON_GetObjectItemCaseSensitive(schema, "maximum");
    if (max_node && cJSON_IsNumber(max_node)) {
        if (value->valuedouble > max_node->valuedouble)
            return fail(path, "value %g exceeds maximum %g",
                        value->valuedouble, max_node->valuedouble);
    }

    return ok();
}

static sc_schema_result_t validate_impl(const cJSON *schema, const cJSON *value,
                                         const char *path)
{
    if (!schema) return ok();

    /* Type check */
    const cJSON *type_node = cJSON_GetObjectItemCaseSensitive(schema, "type");
    if (type_node && cJSON_IsString(type_node)) {
        const char *expected = type_node->valuestring;

        /* NULL/missing value: only valid if no type constraint */
        if (!value || cJSON_IsNull(value))
            return fail(path, "expected %s, got null", expected);

        if (!type_matches(value, expected))
            return fail(path, "expected %s, got %s", expected,
                        cjson_type_name(value));

        /* Numeric range constraints */
        if (cJSON_IsNumber(value)) {
            sc_schema_result_t r = check_numeric(schema, value, path);
            if (!r.valid) return r;
        }
    }

    /* Enum check */
    const cJSON *enum_arr = cJSON_GetObjectItemCaseSensitive(schema, "enum");
    if (enum_arr && cJSON_IsArray(enum_arr) && value) {
        sc_schema_result_t r = check_enum(enum_arr, value, path);
        if (!r.valid) return r;
    }

    /* Object: required fields + property validation */
    if (value && cJSON_IsObject(value)) {
        /* Required fields */
        const cJSON *req = cJSON_GetObjectItemCaseSensitive(schema, "required");
        if (req && cJSON_IsArray(req)) {
            const cJSON *field;
            cJSON_ArrayForEach(field, req) {
                if (!cJSON_IsString(field)) continue;
                const cJSON *child = cJSON_GetObjectItemCaseSensitive(
                    value, field->valuestring);
                if (!child || cJSON_IsNull(child))
                    return fail(path, "missing required field '%s'",
                                field->valuestring);
            }
        }

        /* Property schemas */
        const cJSON *props = cJSON_GetObjectItemCaseSensitive(schema, "properties");
        if (props && cJSON_IsObject(props)) {
            const cJSON *prop_schema;
            cJSON_ArrayForEach(prop_schema, props) {
                const char *key = prop_schema->string;
                const cJSON *child = cJSON_GetObjectItemCaseSensitive(value, key);
                /* Only validate if the property is present */
                if (child && !cJSON_IsNull(child)) {
                    char child_path[256];
                    path_push(child_path, sizeof(child_path), path, key);
                    sc_schema_result_t r = validate_impl(prop_schema, child,
                                                          child_path);
                    if (!r.valid) return r;
                }
            }
        }
    }

    /* Array: item validation */
    if (value && cJSON_IsArray(value)) {
        const cJSON *items = cJSON_GetObjectItemCaseSensitive(schema, "items");
        if (items) {
            int idx = 0;
            const cJSON *elem;
            cJSON_ArrayForEach(elem, value) {
                char idx_path[256];
                char idx_str[16];
                snprintf(idx_str, sizeof(idx_str), "[%d]", idx);
                path_push(idx_path, sizeof(idx_path), path, idx_str);
                sc_schema_result_t r = validate_impl(items, elem, idx_path);
                if (!r.valid) return r;
                idx++;
            }
        }
    }

    return ok();
}

/* ---------- Public API ---------- */

sc_schema_result_t sc_schema_validate(const cJSON *schema, const cJSON *value)
{
    return validate_impl(schema, value, "");
}
