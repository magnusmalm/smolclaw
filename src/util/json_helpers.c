#include "json_helpers.h"
#include "str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

const char *sc_json_get_string(const cJSON *obj, const char *key, const char *def)
{
    if (!obj || !key)
        return def;
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsString(item) || !item->valuestring)
        return def;
    return item->valuestring;
}

int sc_json_get_int(const cJSON *obj, const char *key, int def)
{
    if (!obj || !key)
        return def;
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsNumber(item))
        return def;
    return item->valueint;
}

double sc_json_get_double(const cJSON *obj, const char *key, double def)
{
    if (!obj || !key)
        return def;
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsNumber(item))
        return def;
    return item->valuedouble;
}

int sc_json_get_bool(const cJSON *obj, const char *key, int def)
{
    if (!obj || !key)
        return def;
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item)
        return def;
    if (cJSON_IsTrue(item))
        return 1;
    if (cJSON_IsFalse(item))
        return 0;
    return def;
}

cJSON *sc_json_get_array(const cJSON *obj, const char *key)
{
    if (!obj || !key)
        return NULL;
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsArray(item))
        return NULL;
    return item;
}

cJSON *sc_json_get_object(const cJSON *obj, const char *key)
{
    if (!obj || !key)
        return NULL;
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsObject(item))
        return NULL;
    return item;
}

cJSON *sc_json_load_file(const char *path)
{
    if (!path)
        return NULL;

    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    if (size < 0) {
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);

    char *buf = malloc((size_t)size + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t nread = fread(buf, 1, (size_t)size, f);
    fclose(f);
    buf[nread] = '\0';

    cJSON *json = cJSON_Parse(buf);
    free(buf);
    return json;
}

int sc_json_save_file(const char *path, const cJSON *json)
{
    if (!path || !json)
        return -1;

    char *str = cJSON_Print(json);
    if (!str)
        return -1;

    /* Write to temporary file, then rename for atomicity */
    size_t path_len = strlen(path);
    char *tmp_path = malloc(path_len + 5); /* ".tmp\0" */
    if (!tmp_path) {
        cJSON_free(str);
        return -1;
    }
    memcpy(tmp_path, path, path_len);
    memcpy(tmp_path + path_len, ".tmp", 5);

    FILE *f = fopen(tmp_path, "wb");
    if (!f) {
        free(tmp_path);
        cJSON_free(str);
        return -1;
    }

    size_t str_len = strlen(str);
    size_t written = fwrite(str, 1, str_len, f);
    /* Write trailing newline */
    if (written == str_len)
        fputc('\n', f);
    /* Flush to kernel and fsync to disk before rename for crash safety */
    fflush(f);
    fsync(fileno(f));
    fclose(f);
    cJSON_free(str);

    /* Set restrictive permissions (0600) before rename */
    chmod(tmp_path, 0600);

    if (written != str_len) {
        remove(tmp_path);
        free(tmp_path);
        return -1;
    }

    if (rename(tmp_path, path) != 0) {
        remove(tmp_path);
        free(tmp_path);
        return -1;
    }

    free(tmp_path);
    return 0;
}

int sc_json_get_string_array(const cJSON *arr, const char **out, int max)
{
    if (!arr || !cJSON_IsArray(arr) || !out || max <= 0)
        return 0;

    int count = 0;
    const cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        if (count >= max)
            break;
        if (cJSON_IsString(item) && item->valuestring)
            out[count++] = item->valuestring;
    }
    return count;
}

char **sc_json_parse_string_list(const cJSON *arr, int *out_count)
{
    *out_count = 0;
    if (!arr || !cJSON_IsArray(arr)) return NULL;
    int n = cJSON_GetArraySize(arr);
    if (n <= 0) return NULL;

    char **list = calloc((size_t)n, sizeof(char *));
    if (!list) return NULL;

    const cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        if (cJSON_IsString(item) && item->valuestring)
            list[(*out_count)++] = sc_strdup(item->valuestring);
    }
    return list;
}

/* ---------- JSON Schema helpers ---------- */

cJSON *sc_schema_new(void)
{
    cJSON *s = cJSON_CreateObject();
    cJSON_AddStringToObject(s, "type", "object");
    cJSON_AddObjectToObject(s, "properties");
    return s;
}

static void schema_add_prop(cJSON *schema, const char *name,
                            const char *type, const char *desc, int required)
{
    cJSON *props = cJSON_GetObjectItem(schema, "properties");
    cJSON *prop = cJSON_AddObjectToObject(props, name);
    cJSON_AddStringToObject(prop, "type", type);
    cJSON_AddStringToObject(prop, "description", desc);

    if (required) {
        cJSON *req = cJSON_GetObjectItem(schema, "required");
        if (!req)
            req = cJSON_AddArrayToObject(schema, "required");
        cJSON_AddItemToArray(req, cJSON_CreateString(name));
    }
}

void sc_schema_add_string(cJSON *schema, const char *name,
                          const char *desc, int required)
{
    schema_add_prop(schema, name, "string", desc, required);
}

void sc_schema_add_integer(cJSON *schema, const char *name,
                           const char *desc, int required)
{
    schema_add_prop(schema, name, "integer", desc, required);
}
