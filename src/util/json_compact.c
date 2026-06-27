/*
 * smolclaw - JSON-aware tool result compaction (Phase 1.7)
 */
#include "util/json_compact.h"
#include "cJSON.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define SC_JSON_COMPACT_MAX_DEPTH 32

/* String fields worth truncating when oversized. */
static int is_long_text_key(const char *key)
{
    static const char *const keys[] = {
        "content", "output", "diff", "text", "stdout", "stderr",
        "body", "data", "result", "message", NULL
    };
    for (int i = 0; keys[i]; i++)
        if (strcmp(key, keys[i]) == 0) return 1;
    return 0;
}

/* Array fields worth capping when they have too many items. */
static int is_list_key(const char *key)
{
    static const char *const keys[] = {
        "matches", "entries", "results", "items", "files", "lines",
        "hits", "rows", NULL
    };
    for (int i = 0; keys[i]; i++)
        if (strcmp(key, keys[i]) == 0) return 1;
    return 0;
}

/* Mark an object as compacted (no-op for non-objects). */
static void mark_compacted(cJSON *obj)
{
    if (cJSON_IsObject(obj) && !cJSON_GetObjectItem(obj, "compacted"))
        cJSON_AddBoolToObject(obj, "compacted", 1);
}

/* Returns 1 if anything was changed in the subtree. */
static int compact_node(cJSON *node, int max_field_chars, int max_array_items,
                        int depth)
{
    if (!node || depth > SC_JSON_COMPACT_MAX_DEPTH) return 0;

    int changed = 0;

    if (cJSON_IsObject(node)) {
        for (cJSON *child = node->child; child; child = child->next) {
            const char *key = child->string ? child->string : "";

            if (cJSON_IsString(child) && is_long_text_key(key) &&
                child->valuestring &&
                (int)strlen(child->valuestring) > max_field_chars) {
                size_t full = strlen(child->valuestring);
                char *buf = malloc((size_t)max_field_chars + 64);
                if (buf) {
                    int n = snprintf(buf, (size_t)max_field_chars + 64,
                                     "%.*s...[truncated %zu chars]",
                                     max_field_chars, child->valuestring,
                                     full - (size_t)max_field_chars);
                    (void)n;
                    cJSON_SetValuestring(child, buf);
                    free(buf);
                    changed = 1;
                    mark_compacted(node);
                }
            } else if (cJSON_IsArray(child) && is_list_key(key) &&
                       cJSON_GetArraySize(child) > max_array_items) {
                int total = cJSON_GetArraySize(child);
                while (cJSON_GetArraySize(child) > max_array_items)
                    cJSON_DeleteItemFromArray(child, cJSON_GetArraySize(child) - 1);
                /* annotate count on the parent object */
                char note[64];
                snprintf(note, sizeof(note), "%s_total", key);
                if (!cJSON_GetObjectItem(node, note))
                    cJSON_AddNumberToObject(node, note, total);
                changed = 1;
                mark_compacted(node);
                /* recurse into the kept items */
                if (compact_node(child, max_field_chars, max_array_items, depth + 1))
                    changed = 1;
            } else if (cJSON_IsObject(child) || cJSON_IsArray(child)) {
                if (compact_node(child, max_field_chars, max_array_items, depth + 1))
                    changed = 1;
            }
        }
    } else if (cJSON_IsArray(node)) {
        for (cJSON *child = node->child; child; child = child->next) {
            if (cJSON_IsObject(child) || cJSON_IsArray(child)) {
                if (compact_node(child, max_field_chars, max_array_items, depth + 1))
                    changed = 1;
            }
        }
    }

    return changed;
}

char *sc_json_compact_for_llm(const char *content, int max_field_chars,
                              int max_array_items)
{
    if (!content || max_field_chars <= 0 || max_array_items <= 0)
        return NULL;

    cJSON *root = cJSON_Parse(content);
    if (!root)
        return NULL;  /* not JSON — leave it alone */

    int changed = compact_node(root, max_field_chars, max_array_items, 0);
    char *out = NULL;
    if (changed)
        out = cJSON_PrintUnformatted(root);

    cJSON_Delete(root);
    return out;  /* NULL when nothing changed */
}
