/*
 * smolclaw - JSON-aware result compaction tests (Phase 1.7)
 */
#include "test_main.h"
#include "util/json_compact.h"
#include "util/str.h"
#include "cJSON.h"

#include <string.h>

static void test_compact_non_json_unchanged(void)
{
    ASSERT_NULL(sc_json_compact_for_llm("not json at all", 4096, 50));
    ASSERT_NULL(sc_json_compact_for_llm("", 4096, 50));
    ASSERT_NULL(sc_json_compact_for_llm(NULL, 4096, 50));
}

static void test_compact_small_json_unchanged(void)
{
    /* Below thresholds → nothing to do → NULL (caller keeps original). */
    ASSERT_NULL(sc_json_compact_for_llm("{\"content\":\"short\"}", 4096, 50));
}

static void test_compact_long_field(void)
{
    sc_strbuf_t sb; sc_strbuf_init(&sb);
    sc_strbuf_append(&sb, "{\"content\":\"");
    for (int i = 0; i < 5000; i++) sc_strbuf_append_char(&sb, 'A');
    sc_strbuf_append(&sb, "\"}");
    char *json = sc_strbuf_finish(&sb);

    char *out = sc_json_compact_for_llm(json, 4096, 50);
    ASSERT_NOT_NULL(out);
    ASSERT(strstr(out, "truncated") != NULL, "has truncated marker");
    ASSERT(strstr(out, "compacted") != NULL, "marked compacted");
    ASSERT(strlen(out) < strlen(json), "compacted output is shorter");

    free(out);
    free(json);
}

static void test_compact_big_array(void)
{
    sc_strbuf_t sb; sc_strbuf_init(&sb);
    sc_strbuf_append(&sb, "{\"matches\":[");
    for (int i = 0; i < 60; i++) {
        if (i) sc_strbuf_append_char(&sb, ',');
        sc_strbuf_appendf(&sb, "%d", i);
    }
    sc_strbuf_append(&sb, "]}");
    char *json = sc_strbuf_finish(&sb);

    char *out = sc_json_compact_for_llm(json, 4096, 50);
    ASSERT_NOT_NULL(out);

    cJSON *r = cJSON_Parse(out);
    ASSERT_NOT_NULL(r);
    cJSON *m = cJSON_GetObjectItem(r, "matches");
    ASSERT_INT_EQ(cJSON_GetArraySize(m), 50);
    cJSON *t = cJSON_GetObjectItem(r, "matches_total");
    ASSERT(cJSON_IsNumber(t) && t->valueint == 60, "matches_total recorded");
    cJSON *c = cJSON_GetObjectItem(r, "compacted");
    ASSERT(cJSON_IsBool(c), "compacted marker present");

    cJSON_Delete(r);
    free(out);
    free(json);
}

int main(void)
{
    printf("test_json_compact\n");

    RUN_TEST(test_compact_non_json_unchanged);
    RUN_TEST(test_compact_small_json_unchanged);
    RUN_TEST(test_compact_long_field);
    RUN_TEST(test_compact_big_array);

    TEST_REPORT();
}
