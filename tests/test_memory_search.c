/*
 * smolclaw - memory search (FTS5) tests
 */

#include "test_main.h"
#include "memory_index.h"
#include "tools/types.h"
#include "tools/memory_search.h"
#include "memory.h"
#include "util/str.h"
#include "cJSON.h"

#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>

/* Helper: create temp workspace dir */
static char *make_tmpdir(void)
{
    static char tmpdir[64];
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/sc_test_msearch_XXXXXX");
    return mkdtemp(tmpdir);
}

/* Helper: cleanup temp dir */
static void cleanup_tmpdir(const char *dir)
{
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "rm -rf %s", dir);
    char *cmd = sc_strbuf_finish(&sb);
    system(cmd);
    free(cmd);
}

/* Helper: write a file */
static void write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(content, f);
        fclose(f);
    }
}

/* Helper: execute tool with JSON args */
static sc_tool_result_t *exec_tool(sc_tool_t *tool, const char *json_args)
{
    cJSON *args = json_args ? cJSON_Parse(json_args) : cJSON_CreateObject();
    sc_tool_result_t *r = tool->execute(tool, args, NULL);
    cJSON_Delete(args);
    return r;
}

/* Index callback wrapper for memory_set_index_cb */
static void index_cb_wrapper(const char *source, const char *content, void *ctx)
{
    sc_memory_index_put((sc_memory_index_t *)ctx, source, content);
}

/* ---- Tests ---- */

static void test_index_create_and_free(void)
{
    char *dir = make_tmpdir();
    ASSERT_NOT_NULL(dir);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/test.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    ASSERT_NOT_NULL(idx);
    sc_memory_index_free(idx);

    free(db_path);
    cleanup_tmpdir(dir);
}

static void test_index_put_and_search(void)
{
    char *dir = make_tmpdir();
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/test.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    ASSERT_NOT_NULL(idx);

    sc_memory_index_put(idx, "long_term",
        "The user prefers vim keybindings and dark themes.");
    sc_memory_index_put(idx, "20260301",
        "Discussed IRC channel setup and webhook integration.");

    int count = 0;
    sc_memory_search_result_t *results = sc_memory_index_search(
        idx, "vim keybindings", 10, &count);

    ASSERT(count > 0, "should find vim keybindings");
    ASSERT_NOT_NULL(results);
    ASSERT_STR_EQ(results[0].source, "long_term");
    ASSERT(strstr(results[0].snippet, "vim") != NULL,
           "snippet should contain 'vim'");

    sc_memory_search_results_free(results, count);
    sc_memory_index_free(idx);
    free(db_path);
    cleanup_tmpdir(dir);
}

static void test_index_search_no_results(void)
{
    char *dir = make_tmpdir();
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/test.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    ASSERT_NOT_NULL(idx);

    sc_memory_index_put(idx, "long_term", "Only cats and dogs here.");

    int count = 0;
    sc_memory_search_result_t *results = sc_memory_index_search(
        idx, "quantum physics", 10, &count);

    ASSERT_INT_EQ(count, 0);
    ASSERT(results == NULL, "should return NULL for no results");

    sc_memory_index_free(idx);
    free(db_path);
    cleanup_tmpdir(dir);
}

static void test_index_put_replaces(void)
{
    char *dir = make_tmpdir();
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/test.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    ASSERT_NOT_NULL(idx);

    sc_memory_index_put(idx, "long_term", "Old content about elephants.");
    sc_memory_index_put(idx, "long_term", "New content about giraffes.");

    int count = 0;
    sc_memory_search_result_t *results;

    /* Old content should not be found */
    results = sc_memory_index_search(idx, "elephants", 10, &count);
    ASSERT_INT_EQ(count, 0);
    sc_memory_search_results_free(results, count);

    /* New content should be found */
    results = sc_memory_index_search(idx, "giraffes", 10, &count);
    ASSERT(count > 0, "should find new content");
    sc_memory_search_results_free(results, count);

    sc_memory_index_free(idx);
    free(db_path);
    cleanup_tmpdir(dir);
}

static void test_index_remove(void)
{
    char *dir = make_tmpdir();
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/test.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    ASSERT_NOT_NULL(idx);

    sc_memory_index_put(idx, "20260301", "Meeting notes about deployment.");
    sc_memory_index_remove(idx, "20260301");

    int count = 0;
    sc_memory_search_result_t *results = sc_memory_index_search(
        idx, "deployment", 10, &count);
    ASSERT_INT_EQ(count, 0);
    sc_memory_search_results_free(results, count);

    sc_memory_index_free(idx);
    free(db_path);
    cleanup_tmpdir(dir);
}

static void test_index_rebuild(void)
{
    char *dir = make_tmpdir();
    ASSERT_NOT_NULL(dir);

    /* Create memory dir structure */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory", dir);
    char *mem_dir = sc_strbuf_finish(&sb);
    mkdir(mem_dir, 0755);

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/202603", dir);
    char *month_dir = sc_strbuf_finish(&sb);
    mkdir(month_dir, 0755);

    /* Write test files */
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/MEMORY.md", dir);
    char *lt_path = sc_strbuf_finish(&sb);
    write_file(lt_path, "# Long-term\nUser likes Python and Rust.");

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/202603/20260301.md", dir);
    char *daily_path = sc_strbuf_finish(&sb);
    write_file(daily_path, "# 2026-03-01\n- Set up CI pipeline");

    /* Create index and rebuild */
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/memory/search.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    ASSERT_NOT_NULL(idx);

    int count = sc_memory_index_rebuild(idx, mem_dir);
    ASSERT(count >= 2, "should index at least 2 files");

    /* Search for content from each file */
    int rc;
    sc_memory_search_result_t *results;

    results = sc_memory_index_search(idx, "Python", 10, &rc);
    ASSERT(rc > 0, "should find Python in long-term memory");
    ASSERT_STR_EQ(results[0].source, "long_term");
    sc_memory_search_results_free(results, rc);

    results = sc_memory_index_search(idx, "CI pipeline", 10, &rc);
    ASSERT(rc > 0, "should find CI pipeline in daily notes");
    ASSERT_STR_EQ(results[0].source, "20260301");
    sc_memory_search_results_free(results, rc);

    sc_memory_index_free(idx);
    free(db_path);
    free(lt_path);
    free(daily_path);
    free(month_dir);
    free(mem_dir);
    cleanup_tmpdir(dir);
}

static void test_index_max_results(void)
{
    char *dir = make_tmpdir();
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/test.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    ASSERT_NOT_NULL(idx);

    /* Index multiple documents containing same term */
    for (int i = 0; i < 10; i++) {
        char source[16], content[64];
        snprintf(source, sizeof(source), "doc%d", i);
        snprintf(content, sizeof(content), "Document %d about testing methodology.", i);
        sc_memory_index_put(idx, source, content);
    }

    /* Limit to 3 results */
    int count = 0;
    sc_memory_search_result_t *results = sc_memory_index_search(
        idx, "testing", 3, &count);
    ASSERT(count <= 3, "should respect max_results limit");
    ASSERT(count > 0, "should find at least one result");
    sc_memory_search_results_free(results, count);

    sc_memory_index_free(idx);
    free(db_path);
    cleanup_tmpdir(dir);
}

static void test_index_phrase_search(void)
{
    char *dir = make_tmpdir();
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/test.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    ASSERT_NOT_NULL(idx);

    sc_memory_index_put(idx, "doc1", "The red fox jumps over the lazy dog.");
    sc_memory_index_put(idx, "doc2", "Red paint on the fox fence.");

    int count = 0;
    sc_memory_search_result_t *results = sc_memory_index_search(
        idx, "\"red fox\"", 10, &count);
    ASSERT(count > 0, "should find exact phrase");
    ASSERT_STR_EQ(results[0].source, "doc1");
    sc_memory_search_results_free(results, count);

    sc_memory_index_free(idx);
    free(db_path);
    cleanup_tmpdir(dir);
}

static void test_index_prefix_search(void)
{
    char *dir = make_tmpdir();
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/test.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    ASSERT_NOT_NULL(idx);

    sc_memory_index_put(idx, "doc1", "Configuration management system.");

    int count = 0;
    sc_memory_search_result_t *results = sc_memory_index_search(
        idx, "config*", 10, &count);
    ASSERT(count > 0, "prefix search should match");
    sc_memory_search_results_free(results, count);

    sc_memory_index_free(idx);
    free(db_path);
    cleanup_tmpdir(dir);
}

static void test_index_null_safety(void)
{
    ASSERT(sc_memory_index_new(NULL) == NULL, "NULL path should return NULL");

    int count = 0;
    ASSERT(sc_memory_index_search(NULL, "test", 10, &count) == NULL,
           "NULL index search should return NULL");
    ASSERT_INT_EQ(sc_memory_index_put(NULL, "src", "content"), -1);
    ASSERT_INT_EQ(sc_memory_index_remove(NULL, "src"), -1);
    ASSERT_INT_EQ(sc_memory_index_rebuild(NULL, "/tmp"), -1);

    /* Free NULL should be safe */
    sc_memory_index_free(NULL);
    sc_memory_search_results_free(NULL, 0);
}

static void test_search_tool_basic(void)
{
    char *dir = make_tmpdir();
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/test.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    ASSERT_NOT_NULL(idx);

    sc_memory_index_put(idx, "long_term",
        "The project uses CMake for building.");

    sc_tool_t *tool = sc_tool_memory_search_new(idx);
    ASSERT_NOT_NULL(tool);
    ASSERT_STR_EQ(tool->name, "memory_search");
    ASSERT_INT_EQ(tool->needs_confirm, 0);

    sc_tool_result_t *r = exec_tool(tool,
        "{\"query\": \"CMake building\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_NOT_NULL(r->for_llm);
    ASSERT(strstr(r->for_llm, "Found") != NULL, "should have results header");
    ASSERT(strstr(r->for_llm, "CMake") != NULL, "should mention CMake");

    sc_tool_result_free(r);
    tool->destroy(tool);
    sc_memory_index_free(idx);
    free(db_path);
    cleanup_tmpdir(dir);
}

static void test_search_tool_no_results(void)
{
    char *dir = make_tmpdir();
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/test.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    ASSERT_NOT_NULL(idx);

    sc_tool_t *tool = sc_tool_memory_search_new(idx);
    ASSERT_NOT_NULL(tool);

    sc_tool_result_t *r = exec_tool(tool,
        "{\"query\": \"nonexistent\"}");
    ASSERT_NOT_NULL(r);
    ASSERT(strstr(r->for_llm, "No results") != NULL,
           "should say no results");

    sc_tool_result_free(r);
    tool->destroy(tool);
    sc_memory_index_free(idx);
    free(db_path);
    cleanup_tmpdir(dir);
}

static void test_search_tool_missing_query(void)
{
    char *dir = make_tmpdir();
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/test.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    sc_tool_t *tool = sc_tool_memory_search_new(idx);

    sc_tool_result_t *r = exec_tool(tool, "{}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);

    sc_tool_result_free(r);
    tool->destroy(tool);
    sc_memory_index_free(idx);
    free(db_path);
    cleanup_tmpdir(dir);
}

static void test_search_tool_parameters(void)
{
    char *dir = make_tmpdir();
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/test.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    sc_tool_t *tool = sc_tool_memory_search_new(idx);

    cJSON *params = tool->parameters(tool);
    ASSERT_NOT_NULL(params);

    /* Should have query and max_results properties */
    cJSON *props = cJSON_GetObjectItem(params, "properties");
    ASSERT_NOT_NULL(props);
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "query"));
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "max_results"));

    /* query should be required */
    cJSON *req = cJSON_GetObjectItem(params, "required");
    ASSERT_NOT_NULL(req);
    ASSERT(cJSON_GetArraySize(req) == 1, "should have 1 required param");

    cJSON_Delete(params);
    tool->destroy(tool);
    sc_memory_index_free(idx);
    free(db_path);
    cleanup_tmpdir(dir);
}

static void test_memory_write_triggers_callback(void)
{
    char *dir = make_tmpdir();
    ASSERT_NOT_NULL(dir);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/test.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    ASSERT_NOT_NULL(idx);

    /* Create memory store and set callback */
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/workspace", dir);
    char *ws = sc_strbuf_finish(&sb);
    mkdir(ws, 0755);

    sc_memory_t *mem = sc_memory_new(ws);
    ASSERT_NOT_NULL(mem);

    /* Use callback wrapper */
    sc_memory_set_index_cb(mem, index_cb_wrapper, idx);

    /* Write long-term memory */
    sc_memory_write_long_term(mem, "Callback test: favorite language is C.");

    /* Search should find it */
    int count = 0;
    sc_memory_search_result_t *results = sc_memory_index_search(
        idx, "favorite language", 10, &count);
    ASSERT(count > 0, "callback should have indexed the write");
    sc_memory_search_results_free(results, count);

    sc_memory_free(mem);
    sc_memory_index_free(idx);
    free(db_path);
    free(ws);
    cleanup_tmpdir(dir);
}

static void test_index_empty_content(void)
{
    char *dir = make_tmpdir();
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/test.db", dir);
    char *db_path = sc_strbuf_finish(&sb);

    sc_memory_index_t *idx = sc_memory_index_new(db_path);
    ASSERT_NOT_NULL(idx);

    /* Indexing empty content should work */
    int rc = sc_memory_index_put(idx, "empty", "");
    ASSERT_INT_EQ(rc, 0);

    sc_memory_index_free(idx);
    free(db_path);
    cleanup_tmpdir(dir);
}

int main(void)
{
    RUN_TEST(test_index_create_and_free);
    RUN_TEST(test_index_put_and_search);
    RUN_TEST(test_index_search_no_results);
    RUN_TEST(test_index_put_replaces);
    RUN_TEST(test_index_remove);
    RUN_TEST(test_index_rebuild);
    RUN_TEST(test_index_max_results);
    RUN_TEST(test_index_phrase_search);
    RUN_TEST(test_index_prefix_search);
    RUN_TEST(test_index_null_safety);
    RUN_TEST(test_search_tool_basic);
    RUN_TEST(test_search_tool_no_results);
    RUN_TEST(test_search_tool_missing_query);
    RUN_TEST(test_search_tool_parameters);
    RUN_TEST(test_memory_write_triggers_callback);
    RUN_TEST(test_index_empty_content);
    TEST_REPORT();
}
