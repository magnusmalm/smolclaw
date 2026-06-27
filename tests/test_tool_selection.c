/*
 * smolclaw - adaptive tool selection tests (Phase 1.5)
 */
#include "test_main.h"
#include "tools/tool_selection.h"
#include "providers/types.h"
#include "tools/registry.h"   /* sc_tool_definitions_free */
#include "cJSON.h"
#include "util/str.h"

#include <string.h>

static const char *const TOOLS[] = {
    "read_file", "list_dir", "write_file", "edit_file",
    "exec", "web_search", "memory_search", "mcp_custom"
};
#define NTOOLS 8

static sc_tool_definition_t *make_defs(void)
{
    sc_tool_definition_t *defs = calloc(NTOOLS, sizeof(*defs));
    for (int i = 0; i < NTOOLS; i++) {
        defs[i].name = sc_strdup(TOOLS[i]);
        defs[i].description = sc_strdup("desc");
        defs[i].parameters = cJSON_CreateObject();
    }
    return defs;
}

static int has_tool(sc_tool_definition_t *defs, int n, const char *name)
{
    for (int i = 0; i < n; i++)
        if (defs[i].name && strcmp(defs[i].name, name) == 0) return 1;
    return 0;
}

static void test_tool_selection_str_roundtrip(void)
{
    ASSERT_INT_EQ(sc_tool_selection_from_str("auto"), SC_TOOL_SELECTION_AUTO);
    ASSERT_INT_EQ(sc_tool_selection_from_str("fixed"), SC_TOOL_SELECTION_FIXED);
    ASSERT_INT_EQ(sc_tool_selection_from_str(NULL), SC_TOOL_SELECTION_FIXED);
    ASSERT_INT_EQ(sc_tool_selection_from_str("bogus"), SC_TOOL_SELECTION_FIXED);
    ASSERT_STR_EQ(sc_tool_selection_to_str(SC_TOOL_SELECTION_AUTO), "auto");
    ASSERT_STR_EQ(sc_tool_selection_to_str(SC_TOOL_SELECTION_FIXED), "fixed");
}

static void test_tool_selection_fixed_keeps_all(void)
{
    sc_tool_definition_t *defs = make_defs();
    int n = sc_tool_selection_apply(SC_TOOL_SELECTION_FIXED, "read the file", defs, NTOOLS);
    ASSERT_INT_EQ(n, NTOOLS);
    sc_tool_definitions_free(defs, n);
}

static void test_tool_selection_greeting_drops_task_tools(void)
{
    sc_tool_definition_t *defs = make_defs();
    int n = sc_tool_selection_apply(SC_TOOL_SELECTION_AUTO, "hello", defs, NTOOLS);
    /* greeting: only the unknown/custom tool survives */
    ASSERT_INT_EQ(n, 1);
    ASSERT(has_tool(defs, n, "mcp_custom"), "unknown tool kept on greeting");
    ASSERT_INT_EQ(has_tool(defs, n, "read_file"), 0);
    sc_tool_definitions_free(defs, n);
}

static void test_tool_selection_fileish(void)
{
    sc_tool_definition_t *defs = make_defs();
    int n = sc_tool_selection_apply(SC_TOOL_SELECTION_AUTO,
                                    "grep for config in src", defs, NTOOLS);
    ASSERT(has_tool(defs, n, "read_file"), "fileish keeps read_file");
    ASSERT(has_tool(defs, n, "list_dir"), "fileish keeps list_dir");
    ASSERT(has_tool(defs, n, "memory_search"), "fileish keeps memory_search");
    ASSERT(has_tool(defs, n, "mcp_custom"), "unknown always kept");
    ASSERT_INT_EQ(has_tool(defs, n, "write_file"), 0);
    ASSERT_INT_EQ(has_tool(defs, n, "exec"), 0);
    ASSERT_INT_EQ(has_tool(defs, n, "web_search"), 0);
    sc_tool_definitions_free(defs, n);
}

static void test_tool_selection_shellish(void)
{
    sc_tool_definition_t *defs = make_defs();
    int n = sc_tool_selection_apply(SC_TOOL_SELECTION_AUTO,
                                    "run the build and test it", defs, NTOOLS);
    ASSERT(has_tool(defs, n, "exec"), "shellish keeps exec");
    ASSERT(has_tool(defs, n, "read_file"), "shellish keeps read_file");
    ASSERT_INT_EQ(has_tool(defs, n, "write_file"), 0);
    sc_tool_definitions_free(defs, n);
}

static void test_tool_selection_editish(void)
{
    sc_tool_definition_t *defs = make_defs();
    int n = sc_tool_selection_apply(SC_TOOL_SELECTION_AUTO,
                                    "edit the file and replace the function", defs, NTOOLS);
    ASSERT(has_tool(defs, n, "edit_file"), "editish keeps edit_file");
    ASSERT(has_tool(defs, n, "write_file"), "editish keeps write_file");
    ASSERT(has_tool(defs, n, "read_file"), "editish keeps read_file");
    ASSERT_INT_EQ(has_tool(defs, n, "web_search"), 0);
    sc_tool_definitions_free(defs, n);
}

static void test_tool_selection_ambiguous_keeps_all(void)
{
    sc_tool_definition_t *defs = make_defs();
    /* No category keyword and not a greeting → keep everything. */
    int n = sc_tool_selection_apply(SC_TOOL_SELECTION_AUTO, "zxcv qwer asdf", defs, NTOOLS);
    ASSERT_INT_EQ(n, NTOOLS);
    sc_tool_definitions_free(defs, n);
}

int main(void)
{
    printf("test_tool_selection\n");

    RUN_TEST(test_tool_selection_str_roundtrip);
    RUN_TEST(test_tool_selection_fixed_keeps_all);
    RUN_TEST(test_tool_selection_greeting_drops_task_tools);
    RUN_TEST(test_tool_selection_fileish);
    RUN_TEST(test_tool_selection_shellish);
    RUN_TEST(test_tool_selection_editish);
    RUN_TEST(test_tool_selection_ambiguous_keeps_all);

    TEST_REPORT();
}
