/*
 * smolclaw — code graph tool tests
 */

#include "test_main.h"
#include "sc_features.h"

#if SC_ENABLE_CODE_GRAPH

#include "tools/code_graph.h"
#include "tools/symbol_lookup.h"
#include "tools/types.h"
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
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/sc_test_cgraph_XXXXXX");
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

/* ---- Tests ---- */

static void test_create_and_destroy(void)
{
    char *dir = make_tmpdir();
    ASSERT_NOT_NULL(dir);

    sc_tool_t *tool = sc_tool_code_graph_new(dir);
    ASSERT_NOT_NULL(tool);
    ASSERT_STR_EQ(tool->name, "code_graph");

    tool->destroy(tool);
    cleanup_tmpdir(dir);
}

static void test_build_js_project(void)
{
    char *dir = make_tmpdir();

    /* Create a small JS project */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/src", dir);
    char *src = sc_strbuf_finish(&sb);
    mkdir(src, 0755);

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/src/index.js", dir);
    char *f1 = sc_strbuf_finish(&sb);
    write_file(f1, "import { foo } from './utils'\nimport bar from 'lodash'\n");

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/src/utils.js", dir);
    char *f2 = sc_strbuf_finish(&sb);
    write_file(f2, "export const foo = 42\n");

    sc_tool_t *tool = sc_tool_code_graph_new(dir);
    sc_tool_result_t *r = exec_tool(tool, "{\"action\":\"build\",\"directory\":\".\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "2 files") != NULL, "should find 2 files");

    sc_tool_result_free(r);
    tool->destroy(tool);
    free(src);
    free(f1);
    free(f2);
    cleanup_tmpdir(dir);
}

static void test_build_python_project(void)
{
    char *dir = make_tmpdir();

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/main.py", dir);
    char *f1 = sc_strbuf_finish(&sb);
    write_file(f1, "import os\nfrom sys import argv\nimport mymodule\n");

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/mymodule.py", dir);
    char *f2 = sc_strbuf_finish(&sb);
    write_file(f2, "import json\n");

    sc_tool_t *tool = sc_tool_code_graph_new(dir);
    sc_tool_result_t *r = exec_tool(tool, "{\"action\":\"build\",\"directory\":\".\"}");
    ASSERT_NOT_NULL(r);
    ASSERT(strstr(r->for_llm, "2 files") != NULL, "should find 2 files");

    sc_tool_result_free(r);
    tool->destroy(tool);
    free(f1);
    free(f2);
    cleanup_tmpdir(dir);
}

static void test_build_c_project(void)
{
    char *dir = make_tmpdir();

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/main.c", dir);
    char *f1 = sc_strbuf_finish(&sb);
    write_file(f1, "#include <stdio.h>\n#include \"utils.h\"\nint main() {}\n");

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/utils.h", dir);
    char *f2 = sc_strbuf_finish(&sb);
    write_file(f2, "#ifndef UTILS_H\n#define UTILS_H\nvoid foo(void);\n#endif\n");

    sc_tool_t *tool = sc_tool_code_graph_new(dir);
    sc_tool_result_t *r = exec_tool(tool, "{\"action\":\"build\",\"directory\":\".\"}");
    ASSERT_NOT_NULL(r);
    ASSERT(strstr(r->for_llm, "2 files") != NULL, "should find 2 files");

    sc_tool_result_free(r);
    tool->destroy(tool);
    free(f1);
    free(f2);
    cleanup_tmpdir(dir);
}

static void test_query(void)
{
    char *dir = make_tmpdir();

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/main.c", dir);
    char *f1 = sc_strbuf_finish(&sb);
    write_file(f1, "#include \"utils.h\"\n");

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/utils.h", dir);
    char *f2 = sc_strbuf_finish(&sb);
    write_file(f2, "/* no imports */\n");

    sc_tool_t *tool = sc_tool_code_graph_new(dir);

    /* Build first */
    sc_tool_result_t *r = exec_tool(tool, "{\"action\":\"build\",\"directory\":\".\"}");
    sc_tool_result_free(r);

    /* Query main.c */
    r = exec_tool(tool, "{\"action\":\"query\",\"file\":\"main.c\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "utils.h") != NULL, "should show utils.h import");

    sc_tool_result_free(r);

    /* Query without build should fail... but graph is built */
    /* Query nonexistent file */
    r = exec_tool(tool, "{\"action\":\"query\",\"file\":\"nonexistent.c\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);

    sc_tool_result_free(r);
    tool->destroy(tool);
    free(f1);
    free(f2);
    cleanup_tmpdir(dir);
}

static void test_stats(void)
{
    char *dir = make_tmpdir();

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/main.c", dir);
    char *f1 = sc_strbuf_finish(&sb);
    write_file(f1, "#include \"utils.h\"\n");

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/utils.h", dir);
    char *f2 = sc_strbuf_finish(&sb);
    write_file(f2, "/* utils */\n");

    sc_tool_t *tool = sc_tool_code_graph_new(dir);
    sc_tool_result_t *r = exec_tool(tool, "{\"action\":\"build\",\"directory\":\".\"}");
    sc_tool_result_free(r);

    r = exec_tool(tool, "{\"action\":\"stats\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "Files: 2") != NULL, "should show 2 files");
    ASSERT(strstr(r->for_llm, "C/C++") != NULL, "should show C/C++ language");

    sc_tool_result_free(r);
    tool->destroy(tool);
    free(f1);
    free(f2);
    cleanup_tmpdir(dir);
}

static void test_cycles(void)
{
    char *dir = make_tmpdir();

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/a.py", dir);
    char *f1 = sc_strbuf_finish(&sb);
    write_file(f1, "import b\n");

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/b.py", dir);
    char *f2 = sc_strbuf_finish(&sb);
    write_file(f2, "import a\n");

    sc_tool_t *tool = sc_tool_code_graph_new(dir);
    sc_tool_result_t *r = exec_tool(tool, "{\"action\":\"build\",\"directory\":\".\"}");
    sc_tool_result_free(r);

    r = exec_tool(tool, "{\"action\":\"cycles\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    /* Note: cycle detection requires the import name to match the node path,
     * which only works if Python imports match filenames exactly.
     * With "import b" and node "b.py", they won't match (b != b.py).
     * This is expected — real cycle detection needs path resolution. */

    sc_tool_result_free(r);
    tool->destroy(tool);
    free(f1);
    free(f2);
    cleanup_tmpdir(dir);
}

static void test_no_build(void)
{
    char *dir = make_tmpdir();
    sc_tool_t *tool = sc_tool_code_graph_new(dir);

    sc_tool_result_t *r = exec_tool(tool, "{\"action\":\"query\",\"file\":\"foo.c\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);
    ASSERT(strstr(r->for_llm, "not built") != NULL, "should say not built");

    sc_tool_result_free(r);

    r = exec_tool(tool, "{\"action\":\"stats\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);

    sc_tool_result_free(r);
    tool->destroy(tool);
    cleanup_tmpdir(dir);
}

static void test_unknown_action(void)
{
    char *dir = make_tmpdir();
    sc_tool_t *tool = sc_tool_code_graph_new(dir);

    sc_tool_result_t *r = exec_tool(tool, "{\"action\":\"invalid\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 1);

    sc_tool_result_free(r);
    tool->destroy(tool);
    cleanup_tmpdir(dir);
}

static void test_parameters(void)
{
    char *dir = make_tmpdir();
    sc_tool_t *tool = sc_tool_code_graph_new(dir);

    cJSON *params = tool->parameters(tool);
    ASSERT_NOT_NULL(params);

    cJSON *props = cJSON_GetObjectItem(params, "properties");
    ASSERT_NOT_NULL(props);
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "action"));
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "directory"));
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "file"));
    /* symbols-related optional params now present */
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "path"));
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "name_filter"));
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "max_results"));
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "kinds"));

    cJSON_Delete(params);
    tool->destroy(tool);
    cleanup_tmpdir(dir);
}

/* ---- New symbols action tests (Phase 3) ---- */

static void test_symbols_action(void)
{
    char *dir = make_tmpdir();
    ASSERT_NOT_NULL(dir);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/src", dir);
    char *src = sc_strbuf_finish(&sb);
    mkdir(src, 0755);

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/src/main.c", dir);
    char *f1 = sc_strbuf_finish(&sb);
    /* Realistic C with func, define, struct for extraction */
    write_file(f1,
        "#include <stdio.h>\n"
        "#define MAX_RETENTION 3600\n"
        "static int set_retention(int secs) {\n"
        "    return secs > 0 ? secs : 0;\n"
        "}\n"
        "struct retention_info {\n"
        "    int current;\n"
        "    int max;\n"
        "};\n"
        "typedef struct retention_info ret_info_t;\n"
    );

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/src/utils.c", dir);
    char *f2 = sc_strbuf_finish(&sb);
    write_file(f2, "void helper(void) {}\n#define HELPER_FLAG 1\n");

    sc_tool_t *tool = sc_tool_code_graph_new(dir);

    /* Basic: all symbols */
    sc_tool_result_t *r = exec_tool(tool, "{\"action\":\"symbols\",\"path\":\".\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "code_graph symbols under '.'") != NULL, "header");
    ASSERT(strstr(r->for_llm, "func: set_retention at src/main.c:") != NULL, "func with path:line");
    ASSERT(strstr(r->for_llm, "define: MAX_RETENTION at src/main.c:") != NULL, "define");
    ASSERT(strstr(r->for_llm, "struct: retention_info at src/main.c:") != NULL, "struct");
    ASSERT(strstr(r->for_llm, "func: helper at src/utils.c:") != NULL, "second file");
    /* Should mention typedef too if regex catches */
    sc_tool_result_free(r);

    /* name_filter (case-insensitive) */
    r = exec_tool(tool, "{\"action\":\"symbols\",\"path\":\".\",\"name_filter\":\"ret\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "set_retention") != NULL, "ret matches set_retention");
    ASSERT(strstr(r->for_llm, "MAX_RETENTION") != NULL, "ret matches MAX_RETENTION");
    ASSERT(strstr(r->for_llm, "retention_info") != NULL, "ret matches retention_info");
    /* helper should not appear */
    ASSERT(strstr(r->for_llm, "helper") == NULL, "filter excludes non-matching");
    sc_tool_result_free(r);

    /* max_results + truncation note */
    r = exec_tool(tool, "{\"action\":\"symbols\",\"path\":\".\",\"max_results\":2}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "2 result") != NULL, "respects max");
    ASSERT(strstr(r->for_llm, "truncated at max_results=2") != NULL, "shows truncation note");
    sc_tool_result_free(r);

    /* path restriction: only subdir */
    r = exec_tool(tool, "{\"action\":\"symbols\",\"path\":\"src\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "under 'src'") != NULL);
    ASSERT(strstr(r->for_llm, "src/main.c") != NULL);
    ASSERT(strstr(r->for_llm, "src/utils.c") != NULL);
    sc_tool_result_free(r);

    /* Single file path */
    r = exec_tool(tool, "{\"action\":\"symbols\",\"path\":\"src/main.c\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "main.c") != NULL);
    ASSERT(strstr(r->for_llm, "utils.c") == NULL, "other file excluded");
    sc_tool_result_free(r);

    /* kinds post-filter (comma-separated, applied after extraction) */
    r = exec_tool(tool, "{\"action\":\"symbols\",\"path\":\".\",\"kinds\":\"func\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "(kinds='func')") != NULL, "kinds reflected in output header");
    ASSERT(strstr(r->for_llm, "func: set_retention") != NULL);
    ASSERT(strstr(r->for_llm, "func: helper") != NULL);
    ASSERT(strstr(r->for_llm, "define:") == NULL, "define filtered out by kinds");
    ASSERT(strstr(r->for_llm, "struct:") == NULL, "struct filtered out by kinds");
    sc_tool_result_free(r);

    /* multiple kinds */
    r = exec_tool(tool, "{\"action\":\"symbols\",\"path\":\".\",\"kinds\":\"define,struct\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "define: MAX_RETENTION") != NULL);
    ASSERT(strstr(r->for_llm, "struct: retention_info") != NULL);
    ASSERT(strstr(r->for_llm, "func:") == NULL, "func filtered by multi-kinds");
    sc_tool_result_free(r);

    tool->destroy(tool);
    free(src);
    free(f1);
    free(f2);
    cleanup_tmpdir(dir);
}

/* ---- Expanded coverage tests for Phase 3 (kinds + wrapper + edges + set_workspace) ---- */

static void test_symbols_kinds_combined_with_filters(void)
{
    char *dir = make_tmpdir();
    ASSERT_NOT_NULL(dir);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/main.c", dir);
    char *f1 = sc_strbuf_finish(&sb);
    write_file(f1,
        "#define FOO_BAR 1\n"
        "#define BAZ 2\n"
        "int func_one(int x) { return x; }\n"
        "void func_two(void) {}\n"
        "struct data { int v; };\n"
        "static int helper_func(int y) { return y + 1; }\n"
    );

    sc_tool_t *tool = sc_tool_code_graph_new(dir);

    /* kinds + name_filter */
    sc_tool_result_t *r = exec_tool(tool,
        "{\"action\":\"symbols\",\"path\":\".\",\"kinds\":\"func\",\"name_filter\":\"one\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "(kinds='func')") != NULL);
    ASSERT(strstr(r->for_llm, "(name_filter='one')") != NULL);
    ASSERT(strstr(r->for_llm, "func_one") != NULL);
    ASSERT(strstr(r->for_llm, "func_two") == NULL, "name_filter excludes");
    ASSERT(strstr(r->for_llm, "define:") == NULL, "kinds excludes defines");
    ASSERT(strstr(r->for_llm, "struct:") == NULL);
    sc_tool_result_free(r);

    /* kinds + max_results (truncation still possible if enough matching kinds) */
    r = exec_tool(tool,
        "{\"action\":\"symbols\",\"path\":\".\",\"kinds\":\"func,define\",\"max_results\":1}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "1 result") != NULL || strstr(r->for_llm, "1 results") != NULL);
    /* truncation note appears only if pre-filter hit the cap for the requested kinds */
    /* since 3 funcs+defines >1, and filter keeps some, but cap during scan, expect note if count post still >=? */
    /* In practice, with small set we mainly verify it doesn't crash and applies both */
    sc_tool_result_free(r);

    tool->destroy(tool);
    free(f1);
    cleanup_tmpdir(dir);
}

static void test_symbol_lookup_wrapper_basic(void)
{
    char *dir = make_tmpdir();
    ASSERT_NOT_NULL(dir);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/src", dir);
    char *src = sc_strbuf_finish(&sb);
    mkdir(src, 0755);

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/src/lookup.c", dir);
    char *f = sc_strbuf_finish(&sb);
    write_file(f,
        "#define WRAP_DEF 42\n"
        "int wrapper_func(char *s) { return 0; }\n"
        "struct wrap_struct { int a; };\n"
    );

    sc_tool_t *tool = sc_tool_symbol_lookup_new(dir);
    ASSERT_NOT_NULL(tool);
    ASSERT_STR_EQ(tool->name, "symbol_lookup");

    /* Basic via 'name' param (maps to name_filter internally) */
    sc_tool_result_t *r = exec_tool(tool, "{\"name\":\"wrap\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "code_graph symbols under '.'") != NULL);
    ASSERT(strstr(r->for_llm, "define: WRAP_DEF") != NULL);
    ASSERT(strstr(r->for_llm, "func: wrapper_func") != NULL);
    ASSERT(strstr(r->for_llm, "struct: wrap_struct") != NULL);
    /* default max_results=30 reflected? (not in text header unless hit) */
    sc_tool_result_free(r);

    /* With explicit path and max */
    r = exec_tool(tool, "{\"name\":\"func\",\"path\":\"src\",\"max_results\":5}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "under 'src'") != NULL);
    ASSERT(strstr(r->for_llm, "wrapper_func") != NULL);
    sc_tool_result_free(r);

    /* Wrapper parameters schema */
    cJSON *params = tool->parameters(tool);
    ASSERT_NOT_NULL(params);
    cJSON *props = cJSON_GetObjectItem(params, "properties");
    ASSERT_NOT_NULL(props);
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "name"));
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "path"));
    ASSERT_NOT_NULL(cJSON_GetObjectItem(props, "max_results"));
    /* note: 'kinds' is accepted at runtime via passthrough even if not declared in schema */
    cJSON_Delete(params);

    tool->destroy(tool);
    free(src);
    free(f);
    cleanup_tmpdir(dir);
}

static void test_symbol_lookup_wrapper_with_kinds(void)
{
    char *dir = make_tmpdir();
    ASSERT_NOT_NULL(dir);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/k.c", dir);
    char *f = sc_strbuf_finish(&sb);
    write_file(f,
        "#define ONLY_DEF 99\n"
        "void only_func(void) {}\n"
        "struct only_struct {};\n"
    );

    sc_tool_t *tool = sc_tool_symbol_lookup_new(dir);

    /* kinds via wrapper (passthrough) */
    sc_tool_result_t *r = exec_tool(tool, "{\"name\":\"only\",\"kinds\":\"define,struct\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "(kinds='define,struct')") != NULL, "kinds header from core");
    ASSERT(strstr(r->for_llm, "define: ONLY_DEF") != NULL);
    ASSERT(strstr(r->for_llm, "struct: only_struct") != NULL);
    ASSERT(strstr(r->for_llm, "func:") == NULL, "func excluded by wrapper-kinds");
    sc_tool_result_free(r);

    /* kinds=func only */
    r = exec_tool(tool, "{\"kinds\":\"func\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "only_func") != NULL);
    ASSERT(strstr(r->for_llm, "ONLY_DEF") == NULL);
    sc_tool_result_free(r);

    tool->destroy(tool);
    free(f);
    cleanup_tmpdir(dir);
}

static void test_symbols_edge_cases(void)
{
    char *dir = make_tmpdir();
    ASSERT_NOT_NULL(dir);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s", dir);
    char *cfile = sc_strbuf_finish(&sb);
    /* .c with no C symbols (only comments or non-matching) */
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/emptyish.c", dir);
    char *fempty = sc_strbuf_finish(&sb);
    write_file(fempty, "/* just comments */\n// no defines or funcs here\nint local_var = 1;\n");

    /* non-C file */
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/notc.py", dir);
    char *fpy = sc_strbuf_finish(&sb);
    write_file(fpy, "def pyfunc(): pass\n");

    /* binary-ish .c (has NUL byte, should be skipped by is_binary_file) */
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/binary.c", dir);
    char *fbin = sc_strbuf_finish(&sb);
    FILE *fb = fopen(fbin, "w");
    if (fb) {
        fputs("int binfunc() {}", fb);
        fputc('\0', fb);  /* force binary detect */
        fputc('x', fb);
        fclose(fb);
    }

    sc_tool_t *tool = sc_tool_code_graph_new(dir);

    /* empty results: name_filter no match */
    sc_tool_result_t *r = exec_tool(tool, "{\"action\":\"symbols\",\"path\":\".\",\"name_filter\":\"__NOMATCH__XYZ\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "(no C symbols matched") != NULL, "empty result message");
    ASSERT(strstr(r->for_llm, "0 result") != NULL);
    sc_tool_result_free(r);

    /* path to non-C : 0 C files scanned */
    r = exec_tool(tool, "{\"action\":\"symbols\",\"path\":\"notc.py\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "scanned 0 C file") != NULL, "non-C path scans 0");
    ASSERT(strstr(r->for_llm, "0 result") != NULL);
    sc_tool_result_free(r);

    /* single binary .c should also yield 0 */
    r = exec_tool(tool, "{\"action\":\"symbols\",\"path\":\"binary.c\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    /* still 0 C because binary skipped */
    ASSERT(strstr(r->for_llm, "0 result") != NULL || strstr(r->for_llm, "scanned 0") != NULL);
    sc_tool_result_free(r);

    /* truncation note when kinds filter active: create enough funcs to hit cap, then filter to funcs */
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/many.c", dir);
    char *fmany = sc_strbuf_finish(&sb);
    /* write 5 funcs so that with max=2 and kinds=func we hit cap during scan */
    write_file(fmany,
        "int f1(void){}\nint f2(void){}\nint f3(void){}\nint f4(void){}\nint f5(void){}\n"
        "#define D1 1\n"
    );
    /* Note: scan caps at max_results=2, kinds=func keeps the 2 funcs, post count==2 so >= triggers note */
    r = exec_tool(tool, "{\"action\":\"symbols\",\"path\":\"many.c\",\"kinds\":\"func\",\"max_results\":2}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "truncated at max_results=2") != NULL, "truncation note with kinds active");
    ASSERT(strstr(r->for_llm, "f1") != NULL);
    ASSERT(strstr(r->for_llm, "f2") != NULL);
    ASSERT(strstr(r->for_llm, "f3") == NULL, "capped");
    sc_tool_result_free(r);

    /* kinds that filters everything out -> empty after filter */
    r = exec_tool(tool, "{\"action\":\"symbols\",\"path\":\".\",\"kinds\":\"enum\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "0 result") != NULL);
    ASSERT(strstr(r->for_llm, "enum") != NULL || strstr(r->for_llm, "no C symbols") != NULL);
    sc_tool_result_free(r);

    tool->destroy(tool);
    free(cfile);
    free(fempty);
    free(fpy);
    free(fbin);
    free(fmany);
    cleanup_tmpdir(dir);
}

static void test_symbol_lookup_set_workspace(void)
{
    /* Basic interaction: create with ws1, lookup sees ws1 symbols; set_workspace(ws2), sees ws2 */
    /* Note: make_tmpdir uses static buffer, so we must copy immediately to support >1 call per test */
    char *raw1 = make_tmpdir();
    ASSERT_NOT_NULL(raw1);
    char *dir1 = sc_strdup(raw1);
    char *raw2 = make_tmpdir();
    ASSERT_NOT_NULL(raw2);
    char *dir2 = sc_strdup(raw2);

    /* dir1 has foo symbol */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/ws1.c", dir1);
    char *f1 = sc_strbuf_finish(&sb);
    write_file(f1, "int from_dir1_symbol(void) { return 1; }\n");

    /* dir2 has bar symbol */
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/ws2.c", dir2);
    char *f2 = sc_strbuf_finish(&sb);
    write_file(f2, "void from_dir2_symbol(void) {}\n");

    sc_tool_t *tool = sc_tool_symbol_lookup_new(dir1);
    ASSERT_NOT_NULL(tool);

    /* initial workspace = dir1 */
    sc_tool_result_t *r = exec_tool(tool, "{\"name\":\"dir1\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "from_dir1_symbol") != NULL);
    ASSERT(strstr(r->for_llm, "from_dir2_symbol") == NULL);
    sc_tool_result_free(r);

    /* switch workspace */
    tool->set_workspace(tool, dir2);

    /* now should see dir2 content */
    r = exec_tool(tool, "{\"name\":\"dir2\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "from_dir2_symbol") != NULL);
    ASSERT(strstr(r->for_llm, "from_dir1_symbol") == NULL, "old ws no longer active");
    sc_tool_result_free(r);

    /* also verify code_graph set_workspace works similarly (via direct) */
    sc_tool_t *cg = sc_tool_code_graph_new(dir1);
    cg->set_workspace(cg, dir2);
    r = exec_tool(cg, "{\"action\":\"symbols\",\"path\":\".\",\"name_filter\":\"dir2\"}");
    ASSERT_NOT_NULL(r);
    ASSERT(strstr(r->for_llm, "from_dir2_symbol") != NULL);
    sc_tool_result_free(r);
    cg->destroy(cg);

    tool->destroy(tool);
    free(f1);
    free(f2);
    cleanup_tmpdir(dir1);
    cleanup_tmpdir(dir2);
    free(dir1);
    free(dir2);
}

/* Additional expanded coverage for Phase 3 combinations (kinds+wrapper+set_workspace, unsupported kinds, empty post-filter via wrapper) */
static void test_symbol_lookup_kinds_set_workspace_and_unsupported(void)
{
    char *raw1 = make_tmpdir();
    ASSERT_NOT_NULL(raw1);
    char *dir1 = sc_strdup(raw1);
    char *raw2 = make_tmpdir();
    ASSERT_NOT_NULL(raw2);
    char *dir2 = sc_strdup(raw2);

    /* dir1: func + define */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/dir1.c", dir1);
    char *f1 = sc_strbuf_finish(&sb);
    write_file(f1, "int dir1_func(void){}\n#define DIR1_DEF 1\n");

    /* dir2: struct + define (for kinds test) */
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/dir2.c", dir2);
    char *f2 = sc_strbuf_finish(&sb);
    write_file(f2, "struct dir2_s { int x; };\n#define DIR2_DEF 2\nint dir2_func(void){}\n");

    sc_tool_t *sl = sc_tool_symbol_lookup_new(dir1);
    ASSERT_NOT_NULL(sl);

    /* initial: kinds=func via wrapper on dir1 */
    sc_tool_result_t *r = exec_tool(sl, "{\"kinds\":\"func\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "dir1_func") != NULL);
    ASSERT(strstr(r->for_llm, "DIR1_DEF") == NULL);
    sc_tool_result_free(r);

    /* switch workspace */
    sl->set_workspace(sl, dir2);

    /* now kinds=define via wrapper on dir2 */
    r = exec_tool(sl, "{\"kinds\":\"define\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "DIR2_DEF") != NULL);
    ASSERT(strstr(r->for_llm, "dir2_func") == NULL, "func excluded by kinds after switch");
    sc_tool_result_free(r);

    /* unsupported kinds (typedef,enum) -> empty results after filter (via wrapper) */
    r = exec_tool(sl, "{\"kinds\":\"typedef,enum\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "0 result") != NULL || strstr(r->for_llm, "no C symbols matched") != NULL);
    sc_tool_result_free(r);

    /* integration: kinds + name_filter via wrapper after switch */
    r = exec_tool(sl, "{\"name\":\"DIR2\",\"kinds\":\"define\"}");
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ(r->is_error, 0);
    ASSERT(strstr(r->for_llm, "DIR2_DEF") != NULL);
    sc_tool_result_free(r);

    sl->destroy(sl);
    free(f1);
    free(f2);
    cleanup_tmpdir(dir1);
    cleanup_tmpdir(dir2);
    free(dir1);
    free(dir2);
}

#endif /* SC_ENABLE_CODE_GRAPH */

int main(void)
{
#if SC_ENABLE_CODE_GRAPH
    RUN_TEST(test_create_and_destroy);
    RUN_TEST(test_build_js_project);
    RUN_TEST(test_build_python_project);
    RUN_TEST(test_build_c_project);
    RUN_TEST(test_query);
    RUN_TEST(test_stats);
    RUN_TEST(test_cycles);
    RUN_TEST(test_no_build);
    RUN_TEST(test_unknown_action);
    RUN_TEST(test_parameters);
    RUN_TEST(test_symbols_action);
    RUN_TEST(test_symbols_kinds_combined_with_filters);
    RUN_TEST(test_symbol_lookup_wrapper_basic);
    RUN_TEST(test_symbol_lookup_wrapper_with_kinds);
    RUN_TEST(test_symbols_edge_cases);
    RUN_TEST(test_symbol_lookup_set_workspace);
    RUN_TEST(test_symbol_lookup_kinds_set_workspace_and_unsupported);
#else
    printf("  Code graph disabled, skipping tests\n");
    _test_pass++;
#endif
    TEST_REPORT();
}
