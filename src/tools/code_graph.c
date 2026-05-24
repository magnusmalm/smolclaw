/*
 * tools/code_graph.c — Lightweight import dependency graph
 *
 * Regex-based extraction of imports from source files.
 * Supports JS/TS, Python, C/C++, Go, Rust.
 * In-memory, per-session graph.
 *
 * Actions: build, query, stats, cycles
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <ctype.h>  /* for local stristr */

#include "tools/code_graph.h"
#include "tools/types.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "logger.h"
#include "cJSON.h"

#define LOG_TAG "code_graph"
#define MAX_FILES 10000
#define MAX_FILE_SIZE (1024 * 1024) /* 1 MB */
#define MAX_CYCLES 20
#define MAX_IMPORTS_PER_FILE 256

/* Symbol lookup limits (for "symbols" action and Drill-down use) */
#define MAX_SYMBOL_RESULTS 256
#define MAX_SYMBOL_NAME 96
#define MAX_SYMBOL_SIG 192
#define MAX_SYMBOL_CTX 160

/* Symbol record — structured result for researcher symbol queries.
 * Returned by action "symbols". Designed for C code (smol* targets);
 * best-effort regex extraction (approximate on macros/#ifdef/complex decls).
 * Fields chosen for direct LLM citation in Drill-down without read_file. */
typedef struct {
    char path[512];           /* relative path from scan root */
    int line;                 /* 1-based */
    char kind[12];            /* "func" | "define" | "struct" | "typedef" | "enum" */
    char name[MAX_SYMBOL_NAME];
    char signature[MAX_SYMBOL_SIG];
    char context[MAX_SYMBOL_CTX];
} cg_symbol_t;

/* ========== Graph data structures ========== */

typedef struct {
    char *path;         /* relative path from scan root */
    char **imports;     /* imported module/file paths */
    int import_count;
    int import_cap;
} cg_node_t;

typedef struct {
    cg_node_t *nodes;
    int node_count;
    int node_cap;
    char *root_dir;
    /* Compiled regex patterns (compiled once) */
    regex_t re_js_import;
    regex_t re_js_require;
    regex_t re_py_import;
    regex_t re_py_from;
    regex_t re_c_include;
    regex_t re_rust_use;
    int patterns_compiled;

    /* Symbol extraction patterns (C-focused for Phase 3 Drill-down) */
    regex_t re_c_define;
    regex_t re_c_struct;
    regex_t re_c_func_def;   /* approximate function definition */
    int symbol_patterns_compiled;
} code_graph_t;

/* ========== Helpers ========== */

/* Local case-insensitive substring (portable, no _GNU_SOURCE dependency).
 * Used by symbol name filter for researcher queries ("Set_Ret" matches set_retention). */
static const char *stristr(const char *haystack, const char *needle)
{
    if (!haystack || !needle || !*needle) return haystack;
    for (; *haystack; ++haystack) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
            ++h; ++n;
        }
        if (!*n) return haystack;
    }
    return NULL;
}

static void node_add_import(cg_node_t *node, const char *imp)
{
    if (node->import_count >= MAX_IMPORTS_PER_FILE) return;
    if (node->import_count >= node->import_cap) {
        int new_cap = node->import_cap ? node->import_cap * 2 : 16;
        char **tmp = realloc(node->imports, (size_t)new_cap * sizeof(char *));
        if (!tmp) return;
        node->imports = tmp;
        node->import_cap = new_cap;
    }
    node->imports[node->import_count++] = sc_strdup(imp);
}

static cg_node_t *graph_add_node(code_graph_t *g, const char *path)
{
    if (g->node_count >= MAX_FILES) return NULL;
    if (g->node_count >= g->node_cap) {
        int new_cap = g->node_cap ? g->node_cap * 2 : 256;
        cg_node_t *tmp = realloc(g->nodes, (size_t)new_cap * sizeof(cg_node_t));
        if (!tmp) return NULL;
        g->nodes = tmp;
        g->node_cap = new_cap;
    }
    cg_node_t *n = &g->nodes[g->node_count++];
    memset(n, 0, sizeof(*n));
    n->path = sc_strdup(path);
    return n;
}

static void graph_free_data(code_graph_t *g)
{
    for (int i = 0; i < g->node_count; i++) {
        free(g->nodes[i].path);
        for (int j = 0; j < g->nodes[i].import_count; j++)
            free(g->nodes[i].imports[j]);
        free(g->nodes[i].imports);
    }
    free(g->nodes);
    g->nodes = NULL;
    g->node_count = 0;
    g->node_cap = 0;
}

static int is_binary_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 1;
    unsigned char buf[512];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    for (size_t i = 0; i < n; i++)
        if (buf[i] == 0) return 1;
    return 0;
}

/* File extension → language category */
enum lang { LANG_UNKNOWN = 0, LANG_JS, LANG_PY, LANG_C, LANG_GO, LANG_RUST };

static enum lang detect_language(const char *filename)
{
    const char *dot = strrchr(filename, '.');
    if (!dot) return LANG_UNKNOWN;
    if (strcmp(dot, ".js") == 0 || strcmp(dot, ".ts") == 0 ||
        strcmp(dot, ".jsx") == 0 || strcmp(dot, ".tsx") == 0 ||
        strcmp(dot, ".mjs") == 0 || strcmp(dot, ".mts") == 0)
        return LANG_JS;
    if (strcmp(dot, ".py") == 0 || strcmp(dot, ".pyx") == 0)
        return LANG_PY;
    if (strcmp(dot, ".c") == 0 || strcmp(dot, ".h") == 0 ||
        strcmp(dot, ".cpp") == 0 || strcmp(dot, ".hpp") == 0 ||
        strcmp(dot, ".cc") == 0 || strcmp(dot, ".cxx") == 0)
        return LANG_C;
    if (strcmp(dot, ".go") == 0)
        return LANG_GO;
    if (strcmp(dot, ".rs") == 0)
        return LANG_RUST;
    return LANG_UNKNOWN;
}

static const char *lang_name(enum lang l)
{
    switch (l) {
    case LANG_JS: return "JavaScript/TypeScript";
    case LANG_PY: return "Python";
    case LANG_C:  return "C/C++";
    case LANG_GO: return "Go";
    case LANG_RUST: return "Rust";
    default: return "Unknown";
    }
}

/* ========== Regex patterns ========== */

static int compile_patterns(code_graph_t *g)
{
    if (g->patterns_compiled) return 0;
    int err = 0;
    err |= regcomp(&g->re_js_import,
        "^import.*from ['\"]([^'\"]+)['\"]", REG_EXTENDED | REG_NEWLINE);
    err |= regcomp(&g->re_js_require,
        "require\\(['\"]([^'\"]+)['\"]\\)", REG_EXTENDED | REG_NEWLINE);
    err |= regcomp(&g->re_py_import,
        "^import ([a-zA-Z_][a-zA-Z0-9_.]+)", REG_EXTENDED | REG_NEWLINE);
    err |= regcomp(&g->re_py_from,
        "^from ([a-zA-Z_][a-zA-Z0-9_.]+) import", REG_EXTENDED | REG_NEWLINE);
    err |= regcomp(&g->re_c_include,
        "^#include \"([^\"]+)\"", REG_EXTENDED | REG_NEWLINE);
    err |= regcomp(&g->re_rust_use,
        "^use ([a-zA-Z_][a-zA-Z0-9_:]+)", REG_EXTENDED | REG_NEWLINE);
    if (err) return -1;
    g->patterns_compiled = 1;
    return 0;
}

/* Compile C symbol regexes (lazy, separate from import patterns).
 * These power the "symbols" action for Drill-down symbol lookup. */
static int compile_symbol_patterns(code_graph_t *g)
{
    if (g->symbol_patterns_compiled) return 0;
    int err = 0;
    /* #define FOO ... or #define FOO(x) ...  -> capture name */
    err |= regcomp(&g->re_c_define,
        "^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z0-9_]*)", REG_EXTENDED | REG_NEWLINE);
    /* struct Foo or typedef struct Foo.
     * POSIX ERE has no non-capturing (?:) — uses plain (). Name is group 2. */
    err |= regcomp(&g->re_c_struct,
        "^[ \t]*(typedef[ \t]+)?struct[ \t]+([A-Za-z_][A-Za-z0-9_]*)", REG_EXTENDED | REG_NEWLINE);
    /* Approximate C function definition (common smol* style).
     * Captures last identifier before ( as the function name (group 4 in POSIX ERE
     * — the inner alternation gets its own implicit group). */
    err |= regcomp(&g->re_c_func_def,
        "^[ \t]*((static|inline|extern|const|unsigned|signed|void|int|char|short|long|float|double|size_t|uint[0-9]+_t|int[0-9]+_t|bool)[ \t]+)*([A-Za-z_][A-Za-z0-9_ \t\\*]+)[ \t]+([A-Za-z_][A-Za-z0-9_]+)[ \t]*\\(",
        REG_EXTENDED | REG_NEWLINE);
    if (err) return -1;
    g->symbol_patterns_compiled = 1;
    return 0;
}

/* Extract regex match group 1 at all positions in content */
static void extract_matches(const regex_t *re, const char *content,
                             cg_node_t *node)
{
    regmatch_t m[2];
    const char *p = content;
    while (regexec(re, p, 2, m, 0) == 0) {
        if (m[1].rm_so >= 0) {
            int len = m[1].rm_eo - m[1].rm_so;
            char *imp = malloc((size_t)len + 1);
            if (imp) {
                memcpy(imp, p + m[1].rm_so, (size_t)len);
                imp[len] = '\0';
                node_add_import(node, imp);
                free(imp);
            }
        }
        p += m[0].rm_eo;
    }
}

/* Go imports are special: "path" inside import block */
static void extract_go_imports(const char *content, cg_node_t *node)
{
    /* Find import blocks: import ( "pkg1" "pkg2" ) */
    const char *p = content;
    while ((p = strstr(p, "import")) != NULL) {
        p += 6;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '(') {
            p++;
            /* Scan until ) */
            while (*p && *p != ')') {
                /* Find quoted string */
                const char *q = strchr(p, '"');
                if (!q || q > strchr(p, ')')) break;
                q++;
                const char *end = strchr(q, '"');
                if (!end) break;
                int len = (int)(end - q);
                char *imp = malloc((size_t)len + 1);
                if (imp) {
                    memcpy(imp, q, (size_t)len);
                    imp[len] = '\0';
                    node_add_import(node, imp);
                    free(imp);
                }
                p = end + 1;
            }
        } else if (*p == '"') {
            /* Single import: import "pkg" */
            p++;
            const char *end = strchr(p, '"');
            if (end) {
                int len = (int)(end - p);
                char *imp = malloc((size_t)len + 1);
                if (imp) {
                    memcpy(imp, p, (size_t)len);
                    imp[len] = '\0';
                    node_add_import(node, imp);
                    free(imp);
                }
                p = end + 1;
            }
        }
    }
}

static void extract_imports(code_graph_t *g, const char *content,
                            enum lang lang, cg_node_t *node)
{
    switch (lang) {
    case LANG_JS:
        extract_matches(&g->re_js_import, content, node);
        extract_matches(&g->re_js_require, content, node);
        break;
    case LANG_PY:
        extract_matches(&g->re_py_import, content, node);
        extract_matches(&g->re_py_from, content, node);
        break;
    case LANG_C:
        extract_matches(&g->re_c_include, content, node);
        break;
    case LANG_GO:
        extract_go_imports(content, node);
        break;
    case LANG_RUST:
        extract_matches(&g->re_rust_use, content, node);
        break;
    default:
        break;
    }
}

/* Basic C symbol extraction for "symbols" action (Phase 3 Drill-down primitive).
 * Scans C/C++ content line-by-line, uses precompiled regexes + heuristics.
 * Fills caller-provided cg_symbol_t array (capped). Name filter is case-insensitive
 * substring match (NULL/"" matches everything). Returns # added this call.
 *
 * Limitations (documented for researcher):
 * - Regex-based, no full AST: misses K&R defs, some pointer-to-func returns,
 *   macros before decl, #ifdef-hidden symbols, C++ templates/ctors, etc.
 * - Good on smol* clean modern C (static funcs, simple structs, defines).
 * - Context is the definition line (expand with read_file only if needed).
 */
static int extract_c_symbols(code_graph_t *g, const char *content,
                             const char *relpath,
                             cg_symbol_t *symbols, int max_syms, int *out_count,
                             const char *name_filter)
{
    if (!g || !content || !relpath || !symbols || max_syms <= 0) return 0;
    if (compile_symbol_patterns(g) != 0) return 0;

    int local_count = (*out_count > 0 ? *out_count : 0);
    int added = 0;

    const char *p = content;
    int lineno = 1;
    char linebuf[1024];

    while (*p && local_count < max_syms) {
        const char *line_start = p;
        size_t linelen = 0;
        while (*p && *p != '\n' && linelen < sizeof(linebuf)-1) {
            linebuf[linelen++] = *p++;
        }
        linebuf[linelen] = '\0';
        if (*p == '\n') p++;

        /* Very crude single-line comment stripping for matching (v1) */
        char *cmt = strstr(linebuf, "//");
        if (cmt) *cmt = '\0';
        cmt = strstr(linebuf, "/*");
        if (cmt) *cmt = '\0';

        regmatch_t m[2];

        /* #define NAME */
        if (regexec(&g->re_c_define, linebuf, 2, m, 0) == 0 && m[1].rm_so >= 0) {
            int nlen = m[1].rm_eo - m[1].rm_so;
            if (nlen > 0 && nlen < MAX_SYMBOL_NAME-1) {
                char namebuf[MAX_SYMBOL_NAME];
                memcpy(namebuf, linebuf + m[1].rm_so, (size_t)nlen);
                namebuf[nlen] = '\0';
                if (!name_filter || !name_filter[0] || stristr(namebuf, name_filter)) {
                    cg_symbol_t *s = &symbols[local_count];
                    strncpy(s->path, relpath, sizeof(s->path)-1); s->path[sizeof(s->path)-1] = '\0';
                    s->line = lineno;
                    strcpy(s->kind, "define");
                    strncpy(s->name, namebuf, MAX_SYMBOL_NAME-1); s->name[MAX_SYMBOL_NAME-1] = '\0';
                    strncpy(s->signature, linebuf, MAX_SYMBOL_SIG-1); s->signature[MAX_SYMBOL_SIG-1] = '\0';
                    strncpy(s->context, linebuf, MAX_SYMBOL_CTX-1); s->context[MAX_SYMBOL_CTX-1] = '\0';
                    local_count++;
                    added++;
                }
            }
        }

        /* struct NAME — name is capture group 2 (group 1 = optional "typedef ") */
        regmatch_t ms[3];
        if (local_count < max_syms &&
            regexec(&g->re_c_struct, linebuf, 3, ms, 0) == 0 && ms[2].rm_so >= 0) {
            int nlen = ms[2].rm_eo - ms[2].rm_so;
            if (nlen > 0 && nlen < MAX_SYMBOL_NAME-1) {
                char namebuf[MAX_SYMBOL_NAME];
                memcpy(namebuf, linebuf + ms[2].rm_so, (size_t)nlen);
                namebuf[nlen] = '\0';
                if (!name_filter || !name_filter[0] || stristr(namebuf, name_filter)) {
                    cg_symbol_t *s = &symbols[local_count];
                    strncpy(s->path, relpath, sizeof(s->path)-1); s->path[sizeof(s->path)-1] = '\0';
                    s->line = lineno;
                    strcpy(s->kind, "struct");
                    strncpy(s->name, namebuf, MAX_SYMBOL_NAME-1); s->name[MAX_SYMBOL_NAME-1] = '\0';
                    strncpy(s->signature, linebuf, MAX_SYMBOL_SIG-1); s->signature[MAX_SYMBOL_SIG-1] = '\0';
                    strncpy(s->context, linebuf, MAX_SYMBOL_CTX-1); s->context[MAX_SYMBOL_CTX-1] = '\0';
                    local_count++;
                    added++;
                }
            }
        }

        /* func definition — name is capture group 4 (groups 1+2 = optional return-type
         * tokens, group 3 = trailing return type). POSIX ERE inserts an implicit group
         * for the alternation inside group 1. */
        if (local_count < max_syms) {
            regmatch_t mf[5];
            if (regexec(&g->re_c_func_def, linebuf, 5, mf, 0) == 0 && mf[4].rm_so >= 0) {
                int nlen = mf[4].rm_eo - mf[4].rm_so;
                if (nlen > 0 && nlen < MAX_SYMBOL_NAME-1) {
                    char namebuf[MAX_SYMBOL_NAME];
                    memcpy(namebuf, linebuf + mf[4].rm_so, (size_t)nlen);
                    namebuf[nlen] = '\0';
                    if (!name_filter || !name_filter[0] || stristr(namebuf, name_filter)) {
                        /* sig approx: line up to first ) after the name */
                        char sigbuf[MAX_SYMBOL_SIG];
                        const char *after_name = linebuf + mf[4].rm_so;
                        const char *rparen = strchr(after_name, ')');
                        int siglen;
                        if (rparen) {
                            siglen = (int)(rparen - linebuf) + 1;
                            if (siglen > MAX_SYMBOL_SIG-1) siglen = MAX_SYMBOL_SIG-1;
                            memcpy(sigbuf, linebuf, (size_t)siglen);
                            sigbuf[siglen] = '\0';
                        } else {
                            strncpy(sigbuf, linebuf, MAX_SYMBOL_SIG-1); sigbuf[MAX_SYMBOL_SIG-1] = '\0';
                        }
                        cg_symbol_t *s = &symbols[local_count];
                        strncpy(s->path, relpath, sizeof(s->path)-1); s->path[sizeof(s->path)-1] = '\0';
                        s->line = lineno;
                        strcpy(s->kind, "func");
                        strncpy(s->name, namebuf, MAX_SYMBOL_NAME-1); s->name[MAX_SYMBOL_NAME-1] = '\0';
                        strncpy(s->signature, sigbuf, MAX_SYMBOL_SIG-1); s->signature[MAX_SYMBOL_SIG-1] = '\0';
                        strncpy(s->context, linebuf, MAX_SYMBOL_CTX-1); s->context[MAX_SYMBOL_CTX-1] = '\0';
                        local_count++;
                        added++;
                    }
                }
            }
        }

        lineno++;
    }

    *out_count = local_count;
    return added;
}

/* ========== Directory scanning ========== */

/* Directories to skip */
static int should_skip_dir(const char *name)
{
    static const char *skip[] = {
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "build", "dist", "target", ".next", ".tox", "vendor",
        ".mypy_cache", ".pytest_cache", ".cargo"
    };
    for (int i = 0; i < (int)(sizeof(skip) / sizeof(skip[0])); i++)
        if (strcmp(name, skip[i]) == 0) return 1;
    return 0;
}

static int scan_tree(code_graph_t *g, const char *dir_path,
                      const char *rel_prefix)
{
    DIR *d = opendir(dir_path);
    if (!d) return 0;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && g->node_count < MAX_FILES) {
        if (ent->d_name[0] == '.') continue;

        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "%s/%s", dir_path, ent->d_name);
        char *fullpath = sc_strbuf_finish(&sb);

        sc_strbuf_init(&sb);
        if (rel_prefix && rel_prefix[0])
            sc_strbuf_appendf(&sb, "%s/%s", rel_prefix, ent->d_name);
        else
            sc_strbuf_appendf(&sb, "%s", ent->d_name);
        char *relpath = sc_strbuf_finish(&sb);

        struct stat st;
        if (stat(fullpath, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                if (!should_skip_dir(ent->d_name))
                    count += scan_tree(g, fullpath, relpath);
            } else if (S_ISREG(st.st_mode) && st.st_size > 0 &&
                       st.st_size <= MAX_FILE_SIZE) {
                enum lang lang = detect_language(ent->d_name);
                if (lang != LANG_UNKNOWN && !is_binary_file(fullpath)) {
                    FILE *f = fopen(fullpath, "r");
                    if (f) {
                        char *content = malloc((size_t)st.st_size + 1);
                        if (content) {
                            size_t n = fread(content, 1, (size_t)st.st_size, f);
                            content[n] = '\0';

                            cg_node_t *node = graph_add_node(g, relpath);
                            if (node) {
                                extract_imports(g, content, lang, node);
                                count++;
                            }
                            free(content);
                        }
                        fclose(f);
                    }
                }
            }
        }
        free(fullpath);
        free(relpath);
    }
    closedir(d);
    return count;
}

/* ========== Analysis functions ========== */

/* DFS cycle detection */
typedef struct {
    char cycles[MAX_CYCLES][512];
    int cycle_count;
} cycle_result_t;

static int find_node_idx(code_graph_t *g, const char *path)
{
    for (int i = 0; i < g->node_count; i++)
        if (strcmp(g->nodes[i].path, path) == 0) return i;
    return -1;
}

/* DFS with white(0)/gray(1)/black(2) coloring */
static void dfs_cycles(code_graph_t *g, int idx, int *color,
                        int *parent, cycle_result_t *cr)
{
    if (cr->cycle_count >= MAX_CYCLES) return;
    color[idx] = 1; /* gray */

    for (int e = 0; e < g->nodes[idx].import_count; e++) {
        int neighbor = find_node_idx(g, g->nodes[idx].imports[e]);
        if (neighbor < 0) continue;

        if (color[neighbor] == 1) {
            /* Back edge → cycle found */
            if (cr->cycle_count < MAX_CYCLES) {
                snprintf(cr->cycles[cr->cycle_count], 512,
                         "%s → %s", g->nodes[idx].path,
                         g->nodes[neighbor].path);
                cr->cycle_count++;
            }
        } else if (color[neighbor] == 0) {
            parent[neighbor] = idx;
            dfs_cycles(g, neighbor, color, parent, cr);
        }
    }

    color[idx] = 2; /* black */
}

/* ========== Tool actions ========== */

static sc_tool_result_t *action_build(code_graph_t *g, cJSON *args)
{
    const char *dir = sc_json_get_string(args, "directory", ".");

    /* Resolve directory */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    if (dir[0] == '/') {
        sc_strbuf_appendf(&sb, "%s", dir);
    } else {
        sc_strbuf_appendf(&sb, "%s/%s", g->root_dir, dir);
    }
    char *scan_dir = sc_strbuf_finish(&sb);

    /* Clear old graph */
    graph_free_data(g);

    /* Compile patterns */
    if (compile_patterns(g) != 0) {
        free(scan_dir);
        return sc_tool_result_error("failed to compile regex patterns");
    }

    int count = scan_tree(g, scan_dir, "");
    free(scan_dir);

    /* Compute total edges */
    int edges = 0;
    for (int i = 0; i < g->node_count; i++)
        edges += g->nodes[i].import_count;

    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Graph built: %d files, %d import edges", count, edges);
    if (g->node_count >= MAX_FILES)
        sc_strbuf_appendf(&sb, " (truncated at %d files)", MAX_FILES);

    char *msg = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(msg);
    free(msg);
    return r;
}

static sc_tool_result_t *action_query(code_graph_t *g, cJSON *args)
{
    if (g->node_count == 0)
        return sc_tool_result_error("graph not built — run build first");

    const char *file = sc_json_get_string(args, "file", NULL);
    if (!file)
        return sc_tool_result_error("file parameter is required");

    int idx = find_node_idx(g, file);
    if (idx < 0)
        return sc_tool_result_error("file not found in graph");

    cg_node_t *node = &g->nodes[idx];
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    sc_strbuf_appendf(&sb, "File: %s\n\nImports (%d):\n", file,
                       node->import_count);
    for (int i = 0; i < node->import_count; i++)
        sc_strbuf_appendf(&sb, "  → %s\n", node->imports[i]);

    /* Reverse lookup: who imports this file */
    sc_strbuf_appendf(&sb, "\nImported by:\n");
    int imported_by = 0;
    for (int i = 0; i < g->node_count; i++) {
        for (int j = 0; j < g->nodes[i].import_count; j++) {
            if (strcmp(g->nodes[i].imports[j], file) == 0) {
                sc_strbuf_appendf(&sb, "  ← %s\n", g->nodes[i].path);
                imported_by++;
                break;
            }
        }
    }
    if (imported_by == 0)
        sc_strbuf_append(&sb, "  (none)\n");

    char *msg = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(msg);
    free(msg);
    return r;
}

static sc_tool_result_t *action_stats(code_graph_t *g)
{
    if (g->node_count == 0)
        return sc_tool_result_error("graph not built — run build first");

    int total_edges = 0;
    int lang_counts[6] = {0};

    /* Count imports per file for top-10 */
    typedef struct { const char *path; int count; } import_count_t;
    import_count_t *imports_by = calloc((size_t)g->node_count,
                                         sizeof(import_count_t));

    for (int i = 0; i < g->node_count; i++) {
        total_edges += g->nodes[i].import_count;
        enum lang l = detect_language(g->nodes[i].path);
        if (l < 6) lang_counts[l]++;

        /* Count how many files import each path */
        imports_by[i].path = g->nodes[i].path;
        imports_by[i].count = 0;
    }

    /* Count reverse imports (how many other files import each file) */
    for (int i = 0; i < g->node_count; i++) {
        for (int j = 0; j < g->nodes[i].import_count; j++) {
            int target = find_node_idx(g, g->nodes[i].imports[j]);
            if (target >= 0)
                imports_by[target].count++;
        }
    }

    /* Sort by import count (simple selection of top 10) */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Graph Statistics:\n");
    sc_strbuf_appendf(&sb, "  Files: %d\n", g->node_count);
    sc_strbuf_appendf(&sb, "  Import edges: %d\n\n", total_edges);

    sc_strbuf_append(&sb, "Language breakdown:\n");
    for (int l = 1; l < 6; l++) {
        if (lang_counts[l] > 0)
            sc_strbuf_appendf(&sb, "  %s: %d\n", lang_name((enum lang)l),
                              lang_counts[l]);
    }

    sc_strbuf_append(&sb, "\nTop-10 most imported:\n");
    for (int top = 0; top < 10 && top < g->node_count; top++) {
        int best = -1;
        for (int i = 0; i < g->node_count; i++) {
            if (imports_by[i].count >= 0 &&
                (best < 0 || imports_by[i].count > imports_by[best].count))
                best = i;
        }
        if (best < 0 || imports_by[best].count == 0) break;
        sc_strbuf_appendf(&sb, "  %3d  %s\n", imports_by[best].count,
                          imports_by[best].path);
        imports_by[best].count = -1; /* mark as used */
    }

    free(imports_by);

    char *msg = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(msg);
    free(msg);
    return r;
}

static sc_tool_result_t *action_cycles(code_graph_t *g)
{
    if (g->node_count == 0)
        return sc_tool_result_error("graph not built — run build first");

    int *color = calloc((size_t)g->node_count, sizeof(int));
    int *parent = calloc((size_t)g->node_count, sizeof(int));
    cycle_result_t cr = {.cycle_count = 0};

    for (int i = 0; i < g->node_count; i++)
        parent[i] = -1;

    for (int i = 0; i < g->node_count; i++) {
        if (color[i] == 0)
            dfs_cycles(g, i, color, parent, &cr);
    }

    free(color);
    free(parent);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    if (cr.cycle_count == 0) {
        sc_strbuf_append(&sb, "No import cycles detected.");
    } else {
        sc_strbuf_appendf(&sb, "Found %d cycle%s:\n",
                          cr.cycle_count, cr.cycle_count == 1 ? "" : "s");
        for (int i = 0; i < cr.cycle_count; i++)
            sc_strbuf_appendf(&sb, "  %d. %s\n", i + 1, cr.cycles[i]);
        if (cr.cycle_count >= MAX_CYCLES)
            sc_strbuf_appendf(&sb, "  ... (truncated at %d)\n", MAX_CYCLES);
    }

    char *msg = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(msg);
    free(msg);
    return r;
}

/* Symbols-specific tree walker (separate from import-graph scan_tree to avoid
 * any behavior change to build/query/etc.). Reuses shared helpers (detect_language,
 * should_skip_dir, is_binary_file, extract_c_symbols). Only processes .c/.h. */
static int scan_symbols_tree(code_graph_t *g, const char *dir_path,
                             const char *rel_prefix,
                             cg_symbol_t *symbols, int max_syms, int *out_count,
                             const char *name_filter)
{
    DIR *d = opendir(dir_path);
    if (!d) return 0;

    int files = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && *out_count < max_syms) {
        if (ent->d_name[0] == '.') continue;

        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "%s/%s", dir_path, ent->d_name);
        char *fullpath = sc_strbuf_finish(&sb);

        sc_strbuf_init(&sb);
        if (rel_prefix && rel_prefix[0])
            sc_strbuf_appendf(&sb, "%s/%s", rel_prefix, ent->d_name);
        else
            sc_strbuf_appendf(&sb, "%s", ent->d_name);
        char *relpath = sc_strbuf_finish(&sb);

        struct stat st;
        if (stat(fullpath, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                if (!should_skip_dir(ent->d_name))
                    files += scan_symbols_tree(g, fullpath, relpath, symbols, max_syms, out_count, name_filter);
            } else if (S_ISREG(st.st_mode) && st.st_size > 0 &&
                       st.st_size <= MAX_FILE_SIZE) {
                enum lang lang = detect_language(ent->d_name);
                if (lang == LANG_C && !is_binary_file(fullpath)) {
                    FILE *f = fopen(fullpath, "r");
                    if (f) {
                        char *content = malloc((size_t)st.st_size + 1);
                        if (content) {
                            size_t n = fread(content, 1, (size_t)st.st_size, f);
                            content[n] = '\0';
                            extract_c_symbols(g, content, relpath, symbols, max_syms, out_count, name_filter);
                            files++;
                            free(content);
                        }
                        fclose(f);
                    }
                }
            }
        }
        free(fullpath);
        free(relpath);
    }
    closedir(d);
    return files;
}

/* Action handler for "symbols". Basic working implementation for first Phase 3
 * increment: callable, scans C files, uses pre-existing extract_c_symbols,
 * returns bounded researcher-friendly text output with "kind: name at path:line (sig)"
 * + context lines. Does not modify import graph state. */

/* Cheap post-extract filter helper for the `kinds` parameter (comma-separated).
 * Supports: func, define, struct, typedef, enum (as set by extraction).
 * Boundary-aware to avoid false matches. If list empty, everything matches. */
static int kind_matches(const char *kind, const char *list)
{
    if (!list || !*list) return 1;
    if (!kind || !*kind) return 0;
    size_t klen = strlen(kind);
    const char *p = list;
    while ((p = strstr(p, kind)) != NULL) {
        if ((p == list || *(p-1) == ',') &&
            (p[klen] == '\0' || p[klen] == ',')) {
            return 1;
        }
        p += klen ? klen : 1;
    }
    return 0;
}

static sc_tool_result_t *action_symbols(code_graph_t *g, cJSON *args)
{
    const char *target = sc_json_get_string(args, "path", NULL);
    if (!target || !target[0])
        target = sc_json_get_string(args, "directory", ".");

    const char *name_filter = sc_json_get_string(args, "name_filter", NULL);
    int max_results = sc_json_get_int(args, "max_results", 50);
    if (max_results < 1) max_results = 1;
    if (max_results > MAX_SYMBOL_RESULTS) max_results = MAX_SYMBOL_RESULTS;
    /* "kinds" is now supported via cheap post-extract filter (see below) */

    /* Resolve target (absolute or under root_dir) */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    if (target[0] == '/') {
        sc_strbuf_appendf(&sb, "%s", target);
    } else {
        sc_strbuf_appendf(&sb, "%s/%s", g->root_dir, target);
    }
    char *abs_target = sc_strbuf_finish(&sb);

    cg_symbol_t *symbols = calloc((size_t)max_results, sizeof(cg_symbol_t));
    if (!symbols) {
        free(abs_target);
        return sc_tool_result_error("allocation failure for symbol results");
    }

    int count = 0;
    int files_scanned = 0;

    struct stat st;
    if (stat(abs_target, &st) != 0) {
        free(symbols);
        free(abs_target);
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "Path not found under workspace: %s", target);
        char *msg = sc_strbuf_finish(&sb);
        sc_tool_result_t *r = sc_tool_result_new(msg);
        free(msg);
        return r;
    }

    if (S_ISDIR(st.st_mode)) {
        const char *init_prefix = (strcmp(target, ".") == 0 ? "" : target);
        files_scanned = scan_symbols_tree(g, abs_target, init_prefix, symbols, max_results, &count, name_filter);
    } else if (S_ISREG(st.st_mode)) {
        const char *leaf = strrchr(target, '/');
        leaf = leaf ? (leaf + 1) : target;
        enum lang lang = detect_language(leaf);
        if (lang == LANG_C && !is_binary_file(abs_target) &&
            st.st_size > 0 && st.st_size <= MAX_FILE_SIZE) {
            FILE *f = fopen(abs_target, "r");
            if (f) {
                char *content = malloc((size_t)st.st_size + 1);
                if (content) {
                    size_t n = fread(content, 1, (size_t)st.st_size, f);
                    content[n] = '\0';
                    /* Use full user-supplied target for the symbol path (e.g. "src/foo.c") so :line citations match query */
                    extract_c_symbols(g, content, target, symbols, max_results, &count, name_filter);
                    files_scanned = 1;
                    free(content);
                }
                fclose(f);
            }
        }
    }

    /* Post-extract `kinds` filter (cheap O(N) for N<=256).
     * kinds_str is comma-separated (e.g. "func,define,struct"). Only symbols
     * whose .kind exactly matches one of the requested tokens are kept.
     * If absent/empty, all are returned (backward compat).
     */
    const char *kinds_str = sc_json_get_string(args, "kinds", NULL);
    if (kinds_str && *kinds_str && count > 0) {
        int new_count = 0;
        for (int i = 0; i < count; i++) {
            if (kind_matches(symbols[i].kind, kinds_str)) {
                if (new_count != i) {
                    symbols[new_count] = symbols[i];
                }
                new_count++;
            }
        }
        count = new_count;
    }

    /* Researcher-friendly, greppable, citable output.
     * TODO (v1 / provisional): The current format
     *   "kind: name at path:line (signature)\n  context: ..."
     * works for direct LLM citation/grepping in Drill-down and is intentionally
     * simple. It may be refined (e.g. bullets, optional JSON envelope, or
     * stricter per-kind layout) in the future. The `kinds` filter and
     * `symbol_lookup` wrapper are now implemented; see docs for usage.
     * Update docs/tools/code_graph.md when format changes.
     */
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "code_graph symbols under '%s'", target);
    if (name_filter && name_filter[0])
        sc_strbuf_appendf(&sb, " (name_filter='%s')", name_filter);
    if (kinds_str && *kinds_str)
        sc_strbuf_appendf(&sb, " (kinds='%s')", kinds_str);
    sc_strbuf_appendf(&sb, ": %d result%s (scanned %d C file%s; capped at %d)\n\n",
                      count, (count == 1 ? "" : "s"),
                      files_scanned, (files_scanned == 1 ? "" : "s"),
                      max_results);

    if (count == 0) {
        sc_strbuf_append(&sb, "(no C symbols matched; supported kinds: func/define/struct/typedef/enum. "
                              "Use on smol* .c/.h sources. Try name_filter or path=\"src\").\n");
    } else {
        for (int i = 0; i < count; i++) {
            const cg_symbol_t *s = &symbols[i];
            sc_strbuf_appendf(&sb, "%s: %s at %s:%d (%s)\n",
                              s->kind, s->name, s->path, s->line, s->signature);
            if (s->context[0])
                sc_strbuf_appendf(&sb, "  context: %s\n", s->context);
            sc_strbuf_append_char(&sb, '\n');
        }
        if (count >= max_results) {
            sc_strbuf_appendf(&sb, "... (truncated at max_results=%d — use name_filter or narrower path for Drill-down)\n", max_results);
        }
    }

    free(symbols);
    free(abs_target);

    char *msg = sc_strbuf_finish(&sb);
    sc_tool_result_t *r = sc_tool_result_new(msg);
    free(msg);
    return r;
}

/* ========== Tool vtable ========== */

static cJSON *code_graph_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = cJSON_CreateObject();
    cJSON_AddStringToObject(schema, "type", "object");

    cJSON *props = cJSON_AddObjectToObject(schema, "properties");

    cJSON *action = cJSON_AddObjectToObject(props, "action");
    cJSON_AddStringToObject(action, "type", "string");
    cJSON_AddStringToObject(action, "description",
        "Action: 'build' (scan dir, extract imports), 'query' (imports/imported-by for a file), "
        "'stats' (counts, top-10, language breakdown), 'cycles' (detect circular imports), "
        "'symbols' (C/C++ symbol lookup: funcs/structs/defines/typedefs/enums for Drill-down; path+name_filter supported)");
    cJSON *action_enum = cJSON_AddArrayToObject(action, "enum");
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("build"));
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("query"));
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("stats"));
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("cycles"));
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("symbols"));

    cJSON *directory = cJSON_AddObjectToObject(props, "directory");
    cJSON_AddStringToObject(directory, "type", "string");
    cJSON_AddStringToObject(directory, "description",
        "Directory to scan (for build action). Relative to workspace. Default: '.'");

    cJSON *file = cJSON_AddObjectToObject(props, "file");
    cJSON_AddStringToObject(file, "type", "string");
    cJSON_AddStringToObject(file, "description",
        "File path to query (for query action). Must be a path from the built graph.");

    /* New optional params for "symbols" action (Phase 3) */
    cJSON *sym_path = cJSON_AddObjectToObject(props, "path");
    cJSON_AddStringToObject(sym_path, "type", "string");
    cJSON_AddStringToObject(sym_path, "description",
        "Target path or directory for 'symbols' action (C/C++ files scanned). Relative to workspace. Default: '.'. Supports single .c/.h file too.");

    cJSON *name_filter = cJSON_AddObjectToObject(props, "name_filter");
    cJSON_AddStringToObject(name_filter, "type", "string");
    cJSON_AddStringToObject(name_filter, "description",
        "Case-insensitive substring to filter symbol names (for 'symbols'). E.g. 'ret' matches set_retention or RET_*. Default: none (all).");

    cJSON *max_res = cJSON_AddObjectToObject(props, "max_results");
    cJSON_AddStringToObject(max_res, "type", "integer");
    cJSON_AddStringToObject(max_res, "description",
        "Max number of symbol results to return for 'symbols' (1..256). Default: 50. Bounded for researcher use in Drill-down.");

    cJSON *kinds = cJSON_AddObjectToObject(props, "kinds");
    cJSON_AddStringToObject(kinds, "type", "string");
    cJSON_AddStringToObject(kinds, "description",
        "Optional comma-separated list of kinds to include (for 'symbols'): 'func,define,struct,typedef,enum'. Default: all kinds.");

    cJSON *req = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(req, cJSON_CreateString("action"));
    return schema;
}

static sc_tool_result_t *code_graph_execute(sc_tool_t *self, cJSON *args,
                                             void *ctx)
{
    (void)ctx;
    code_graph_t *g = self->data;
    const char *action = sc_json_get_string(args, "action", NULL);

    if (!action)
        return sc_tool_result_error("action is required");

    if (strcmp(action, "build") == 0)
        return action_build(g, args);
    if (strcmp(action, "query") == 0)
        return action_query(g, args);
    if (strcmp(action, "stats") == 0)
        return action_stats(g);
    if (strcmp(action, "cycles") == 0)
        return action_cycles(g);
    if (strcmp(action, "symbols") == 0)
        return action_symbols(g, args);

    return sc_tool_result_error("unknown action (use: build, query, stats, cycles, symbols)");
}

/* set_workspace vtable hook — updates the captured root_dir so that subsequent
 * build/query/stats/cycles/symbols actions resolve paths against the new workspace.
 * Modeled exactly on git_set_workspace / fs_set_workspace. Minimal: only swaps
 * the string; existing graph data (if any) is left for the next explicit build()
 * or symbols() call to handle. References the provisional output format TODO
 * already present in the action_symbols formatter.
 */
static void code_graph_set_workspace(sc_tool_t *self, const char *workspace)
{
    code_graph_t *g = self->data;
    if (!g || !workspace) return;
    free(g->root_dir);
    g->root_dir = sc_strdup(workspace);
}

static void code_graph_destroy(sc_tool_t *self)
{
    if (!self) return;
    code_graph_t *g = self->data;
    if (g) {
        graph_free_data(g);
        if (g->patterns_compiled) {
            regfree(&g->re_js_import);
            regfree(&g->re_js_require);
            regfree(&g->re_py_import);
            regfree(&g->re_py_from);
            regfree(&g->re_c_include);
            regfree(&g->re_rust_use);
        }
        if (g->symbol_patterns_compiled) {
            regfree(&g->re_c_define);
            regfree(&g->re_c_struct);
            regfree(&g->re_c_func_def);
        }
        free(g->root_dir);
        free(g);
    }
    free(self);
}

sc_tool_t *sc_tool_code_graph_new(const char *workspace)
{
    if (!workspace) return NULL;

    code_graph_t *g = calloc(1, sizeof(*g));
    if (!g) return NULL;
    g->root_dir = sc_strdup(workspace);

    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) { free(g->root_dir); free(g); return NULL; }

    t->name = "code_graph";
    t->description = "Analyze import dependencies across source files (build/query/stats/cycles) "
                     "or C/C++ symbols (action 'symbols' for Drill-down: funcs, structs, defines etc. with path:line). "
                     "Supports JS/TS, Python, C/C++, Go, Rust for graphs; focused C extraction for symbols.";
    t->parameters = code_graph_parameters;
    t->execute = code_graph_execute;
    t->destroy = code_graph_destroy;
    t->set_workspace = code_graph_set_workspace;
    t->needs_confirm = 0;
    t->data = g;
    return t;
}
