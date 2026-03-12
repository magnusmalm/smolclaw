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
} code_graph_t;

/* ========== Helpers ========== */

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
        "'stats' (counts, top-10, language breakdown), 'cycles' (detect circular imports)");
    cJSON *action_enum = cJSON_AddArrayToObject(action, "enum");
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("build"));
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("query"));
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("stats"));
    cJSON_AddItemToArray(action_enum, cJSON_CreateString("cycles"));

    cJSON *directory = cJSON_AddObjectToObject(props, "directory");
    cJSON_AddStringToObject(directory, "type", "string");
    cJSON_AddStringToObject(directory, "description",
        "Directory to scan (for build action). Relative to workspace. Default: '.'");

    cJSON *file = cJSON_AddObjectToObject(props, "file");
    cJSON_AddStringToObject(file, "type", "string");
    cJSON_AddStringToObject(file, "description",
        "File path to query (for query action). Must be a path from the built graph.");

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

    return sc_tool_result_error("unknown action (use: build, query, stats, cycles)");
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
    t->description = "Analyze import dependencies across source files. "
                     "Build a graph, query imports for a file, get statistics, "
                     "or detect circular imports. Supports JS/TS, Python, C/C++, Go, Rust.";
    t->parameters = code_graph_parameters;
    t->execute = code_graph_execute;
    t->destroy = code_graph_destroy;
    t->needs_confirm = 0;
    t->data = g;
    return t;
}
