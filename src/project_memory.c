/*
 * project_memory.c — per-workspace code index + repo_search (task 4.5)
 *
 * Walks the workspace, extracts lightweight terms/symbols/imports per source
 * file, and stores a JSON index under {SMOLCLAW_HOME}/indexes/<hash>.json (Q2:
 * never inside the user's repo). repo_search ranks files against a query.
 *
 * Q7: v1 ships its own extraction; the shared sc_symbols helper with code_graph
 * is a v2 follow-up.  TODO(shared-symbols)
 */

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "project_memory.h"
#include "util/sha256.h"
#include "util/str.h"
#include "logger.h"
#include "cJSON.h"

#define PM_MAX_FILE_BYTES   (512 * 1024)   /* skip files larger than this */
#define PM_MAX_FILES        20000          /* sanity cap on index size */
#define PM_MAX_TERMS_FILE   400            /* per-file term cap */

/* ====================================================================== *
 *  Pure helpers
 * ====================================================================== */

char *sc_pm_workspace_hash(const char *abspath)
{
    if (!abspath || !abspath[0]) return NULL;
    uint8_t digest[32];
    sc_sha256_ctx_t ctx;
    sc_sha256_init(&ctx);
    sc_sha256_update(&ctx, (const uint8_t *)abspath, strlen(abspath));
    sc_sha256_final(&ctx, digest);

    char *out = malloc(17);
    if (!out) return NULL;
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {       /* 8 bytes -> 16 hex */
        out[i * 2]     = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0xf];
    }
    out[16] = '\0';
    return out;
}

const char *sc_pm_language_for(const char *path)
{
    if (!path) return NULL;
    const char *dot = strrchr(path, '.');
    if (!dot || !dot[1]) return NULL;
    const char *ext = dot + 1;

    struct { const char *ext; const char *lang; } map[] = {
        {"c","c"}, {"h","c"}, {"cc","cpp"}, {"cpp","cpp"}, {"cxx","cpp"},
        {"hpp","cpp"}, {"hh","cpp"},
        {"py","python"}, {"js","javascript"}, {"mjs","javascript"},
        {"ts","typescript"}, {"tsx","typescript"}, {"jsx","javascript"},
        {"go","go"}, {"rs","rust"}, {"java","java"}, {"rb","ruby"},
        {"sh","shell"}, {"bash","shell"}, {"lua","lua"}, {"php","php"},
        {"md","markdown"}, {"json","json"}, {"yaml","yaml"}, {"yml","yaml"},
        {"toml","toml"}, {"sql","sql"}, {"cmake","cmake"},
        {NULL,NULL}
    };
    for (int i = 0; map[i].ext; i++)
        if (strcmp(ext, map[i].ext) == 0) return map[i].lang;
    return NULL;
}

/* Append a lowercased token (>= 3 chars) to a growing, de-duplicated set. */
static void term_set_add(char ***terms, int *count, int *cap, const char *tok)
{
    if (!tok || strlen(tok) < 3) return;
    for (int i = 0; i < *count; i++)
        if (strcmp((*terms)[i], tok) == 0) return;   /* dedup */
    if (*count >= *cap) {
        int ncap = *cap ? *cap * 2 : 16;
        char **na = realloc(*terms, (size_t)ncap * sizeof(char *));
        if (!na) return;
        *terms = na; *cap = ncap;
    }
    (*terms)[(*count)++] = sc_strdup(tok);
}

char **sc_pm_tokenize(const char *text, int *count)
{
    if (count) *count = 0;
    if (!text) return NULL;

    char **terms = NULL;
    int n = 0, cap = 0;
    char tok[128];
    size_t tl = 0;

    for (const char *p = text; ; p++) {
        unsigned char c = (unsigned char)*p;
        int is_word = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '_';
        if (is_word) {
            if (tl < sizeof(tok) - 1)
                tok[tl++] = (char)tolower(c);
        } else {
            if (tl > 0) {
                tok[tl] = '\0';
                term_set_add(&terms, &n, &cap, tok);
                tl = 0;
                if (n >= PM_MAX_TERMS_FILE) break;
            }
            if (!*p) break;
        }
        if (!*p) break;
    }

    if (n == 0) { free(terms); return NULL; }
    if (count) *count = n;
    return terms;
}

void sc_pm_free_terms(char **terms, int count)
{
    if (!terms) return;
    for (int i = 0; i < count; i++) free(terms[i]);
    free(terms);
}

int sc_pm_match_score(const char *doc_blob, const char *query)
{
    if (!doc_blob || !query) return 0;
    int qn = 0;
    char **qterms = sc_pm_tokenize(query, &qn);
    if (!qterms) return 0;

    int dn = 0;
    char **dterms = sc_pm_tokenize(doc_blob, &dn);

    int score = 0;
    for (int i = 0; i < qn; i++) {
        for (int j = 0; j < dn; j++) {
            if (strcmp(qterms[i], dterms[j]) == 0) { score++; break; }
        }
    }
    sc_pm_free_terms(qterms, qn);
    sc_pm_free_terms(dterms, dn);
    return score;
}

/* ====================================================================== *
 *  Index path
 * ====================================================================== */

char *sc_pm_index_path(const char *workspace)
{
    if (!workspace) return NULL;
    char *abs = realpath(workspace, NULL);
    char *hash = sc_pm_workspace_hash(abs ? abs : workspace);
    free(abs);
    if (!hash) return NULL;

    char *home = sc_get_home_dir();
    if (!home) { free(hash); return NULL; }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s/indexes/%s.json", home, hash);
    free(home);
    free(hash);
    return sc_strbuf_finish(&sb);
}

/* ====================================================================== *
 *  Extraction
 * ====================================================================== */

/* Directory names to never descend into. */
static int dir_ignored(const char *name)
{
    static const char *skip[] = {
        ".git", ".hg", ".svn", "node_modules", "build", "build-size",
        "dist", "target", ".venv", "venv", "__pycache__", "deps",
        ".cache", ".idea", ".vscode", NULL
    };
    for (int i = 0; skip[i]; i++)
        if (strcmp(name, skip[i]) == 0) return 1;
    return 0;
}

static char *read_file_capped(const char *path, long *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > PM_MAX_FILE_BYTES) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[got] = '\0';
    if (out_size) *out_size = (long)got;
    /* Skip binary files (NUL in first 8 KB). */
    size_t scan = got < 8192 ? got : 8192;
    if (memchr(buf, '\0', scan)) { free(buf); return NULL; }
    return buf;
}

/* Add a JSON string array of de-duplicated tokens from `text` (filtered by an
 * optional prefix predicate via simple line scanning for symbols/imports). */
static cJSON *terms_array(const char *text)
{
    int n = 0;
    char **terms = sc_pm_tokenize(text, &n);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++)
        cJSON_AddItemToArray(arr, cJSON_CreateString(terms[i]));
    sc_pm_free_terms(terms, n);
    return arr;
}

/* Lightweight symbol + import extraction by line scanning. Appends to two
 * arrays. TODO(shared-symbols): replace with the shared sc_symbols helper in
 * v2 (code_graph parity). */
static void extract_symbols_imports(const char *text, const char *lang,
                                    cJSON *symbols, cJSON *imports)
{
    char line[1024];
    const char *p = text;
    while (*p) {
        size_t l = 0;
        while (p[l] && p[l] != '\n' && l < sizeof(line) - 1) l++;
        memcpy(line, p, l);
        line[l] = '\0';
        p += l;
        if (*p == '\n') p++;

        const char *s = line;
        while (*s == ' ' || *s == '\t') s++;

        /* imports */
        if (strncmp(s, "#include", 8) == 0 ||
            strncmp(s, "import ", 7) == 0 ||
            strncmp(s, "from ", 5) == 0 ||
            strncmp(s, "require(", 8) == 0 ||
            strncmp(s, "use ", 4) == 0) {
            char *snippet = sc_truncate(s, 120);
            if (snippet) { cJSON_AddItemToArray(imports, cJSON_CreateString(snippet)); free(snippet); }
            continue;
        }

        /* symbols: language-specific leading keywords */
        const char *kw = NULL;
        if (lang && (strcmp(lang, "python") == 0)) {
            if (strncmp(s, "def ", 4) == 0) kw = s + 4;
            else if (strncmp(s, "class ", 6) == 0) kw = s + 6;
        } else if (lang && (strcmp(lang, "go") == 0)) {
            if (strncmp(s, "func ", 5) == 0) kw = s + 5;
        } else if (lang && (strcmp(lang, "rust") == 0)) {
            if (strncmp(s, "fn ", 3) == 0) kw = s + 3;
            else if (strncmp(s, "pub fn ", 7) == 0) kw = s + 7;
        } else {
            /* C-ish: a line like "type name(" at column 0 (no leading ws). */
            if (s == line && strchr(s, '(') && !strchr(s, ';') &&
                !strchr(s, '=') && (isalpha((unsigned char)s[0]) || s[0] == '_'))
                kw = s;
        }
        if (kw) {
            /* Take the identifier just before '(' (functions), else the first
             * token (def/class without parens). */
            char name[128]; size_t ni = 0;
            const char *paren = strchr(kw, '(');
            if (paren) {
                const char *e = paren;
                while (e > kw && (e[-1] == ' ' || e[-1] == '\t')) e--;
                const char *b = e;
                while (b > kw) {
                    unsigned char c = (unsigned char)b[-1];
                    if ((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_') b--;
                    else break;
                }
                ni = (size_t)(e - b);
                if (ni > 0 && ni < sizeof(name)) { memcpy(name, b, ni); name[ni] = '\0'; }
                else ni = 0;
            } else {
                while (kw[ni] && ni < sizeof(name)-1) {
                    unsigned char c = (unsigned char)kw[ni];
                    if ((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_') { name[ni]=kw[ni]; ni++; }
                    else break;
                }
                name[ni] = '\0';
            }
            if (ni >= 2)
                cJSON_AddItemToArray(symbols, cJSON_CreateString(name));
        }
    }
}

/* Recursively walk `dir` (relative `rel` from workspace root), adding file
 * records to `files`. Returns count added (cumulative via *n). */
static void walk_dir(const char *root, const char *rel, cJSON *files,
                     cJSON *prev_by_path, int *n)
{
    if (*n >= PM_MAX_FILES) return;
    char full[2048];
    snprintf(full, sizeof(full), "%s/%s", root, rel[0] ? rel : ".");

    DIR *d = opendir(full);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && *n < PM_MAX_FILES) {
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' || (e->d_name[1] == '.' && e->d_name[2] == '\0')))
            continue;
        if (dir_ignored(e->d_name)) continue;

        char child_rel[2048];
        if (rel[0]) snprintf(child_rel, sizeof(child_rel), "%s/%s", rel, e->d_name);
        else        snprintf(child_rel, sizeof(child_rel), "%s", e->d_name);

        char child_full[2048];
        snprintf(child_full, sizeof(child_full), "%s/%s", root, child_rel);

        struct stat st;
        /* lstat, not stat: do NOT follow symlinks. Following a symlink to a
         * directory would recurse — a cycle (e.g. `ln -s . x`) becomes
         * infinite recursion / stack overflow — and a symlink out of the
         * workspace would leak external file contents into the index. */
        if (lstat(child_full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            walk_dir(root, child_rel, files, prev_by_path, n);
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;   /* skips symlinks, fifos, … */

        const char *lang = sc_pm_language_for(e->d_name);
        if (!lang) continue;   /* only index recognized source files */

        /* Incremental: reuse a prior record if size+mtime match. */
        if (prev_by_path) {
            cJSON *prev = cJSON_GetObjectItem(prev_by_path, child_rel);
            if (prev) {
                cJSON *psz = cJSON_GetObjectItem(prev, "size");
                cJSON *pmt = cJSON_GetObjectItem(prev, "mtime");
                if (cJSON_IsNumber(psz) && cJSON_IsNumber(pmt) &&
                    (long)psz->valuedouble == (long)st.st_size &&
                    (long)pmt->valuedouble == (long)st.st_mtime) {
                    cJSON_AddItemToArray(files, cJSON_Duplicate(prev, 1));
                    (*n)++;
                    continue;
                }
            }
        }

        long fsize = 0;
        char *text = read_file_capped(child_full, &fsize);
        if (!text) continue;

        char *sha = sc_sha256_file(child_full);

        cJSON *rec = cJSON_CreateObject();
        cJSON_AddStringToObject(rec, "path", child_rel);
        cJSON_AddStringToObject(rec, "lang", lang);
        cJSON_AddNumberToObject(rec, "size", (double)st.st_size);
        cJSON_AddNumberToObject(rec, "mtime", (double)st.st_mtime);
        if (sha) cJSON_AddStringToObject(rec, "sha256", sha);
        cJSON_AddItemToObject(rec, "terms", terms_array(text));
        cJSON *symbols = cJSON_AddArrayToObject(rec, "symbols");
        cJSON *imports = cJSON_AddArrayToObject(rec, "imports");
        extract_symbols_imports(text, lang, symbols, imports);
        cJSON_AddItemToArray(files, rec);
        (*n)++;

        free(sha);
        free(text);
    }
    closedir(d);
}

/* ====================================================================== *
 *  Build / load / search
 * ====================================================================== */

static cJSON *load_index(const char *workspace)
{
    char *path = sc_pm_index_path(workspace);
    if (!path) return NULL;
    FILE *f = fopen(path, "rb");
    free(path);
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 64L * 1024 * 1024) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[got] = '\0';
    cJSON *json = cJSON_Parse(buf);
    free(buf);
    return json;
}

int sc_pm_build(const char *workspace, int incremental)
{
    if (!workspace) return -1;

    /* Build a path->record map from the prior index for incremental reuse. */
    cJSON *prev = incremental ? load_index(workspace) : NULL;
    cJSON *prev_map = NULL;
    if (prev) {
        prev_map = cJSON_CreateObject();
        cJSON *pf = cJSON_GetObjectItem(prev, "files");
        cJSON *it = NULL;
        cJSON_ArrayForEach(it, pf) {
            cJSON *pp = cJSON_GetObjectItem(it, "path");
            if (cJSON_IsString(pp))
                cJSON_AddItemReferenceToObject(prev_map, pp->valuestring, it);
        }
    }

    cJSON *root = cJSON_CreateObject();
    char *abs = realpath(workspace, NULL);
    cJSON_AddStringToObject(root, "workspace", abs ? abs : workspace);
    cJSON_AddNumberToObject(root, "built", (double)time(NULL));
    cJSON *files = cJSON_AddArrayToObject(root, "files");

    int n = 0;
    walk_dir(abs ? abs : workspace, "", files, prev_map, &n);
    free(abs);

    cJSON_Delete(prev_map);
    cJSON_Delete(prev);

    /* Write atomically. */
    char *path = sc_pm_index_path(workspace);
    int rc = -1;
    if (path) {
        /* Ensure {HOME}/indexes/ exists. */
        char *slash = strrchr(path, '/');
        if (slash) { *slash = '\0'; mkdir(path, 0700); *slash = '/'; }

        char *str = cJSON_PrintUnformatted(root);
        if (str) {
            sc_strbuf_t tb; sc_strbuf_init(&tb);
            sc_strbuf_appendf(&tb, "%s.tmp", path);
            char *tmp = sc_strbuf_finish(&tb);
            FILE *f = tmp ? fopen(tmp, "wb") : NULL;
            if (f) {
                fwrite(str, 1, strlen(str), f);
                fclose(f);
                if (rename(tmp, path) == 0) rc = n;
            }
            free(tmp);
            free(str);
        }
        free(path);
    }

    cJSON_Delete(root);
    return rc;
}

sc_pm_hit_t *sc_pm_search(const char *workspace, const char *query,
                          int max, int *count)
{
    if (count) *count = 0;
    if (!workspace || !query || !query[0] || max <= 0) return NULL;

    cJSON *root = load_index(workspace);
    if (!root) return NULL;
    cJSON *files = cJSON_GetObjectItem(root, "files");
    if (!cJSON_IsArray(files)) { cJSON_Delete(root); return NULL; }

    /* Score every file. */
    int total = cJSON_GetArraySize(files);
    sc_pm_hit_t *scored = calloc((size_t)(total > 0 ? total : 1), sizeof(*scored));
    int sc_n = 0;
    if (!scored) { cJSON_Delete(root); return NULL; }

    cJSON *rec = NULL;
    cJSON_ArrayForEach(rec, files) {
        /* Build a per-file blob from terms + symbols + imports + path. */
        sc_strbuf_t blob; sc_strbuf_init(&blob);
        cJSON *pp = cJSON_GetObjectItem(rec, "path");
        if (cJSON_IsString(pp)) sc_strbuf_appendf(&blob, "%s ", pp->valuestring);
        const char *fields[] = { "terms", "symbols", "imports" };
        for (int fi = 0; fi < 3; fi++) {
            cJSON *arr = cJSON_GetObjectItem(rec, fields[fi]);
            cJSON *it = NULL;
            cJSON_ArrayForEach(it, arr)
                if (cJSON_IsString(it)) sc_strbuf_appendf(&blob, "%s ", it->valuestring);
        }
        char *blob_str = sc_strbuf_finish(&blob);
        int score = sc_pm_match_score(blob_str, query);
        free(blob_str);

        if (score > 0 && cJSON_IsString(pp)) {
            scored[sc_n].path = sc_strdup(pp->valuestring);
            cJSON *lang = cJSON_GetObjectItem(rec, "lang");
            scored[sc_n].language = sc_strdup(cJSON_IsString(lang) ? lang->valuestring : "");
            scored[sc_n].score = score;
            sc_n++;
        }
    }
    cJSON_Delete(root);

    /* Sort by score desc (insertion sort; result sets are small). */
    for (int i = 1; i < sc_n; i++) {
        sc_pm_hit_t key = scored[i];
        int j = i - 1;
        while (j >= 0 && scored[j].score < key.score) { scored[j+1] = scored[j]; j--; }
        scored[j+1] = key;
    }

    int out_n = sc_n < max ? sc_n : max;
    /* Free the trimmed tail. */
    for (int i = out_n; i < sc_n; i++) { free(scored[i].path); free(scored[i].language); }
    if (out_n == 0) { free(scored); return NULL; }
    if (count) *count = out_n;
    return scored;
}

void sc_pm_hits_free(sc_pm_hit_t *hits, int count)
{
    if (!hits) return;
    for (int i = 0; i < count; i++) { free(hits[i].path); free(hits[i].language); }
    free(hits);
}

char *sc_pm_status(const char *workspace)
{
    cJSON *root = load_index(workspace);
    if (!root) return sc_strdup("Project index not built. Run repo_search build.");

    cJSON *files = cJSON_GetObjectItem(root, "files");
    cJSON *built = cJSON_GetObjectItem(root, "built");
    int nf = cJSON_IsArray(files) ? cJSON_GetArraySize(files) : 0;
    long age = cJSON_IsNumber(built) ? (long)time(NULL) - (long)built->valuedouble : -1;

    sc_strbuf_t sb; sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Project index: %d files", nf);
    if (age >= 0) sc_strbuf_appendf(&sb, ", built %ld min ago", age / 60);
    cJSON_Delete(root);
    return sc_strbuf_finish(&sb);
}
