/*
 * tools/filesystem.c - File system tools
 *
 * read_file, write_file, list_dir, edit_file, append_file
 * All use sc_validate_path for workspace restriction.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <errno.h>
#include <strings.h>

#include "constants.h"

#include "tools/filesystem.h"
#include "tools/types.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "logger.h"
#include "cJSON.h"

/* ---------- Common per-tool data ---------- */

typedef struct {
    char *workspace;
    int restrict_to_workspace;
} fs_tool_data_t;

static void fs_data_free(fs_tool_data_t *d)
{
    if (!d) return;
    free(d->workspace);
    free(d);
}

static fs_tool_data_t *fs_data_new(const char *workspace, int restrict_to_ws)
{
    fs_tool_data_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->workspace = sc_strdup(workspace);
    d->restrict_to_workspace = restrict_to_ws;
    return d;
}

static void fs_tool_destroy(sc_tool_t *self)
{
    if (!self) return;
    fs_data_free(self->data);
    free(self);
}

/* Check if path is a symlink (before realpath resolves it).
 * Handles relative paths by prepending workspace. */
static int is_symlink_path(const char *path, const char *workspace)
{
    if (!path) return 0;

    char *expanded = sc_expand_home(path);
    if (!expanded) return 0;

    char *full;
    if (expanded[0] == '/') {
        full = expanded;
    } else {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "%s/%s", workspace, expanded);
        free(expanded);
        full = sc_strbuf_finish(&sb);
    }

    struct stat lsb;
    int is_link = (lstat(full, &lsb) == 0 && S_ISLNK(lsb.st_mode));
    free(full);
    return is_link;
}

/* Check if path targets a bootstrap file (system prompt sources).
 * These files are read-only to prevent LLM self-modification. */
static int is_bootstrap_file(const char *path)
{
    static const char *names[] = {"AGENTS.md", "SOUL.md", "USER.md", "IDENTITY.md", "HEARTBEAT.md"};
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    for (int i = 0; i < 5; i++)
        if (strcmp(base, names[i]) == 0) return 1;
    return 0;
}

/* Check if path ends with a given suffix */
static int str_ends_with(const char *str, const char *suffix)
{
    size_t slen = strlen(str), xlen = strlen(suffix);
    return slen >= xlen && strcmp(str + slen - xlen, suffix) == 0;
}

/* Check if resolved path targets sensitive directories/files.
 * These contain secrets that should never be accessed by the LLM. */
static int is_sensitive_path(const char *resolved)
{
    if (!resolved) return 0;

    /* Sensitive directories */
    if (strstr(resolved, "/.ssh/") || str_ends_with(resolved, "/.ssh"))
        return 1;
    if (strstr(resolved, "/.aws/") || str_ends_with(resolved, "/.aws"))
        return 1;
    if (strstr(resolved, "/.gnupg/") || str_ends_with(resolved, "/.gnupg"))
        return 1;
    if (strstr(resolved, "/.kube/") || str_ends_with(resolved, "/.kube"))
        return 1;
    /* Agent config directory (config, sessions, pairing, audit — but NOT workspace) */
    if (strstr(resolved, "/.smolclaw/") || str_ends_with(resolved, "/.smolclaw")) {
        if (!strstr(resolved, "/.smolclaw/workspace/") &&
            !str_ends_with(resolved, "/.smolclaw/workspace"))
            return 1;
    }

    /* Sensitive dotfiles */
    const char *basename = strrchr(resolved, '/');
    if (basename) basename++;
    else basename = resolved;
    if (strcasecmp(basename, ".env") == 0 ||
        strcasecmp(basename, ".netrc") == 0 ||
        strcasecmp(basename, ".npmrc") == 0 ||
        strcasecmp(basename, ".pypirc") == 0)
        return 1;

    return 0;
}

/* Check if resolved file is on a different device from workspace.
 * Cross-device hardlinks are impossible (POSIX), so different device = suspicious. */
static int is_cross_device(const char *resolved, const char *workspace)
{
    struct stat fs, ws;
    if (stat(resolved, &fs) != 0 || !S_ISREG(fs.st_mode)) return 0;
    if (stat(workspace, &ws) != 0) return 0;
    return fs.st_dev != ws.st_dev;
}

/* Helper: recursively create directories for a file path */
static int mkdirp(const char *filepath)
{
    char *dir = sc_strdup(filepath);
    if (!dir) return -1;

    /* Find the last slash to get the directory portion */
    char *last_slash = strrchr(dir, '/');
    if (!last_slash) { free(dir); return 0; }
    *last_slash = '\0';

    /* Walk forward, creating each component */
    for (char *p = dir + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
                free(dir);
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        free(dir);
        return -1;
    }
    free(dir);
    return 0;
}

/* Open a file with O_NOFOLLOW to prevent symlink TOCTOU races.
 * If the target is a symlink, open() fails with ELOOP. */
static FILE *fs_open_nofollow(const char *path, int flags, const char *mode)
{
    int fd = open(path, flags | O_NOFOLLOW, 0644);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, mode);
    if (!f) { close(fd); return NULL; }
    return f;
}

/* ---------- Shared path validation ---------- */

#define FS_CHECK_BOOTSTRAP  0x01
#define FS_CHECK_SENSITIVE  0x02
#define FS_CHECK_CROSSDEV   0x04
#define FS_CHECKS_READ      (FS_CHECK_SENSITIVE | FS_CHECK_CROSSDEV)
#define FS_CHECKS_WRITE     (FS_CHECK_BOOTSTRAP | FS_CHECK_SENSITIVE | FS_CHECK_CROSSDEV)

/*
 * Validate a file path for access. Returns resolved path on success.
 * On failure, returns NULL and sets *err_msg to a static error string.
 */
static char *fs_validate_path(const fs_tool_data_t *d, const char *path,
                                int checks, const char **err_msg)
{
    if (checks & FS_CHECK_BOOTSTRAP) {
        if (is_bootstrap_file(path)) {
            *err_msg = "access denied: system prompt files are read-only";
            return NULL;
        }
    }

    if (checks & FS_CHECK_SENSITIVE) {
        if (is_sensitive_path(path)) {
            *err_msg = "access denied: sensitive path";
            return NULL;
        }
    }

    if (is_symlink_path(path, d->workspace)) {
        *err_msg = "access denied: path is a symlink";
        return NULL;
    }

    char *resolved = sc_validate_path(path, d->workspace, d->restrict_to_workspace);
    if (!resolved) {
        *err_msg = "access denied: path outside workspace";
        return NULL;
    }

    if ((checks & FS_CHECK_SENSITIVE) && is_sensitive_path(resolved)) {
        free(resolved);
        *err_msg = "access denied: sensitive path";
        return NULL;
    }

    if ((checks & FS_CHECK_CROSSDEV) && is_cross_device(resolved, d->workspace)) {
        free(resolved);
        *err_msg = "access denied: file is on a different device";
        return NULL;
    }

    return resolved;
}

/* ========== read_file ========== */

static cJSON *read_file_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "path", "Path to the file to read", 1);
    return schema;
}

static sc_tool_result_t *read_file_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    fs_tool_data_t *d = self->data;
    const char *path = sc_json_get_string(args, "path", NULL);
    if (!path)
        return sc_tool_result_error("path is required");

    const char *err = NULL;
    char *resolved = fs_validate_path(d, path, FS_CHECKS_READ, &err);
    if (!resolved)
        return sc_tool_result_error(err);

    FILE *f = fs_open_nofollow(resolved, O_RDONLY, "rb");
    if (!f) {
        free(resolved);
        return sc_tool_result_error(errno == ELOOP
            ? "access denied: path is a symlink"
            : "failed to read file");
    }

    /* Verify it's a regular file */
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode)) {
        fclose(f);
        free(resolved);
        return sc_tool_result_error("not a regular file");
    }

    off_t size = st.st_size;
    if (size > SC_MAX_READ_FILE_SIZE) {
        fclose(f);
        free(resolved);
        return sc_tool_result_error("file too large (max 10 MB)");
    }

    char *content = malloc((size_t)size + 1);
    if (!content) {
        fclose(f);
        free(resolved);
        return sc_tool_result_error("out of memory");
    }

    size_t nread = fread(content, 1, (size_t)size, f);
    content[nread] = '\0';
    fclose(f);
    free(resolved);

    sc_tool_result_t *result = sc_tool_result_new(content);
    free(content);
    return result;
}

sc_tool_t *sc_tool_read_file_new(const char *workspace, int restrict_to_ws)
{
    return sc_tool_new_simple("read_file", "Read the contents of a file",
        read_file_parameters, read_file_execute, fs_tool_destroy, 0,
        fs_data_new(workspace, restrict_to_ws));
}

/* ========== write_file ========== */

static cJSON *write_file_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "path", "Path to the file to write", 1);
    sc_schema_add_string(schema, "content", "Content to write to the file", 1);
    return schema;
}

static sc_tool_result_t *write_file_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    fs_tool_data_t *d = self->data;
    const char *path = sc_json_get_string(args, "path", NULL);
    const char *content = sc_json_get_string(args, "content", NULL);

    if (!path)
        return sc_tool_result_error("path is required");
    if (!content)
        return sc_tool_result_error("content is required");

    const char *err = NULL;
    char *resolved = fs_validate_path(d, path, FS_CHECKS_WRITE, &err);
    if (!resolved)
        return sc_tool_result_error(err);

    if (mkdirp(resolved) != 0) {
        free(resolved);
        return sc_tool_result_error("failed to create directory");
    }

    FILE *f = fs_open_nofollow(resolved, O_WRONLY | O_CREAT | O_TRUNC, "wb");
    if (!f) {
        free(resolved);
        return sc_tool_result_error(errno == ELOOP
            ? "access denied: path is a symlink"
            : "failed to open file for writing");
    }

    /* Verify target is a regular file (reject FIFOs, devices, etc.) */
    struct stat wst;
    if (fstat(fileno(f), &wst) == 0 && !S_ISREG(wst.st_mode)) {
        fclose(f);
        free(resolved);
        return sc_tool_result_error("access denied: not a regular file");
    }

    size_t len = strlen(content);
    size_t written = fwrite(content, 1, len, f);
    fclose(f);
    free(resolved);

    if (written != len)
        return sc_tool_result_error("failed to write complete content");

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "File written: %s", path);
    char *msg = sc_strbuf_finish(&sb);
    sc_tool_result_t *result = sc_tool_result_silent(msg);
    free(msg);
    return result;
}

sc_tool_t *sc_tool_write_file_new(const char *workspace, int restrict_to_ws)
{
    return sc_tool_new_simple("write_file", "Write content to a file",
        write_file_parameters, write_file_execute, fs_tool_destroy, 1,
        fs_data_new(workspace, restrict_to_ws));
}

/* ========== list_dir ========== */

static cJSON *list_dir_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "path", "Path to list", 1);
    return schema;
}

static sc_tool_result_t *list_dir_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    fs_tool_data_t *d = self->data;
    const char *path = sc_json_get_string(args, "path", ".");

    if (is_symlink_path(path, d->workspace))
        return sc_tool_result_error("access denied: path is a symlink");

    char *resolved = sc_validate_path(path, d->workspace, d->restrict_to_workspace);
    if (!resolved)
        return sc_tool_result_error("access denied: path outside workspace");

    DIR *dir = opendir(resolved);
    if (!dir) {
        free(resolved);
        return sc_tool_result_error("failed to read directory");
    }

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);

    int entry_count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        /* Limit entries to prevent memory exhaustion */
        if (++entry_count > 10000) {
            sc_strbuf_append(&sb, "... (truncated, >10000 entries)\n");
            break;
        }

        /* Build full path dynamically (avoid PATH_MAX stack overflow) */
        sc_strbuf_t pathbuf;
        sc_strbuf_init(&pathbuf);
        sc_strbuf_appendf(&pathbuf, "%s/%s", resolved, entry->d_name);
        char *fullpath = sc_strbuf_finish(&pathbuf);

        struct stat st;
        if (fullpath && stat(fullpath, &st) == 0 && S_ISDIR(st.st_mode))
            sc_strbuf_appendf(&sb, "DIR:  %s\n", entry->d_name);
        else
            sc_strbuf_appendf(&sb, "FILE: %s\n", entry->d_name);
        free(fullpath);
    }
    closedir(dir);
    free(resolved);

    char *result_str = sc_strbuf_finish(&sb);
    sc_tool_result_t *result = sc_tool_result_new(result_str);
    free(result_str);
    return result;
}

sc_tool_t *sc_tool_list_dir_new(const char *workspace, int restrict_to_ws)
{
    return sc_tool_new_simple("list_dir", "List files and directories in a path",
        list_dir_parameters, list_dir_execute, fs_tool_destroy, 0,
        fs_data_new(workspace, restrict_to_ws));
}

/* ========== edit_file ========== */

static cJSON *edit_file_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "path", "The file path to edit", 1);
    sc_schema_add_string(schema, "old_text",
                         "The exact text to find and replace", 1);
    sc_schema_add_string(schema, "new_text", "The text to replace with", 1);
    return schema;
}

static sc_tool_result_t *edit_file_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    fs_tool_data_t *d = self->data;
    const char *path = sc_json_get_string(args, "path", NULL);
    const char *old_text = sc_json_get_string(args, "old_text", NULL);
    const char *new_text = sc_json_get_string(args, "new_text", NULL);

    if (!path)
        return sc_tool_result_error("path is required");
    if (!old_text)
        return sc_tool_result_error("old_text is required");
    if (!new_text)
        return sc_tool_result_error("new_text is required");

    const char *err = NULL;
    char *resolved = fs_validate_path(d, path, FS_CHECKS_WRITE, &err);
    if (!resolved)
        return sc_tool_result_error(err);

    /* Read file */
    FILE *f = fs_open_nofollow(resolved, O_RDONLY, "rb");
    if (!f) {
        free(resolved);
        return sc_tool_result_error(errno == ELOOP
            ? "access denied: path is a symlink"
            : "file not found");
    }

    struct stat est;
    if (fstat(fileno(f), &est) != 0) {
        fclose(f);
        free(resolved);
        return sc_tool_result_error("failed to stat file");
    }
    off_t size = est.st_size;

    char *content = malloc((size_t)size + 1);
    if (!content) {
        fclose(f);
        free(resolved);
        return sc_tool_result_error("out of memory");
    }

    size_t nread = fread(content, 1, (size_t)size, f);
    content[nread] = '\0';
    fclose(f);

    /* Check old_text exists exactly once */
    char *first = strstr(content, old_text);
    if (!first) {
        free(content);
        free(resolved);
        return sc_tool_result_error("old_text not found in file. Make sure it matches exactly");
    }

    /* Check if old_text appears more than once */
    char *second = strstr(first + strlen(old_text), old_text);
    if (second) {
        free(content);
        free(resolved);
        return sc_tool_result_error("old_text appears multiple times. Please provide more context to make it unique");
    }

    /* Build new content */
    size_t old_len = strlen(old_text);
    size_t new_len = strlen(new_text);
    size_t prefix_len = (size_t)(first - content);
    size_t suffix_len = nread - prefix_len - old_len;
    size_t result_len = prefix_len + new_len + suffix_len;

    char *new_content = malloc(result_len + 1);
    if (!new_content) {
        free(content);
        free(resolved);
        return sc_tool_result_error("out of memory");
    }

    memcpy(new_content, content, prefix_len);
    memcpy(new_content + prefix_len, new_text, new_len);
    memcpy(new_content + prefix_len + new_len, first + old_len, suffix_len);
    new_content[result_len] = '\0';

    free(content);

    /* Write back */
    f = fs_open_nofollow(resolved, O_WRONLY | O_CREAT | O_TRUNC, "wb");
    if (!f) {
        free(new_content);
        free(resolved);
        return sc_tool_result_error("failed to open file for writing");
    }

    fwrite(new_content, 1, result_len, f);
    fclose(f);
    free(new_content);
    free(resolved);

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "File edited: %s", path);
    char *msg = sc_strbuf_finish(&sb);
    sc_tool_result_t *result = sc_tool_result_silent(msg);
    free(msg);
    return result;
}

sc_tool_t *sc_tool_edit_file_new(const char *workspace, int restrict_to_ws)
{
    return sc_tool_new_simple("edit_file",
        "Edit a file by replacing old_text with new_text. The old_text must exist exactly in the file.",
        edit_file_parameters, edit_file_execute, fs_tool_destroy, 1,
        fs_data_new(workspace, restrict_to_ws));
}

/* ========== append_file ========== */

static cJSON *append_file_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    sc_schema_add_string(schema, "path", "The file path to append to", 1);
    sc_schema_add_string(schema, "content", "The content to append", 1);
    return schema;
}

static sc_tool_result_t *append_file_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    fs_tool_data_t *d = self->data;
    const char *path = sc_json_get_string(args, "path", NULL);
    const char *content = sc_json_get_string(args, "content", NULL);

    if (!path)
        return sc_tool_result_error("path is required");
    if (!content)
        return sc_tool_result_error("content is required");

    const char *err = NULL;
    char *resolved = fs_validate_path(d, path, FS_CHECKS_WRITE, &err);
    if (!resolved)
        return sc_tool_result_error(err);

    FILE *f = fs_open_nofollow(resolved, O_WRONLY | O_APPEND | O_CREAT, "a");
    if (!f) {
        free(resolved);
        return sc_tool_result_error(errno == ELOOP
            ? "access denied: path is a symlink"
            : "failed to open file for appending");
    }

    /* Verify target is a regular file (reject FIFOs, devices, etc.) */
    struct stat ast;
    if (fstat(fileno(f), &ast) == 0 && !S_ISREG(ast.st_mode)) {
        fclose(f);
        free(resolved);
        return sc_tool_result_error("access denied: not a regular file");
    }

    size_t len = strlen(content);
    size_t written = fwrite(content, 1, len, f);
    fclose(f);
    free(resolved);

    if (written != len)
        return sc_tool_result_error("failed to append complete content");

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "Appended to %s", path);
    char *msg = sc_strbuf_finish(&sb);
    sc_tool_result_t *result = sc_tool_result_silent(msg);
    free(msg);
    return result;
}

sc_tool_t *sc_tool_append_file_new(const char *workspace, int restrict_to_ws)
{
    return sc_tool_new_simple("append_file", "Append content to the end of a file",
        append_file_parameters, append_file_execute, fs_tool_destroy, 1,
        fs_data_new(workspace, restrict_to_ws));
}
