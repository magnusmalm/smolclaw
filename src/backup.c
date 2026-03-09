/*
 * Backup/restore for smolclaw state directory.
 * Designed for CLI use and remote invocation from smolswarm.
 */

#include "backup.h"
#include "constants.h"
#include "util/str.h"
#include "util/sha256.h"

#include <cJSON.h>

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define BACKUP_DIR     "backups"
#define MANIFEST_FILE  "manifest.json"
#define SC_BACKUP_MAX_KEEP 10

/* ---- helpers ---- */

static char *get_smolclaw_dir(void)
{
    return sc_expand_home("~/.smolclaw");
}

static char *get_backup_root(void)
{
    char *base = get_smolclaw_dir();
    if (!base) return NULL;
    size_t len = strlen(base);
    char *path = malloc(len + 1 + sizeof(BACKUP_DIR));
    if (!path) { free(base); return NULL; }
    sprintf(path, "%s/%s", base, BACKUP_DIR);
    free(base);
    return path;
}

static void make_timestamp(char *buf, size_t bufsz)
{
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(buf, bufsz, "%Y-%m-%dT%H-%M-%SZ", &tm);
}

static int copy_file(const char *src, const char *dst)
{
    /* Reject symlinks */
    struct stat lst;
    if (lstat(src, &lst) != 0 || !S_ISREG(lst.st_mode))
        return -1;

    FILE *in = fopen(src, "rb");
    if (!in) return -1;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }

    char buf[4096];
    size_t n;
    int ok = 0;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { ok = -1; break; }
    }
    fclose(in);
    fclose(out);
    chmod(dst, 0600);
    return ok;
}

static int mkdirp(const char *path, mode_t mode)
{
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, mode);
            *p = '/';
        }
    }
    return mkdir(tmp, mode) == 0 || errno == EEXIST ? 0 : -1;
}

/* Recursively copy a directory, adding file entries to the manifest array.
 * rel_prefix is the path prefix relative to ~/.smolclaw/ for manifest entries. */
static int copy_dir(const char *src, const char *dst,
                    cJSON *files, const char *rel_prefix)
{
    DIR *d = opendir(src);
    if (!d) return -1;
    mkdirp(dst, 0700);

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        /* Skip backups directory */
        if (strcmp(rel_prefix, "") == 0 && strcmp(ent->d_name, BACKUP_DIR) == 0)
            continue;

        char src_path[PATH_MAX], dst_path[PATH_MAX], rel_path[PATH_MAX];
        snprintf(src_path, sizeof(src_path), "%s/%s", src, ent->d_name);
        snprintf(dst_path, sizeof(dst_path), "%s/%s", dst, ent->d_name);
        if (rel_prefix[0])
            snprintf(rel_path, sizeof(rel_path), "%s/%s", rel_prefix, ent->d_name);
        else
            snprintf(rel_path, sizeof(rel_path), "%s", ent->d_name);

        struct stat st;
        if (lstat(src_path, &st) != 0) continue;
        /* Skip symlinks */
        if (S_ISLNK(st.st_mode)) continue;

        if (S_ISDIR(st.st_mode)) {
            copy_dir(src_path, dst_path, files, rel_path);
        } else if (S_ISREG(st.st_mode)) {
            if (copy_file(src_path, dst_path) != 0) continue;
            char *hash = sc_sha256_file(src_path);
            cJSON *entry = cJSON_CreateObject();
            cJSON_AddStringToObject(entry, "path", rel_path);
            cJSON_AddStringToObject(entry, "sha256", hash ? hash : "");
            cJSON_AddNumberToObject(entry, "size", (double)st.st_size);
            cJSON_AddItemToArray(files, entry);
            free(hash);
        }
    }
    closedir(d);
    return 0;
}

/* Add a single file to the backup and manifest */
static int backup_file(const char *base, const char *backup_dir,
                       const char *rel_path, cJSON *files)
{
    char src[PATH_MAX], dst[PATH_MAX];
    snprintf(src, sizeof(src), "%s/%s", base, rel_path);
    snprintf(dst, sizeof(dst), "%s/%s", backup_dir, rel_path);

    struct stat st;
    if (stat(src, &st) != 0) return -1;

    /* Ensure parent directory exists */
    char *slash = strrchr(dst, '/');
    if (slash) {
        *slash = '\0';
        mkdirp(dst, 0700);
        *slash = '/';
    }

    if (copy_file(src, dst) != 0) return -1;

    char *hash = sc_sha256_file(src);
    cJSON *entry = cJSON_CreateObject();
    cJSON_AddStringToObject(entry, "path", rel_path);
    cJSON_AddStringToObject(entry, "sha256", hash ? hash : "");
    cJSON_AddNumberToObject(entry, "size", (double)st.st_size);
    cJSON_AddItemToArray(files, entry);
    free(hash);
    return 0;
}

/* Write manifest.json to the backup directory */
static int write_manifest(const char *backup_dir, const char *name, cJSON *files)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);
    cJSON_AddStringToObject(root, "name", name);

    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
    cJSON_AddStringToObject(root, "created", ts);
    cJSON_AddStringToObject(root, "smolclaw_version", SC_VERSION_FULL);
    cJSON_AddItemReferenceToObject(root, "files", files);

    char *json = cJSON_Print(root);
    cJSON_Delete(root);
    if (!json) return -1;

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", backup_dir, MANIFEST_FILE);
    FILE *f = fopen(path, "w");
    if (!f) { free(json); return -1; }
    fputs(json, f);
    fputc('\n', f);
    fclose(f);
    chmod(path, 0600);
    free(json);
    return 0;
}

/* Load manifest from a backup directory. Caller must cJSON_Delete. */
static cJSON *load_manifest(const char *backup_dir)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", backup_dir, MANIFEST_FILE);

    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0 || len > 1024 * 1024) { fclose(f); return NULL; }

    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)len, f);
    fclose(f);
    buf[n] = '\0';

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    return root;
}

/* Compare by name (reverse chronological — newest first) */
static int cmp_names_desc(const void *a, const void *b)
{
    return strcmp(*(const char **)b, *(const char **)a);
}

/* List backup names in reverse chronological order. Returns count, fills names
 * array (caller frees each entry + array). */
static int list_backups(char ***out_names)
{
    char *root = get_backup_root();
    if (!root) return -1;

    DIR *d = opendir(root);
    free(root);
    if (!d) return 0;

    char **names = NULL;
    int count = 0, cap = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (count >= cap) {
            cap = cap ? cap * 2 : 16;
            char **tmp = realloc(names, (size_t)cap * sizeof(char *));
            if (!tmp) break;
            names = tmp;
        }
        names[count++] = strdup(ent->d_name);
    }
    closedir(d);

    if (count > 1)
        qsort(names, (size_t)count, sizeof(char *), cmp_names_desc);

    *out_names = names;
    return count;
}

/* Recursively remove a directory */
static void rmdir_recursive(const char *path)
{
    DIR *d = opendir(path);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[PATH_MAX];
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        struct stat st;
        if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode))
            rmdir_recursive(child);
        else
            remove(child);
    }
    closedir(d);
    rmdir(path);
}

/* Prune old backups, keeping at most SC_BACKUP_MAX_KEEP */
static void prune_old_backups(void)
{
    char **names = NULL;
    int count = list_backups(&names);
    if (count <= SC_BACKUP_MAX_KEEP) {
        for (int i = 0; i < count; i++) free(names[i]);
        free(names);
        return;
    }

    char *root = get_backup_root();
    if (!root) {
        for (int i = 0; i < count; i++) free(names[i]);
        free(names);
        return;
    }

    /* Remove backups beyond the keep limit (names are newest-first) */
    for (int i = SC_BACKUP_MAX_KEEP; i < count; i++) {
        char dir[PATH_MAX];
        snprintf(dir, sizeof(dir), "%s/%s", root, names[i]);
        rmdir_recursive(dir);
    }
    free(root);
    for (int i = 0; i < count; i++) free(names[i]);
    free(names);
}

/* ---- public API ---- */

char *sc_backup_create(const char *name, int config_only, int include_sessions)
{
    char *base = get_smolclaw_dir();
    char *root = get_backup_root();
    if (!base || !root) { free(base); free(root); return NULL; }

    /* Generate name if not provided */
    char auto_name[32];
    if (!name || !name[0]) {
        make_timestamp(auto_name, sizeof(auto_name));
        name = auto_name;
    }

    char backup_dir[PATH_MAX];
    snprintf(backup_dir, sizeof(backup_dir), "%s/%s", root, name);

    if (mkdirp(backup_dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "backup: cannot create %s: %s\n", backup_dir, strerror(errno));
        free(base); free(root);
        return NULL;
    }

    cJSON *files = cJSON_CreateArray();
    int ok = 1;

    /* Always back up config.json */
    if (backup_file(base, backup_dir, "config.json", files) != 0) {
        fprintf(stderr, "backup: warning: config.json not found or unreadable\n");
    }

    /* Always try vault.db */
    backup_file(base, backup_dir, "vault.db", files);

    if (!config_only) {
        /* Workspace */
        char ws_src[PATH_MAX], ws_dst[PATH_MAX];
        snprintf(ws_src, sizeof(ws_src), "%s/workspace", base);
        snprintf(ws_dst, sizeof(ws_dst), "%s/workspace", backup_dir);
        if (copy_dir(ws_src, ws_dst, files, "workspace") != 0)
            fprintf(stderr, "backup: warning: workspace not found\n");

        /* State */
        char st_src[PATH_MAX], st_dst[PATH_MAX];
        snprintf(st_src, sizeof(st_src), "%s/state", base);
        snprintf(st_dst, sizeof(st_dst), "%s/state", backup_dir);
        copy_dir(st_src, st_dst, files, "state");

        /* Sessions (optional) */
        if (include_sessions) {
            char se_src[PATH_MAX], se_dst[PATH_MAX];
            snprintf(se_src, sizeof(se_src), "%s/sessions", base);
            snprintf(se_dst, sizeof(se_dst), "%s/sessions", backup_dir);
            copy_dir(se_src, se_dst, files, "sessions");
        }
    }

    /* Write manifest */
    if (write_manifest(backup_dir, name, files) != 0) {
        fprintf(stderr, "backup: failed to write manifest\n");
        ok = 0;
    }

    int file_count = cJSON_GetArraySize(files);
    cJSON_Delete(files);
    free(base);
    free(root);

    if (!ok) return NULL;

    fprintf(stderr, "backup: created '%s' (%d files)\n", name, file_count);
    prune_old_backups();
    return strdup(name);
}

int sc_backup_verify(const char *name)
{
    char *root = get_backup_root();
    if (!root) return -1;

    /* If no name given, use latest */
    char *resolved_name = NULL;
    if (!name || !name[0]) {
        char **names = NULL;
        int count = list_backups(&names);
        if (count <= 0) {
            fprintf(stderr, "backup: no backups found\n");
            free(root);
            return -1;
        }
        resolved_name = strdup(names[0]);
        for (int i = 0; i < count; i++) free(names[i]);
        free(names);
        name = resolved_name;
    }

    char backup_dir[PATH_MAX];
    snprintf(backup_dir, sizeof(backup_dir), "%s/%s", root, name);
    free(root);

    cJSON *manifest = load_manifest(backup_dir);
    if (!manifest) {
        fprintf(stderr, "backup: cannot load manifest for '%s'\n", name);
        free(resolved_name);
        return -1;
    }

    cJSON *files = cJSON_GetObjectItem(manifest, "files");
    if (!files) {
        fprintf(stderr, "backup: manifest has no files array\n");
        cJSON_Delete(manifest);
        free(resolved_name);
        return -1;
    }

    int total = cJSON_GetArraySize(files);
    int passed = 0, failed = 0;

    for (int i = 0; i < total; i++) {
        cJSON *entry = cJSON_GetArrayItem(files, i);
        const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "path"));
        const char *expected = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "sha256"));
        if (!path || !expected) { failed++; continue; }

        char fpath[PATH_MAX];
        snprintf(fpath, sizeof(fpath), "%s/%s", backup_dir, path);

        char *actual = sc_sha256_file(fpath);
        if (!actual) {
            fprintf(stderr, "  FAIL  %s (missing)\n", path);
            failed++;
        } else if (strcmp(actual, expected) != 0) {
            fprintf(stderr, "  FAIL  %s (hash mismatch)\n", path);
            failed++;
            free(actual);
        } else {
            passed++;
            free(actual);
        }
    }

    cJSON_Delete(manifest);
    fprintf(stderr, "backup: '%s' — %d/%d files OK", name, passed, total);
    if (failed > 0)
        fprintf(stderr, ", %d FAILED", failed);
    fprintf(stderr, "\n");
    free(resolved_name);
    return failed > 0 ? 1 : 0;
}

int sc_backup_list(void)
{
    char *root = get_backup_root();
    if (!root) return -1;

    char **names = NULL;
    int count = list_backups(&names);

    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        char dir[PATH_MAX];
        snprintf(dir, sizeof(dir), "%s/%s", root, names[i]);
        cJSON *manifest = load_manifest(dir);

        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "name", names[i]);
        if (manifest) {
            const char *created = cJSON_GetStringValue(
                cJSON_GetObjectItem(manifest, "created"));
            const char *ver = cJSON_GetStringValue(
                cJSON_GetObjectItem(manifest, "smolclaw_version"));
            cJSON *files = cJSON_GetObjectItem(manifest, "files");
            if (created)
                cJSON_AddStringToObject(item, "created", created);
            if (ver)
                cJSON_AddStringToObject(item, "smolclaw_version", ver);
            if (files)
                cJSON_AddNumberToObject(item, "files", cJSON_GetArraySize(files));
            cJSON_Delete(manifest);
        }
        cJSON_AddItemToArray(arr, item);
        free(names[i]);
    }
    free(names);
    free(root);

    char *json = cJSON_Print(arr);
    cJSON_Delete(arr);
    if (json) {
        puts(json);
        free(json);
    }
    return count;
}

int sc_backup_restore(const char *name, int dry_run)
{
    if (!name || !name[0]) {
        fprintf(stderr, "backup: restore requires a backup name\n");
        return 1;
    }

    char *base = get_smolclaw_dir();
    char *root = get_backup_root();
    if (!base || !root) { free(base); free(root); return 1; }

    char backup_dir[PATH_MAX];
    snprintf(backup_dir, sizeof(backup_dir), "%s/%s", root, name);
    free(root);

    cJSON *manifest = load_manifest(backup_dir);
    if (!manifest) {
        fprintf(stderr, "backup: cannot load manifest for '%s'\n", name);
        free(base);
        return 1;
    }

    cJSON *files = cJSON_GetObjectItem(manifest, "files");
    if (!files) {
        fprintf(stderr, "backup: manifest has no files array\n");
        cJSON_Delete(manifest);
        free(base);
        return 1;
    }

    int total = cJSON_GetArraySize(files);
    int restored = 0, errors = 0;

    for (int i = 0; i < total; i++) {
        cJSON *entry = cJSON_GetArrayItem(files, i);
        const char *rel_path = cJSON_GetStringValue(
            cJSON_GetObjectItem(entry, "path"));
        if (!rel_path) continue;

        /* Reject path traversal attempts */
        if (rel_path[0] == '/' || strstr(rel_path, "..")) {
            fprintf(stderr, "  skip: %s (unsafe path)\n", rel_path);
            errors++;
            continue;
        }

        char src[PATH_MAX], dst[PATH_MAX];
        snprintf(src, sizeof(src), "%s/%s", backup_dir, rel_path);
        snprintf(dst, sizeof(dst), "%s/%s", base, rel_path);

        if (dry_run) {
            printf("  restore: %s\n", rel_path);
            restored++;
            continue;
        }

        /* Ensure parent directory exists */
        char tmp[PATH_MAX];
        snprintf(tmp, sizeof(tmp), "%s", dst);
        char *slash = strrchr(tmp, '/');
        if (slash) {
            *slash = '\0';
            mkdirp(tmp, 0700);
        }

        if (copy_file(src, dst) == 0) {
            restored++;
        } else {
            fprintf(stderr, "  error: %s\n", rel_path);
            errors++;
        }
    }

    cJSON_Delete(manifest);
    free(base);

    if (dry_run)
        fprintf(stderr, "backup: dry-run — would restore %d files\n", restored);
    else
        fprintf(stderr, "backup: restored %d/%d files from '%s'%s\n",
                restored, total, name, errors ? " (with errors)" : "");

    return errors > 0 ? 1 : 0;
}
