/*
 * updater/updater.c — Self-update core logic
 *
 * Semver parsing, manifest parsing, SHA-256 verification,
 * atomic binary replacement with backup/rollback.
 */

#include "updater/updater.h"
#include "constants.h"
#include "logger.h"
#include "util/str.h"

#include <cJSON.h>
#include <openssl/evp.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#define LOG_TAG "updater"

/* ELF magic bytes */
static const unsigned char ELF_MAGIC[4] = { 0x7f, 'E', 'L', 'F' };

/* Resolved path to current binary (cached) */
static char g_binary_path[4096];
static int  g_binary_path_resolved;

/* ===== Free functions ===== */

void sc_update_manifest_free(sc_update_manifest_t *m)
{
    if (!m) return;
    free(m->latest);
    free(m->changelog);
    free(m->artifact.arch);
    free(m->artifact.url);
    free(m->artifact.sha256);
    free(m);
}

void sc_fetch_result_free(sc_fetch_result_t *r)
{
    if (!r) return;
    free(r->path);
    free(r->error);
    free(r);
}

/* ===== Semver ===== */

int sc_semver_parse(const char *str, sc_semver_t *out)
{
    if (!str || !out) return -1;

    int major = 0, minor = 0, patch = 0;
    char extra = '\0';

    int n = sscanf(str, "%d.%d.%d%c", &major, &minor, &patch, &extra);
    if (n < 3) return -1;
    /* Reject trailing garbage like "1.2.3x" (but allow "1.2.3" or "1.2.3+build") */
    if (n == 4 && extra != '+' && extra != '-') return -1;
    if (major < 0 || minor < 0 || patch < 0) return -1;

    out->major = major;
    out->minor = minor;
    out->patch = patch;
    return 0;
}

int sc_semver_compare(const sc_semver_t *a, const sc_semver_t *b)
{
    if (a->major != b->major) return a->major - b->major;
    if (a->minor != b->minor) return a->minor - b->minor;
    return a->patch - b->patch;
}

/* ===== Architecture detection ===== */

const char *sc_updater_get_arch(void)
{
    static char arch[sizeof(((struct utsname *)0)->machine)];
    if (arch[0]) return arch;

    struct utsname un;
    if (uname(&un) != 0) return "unknown";

    memcpy(arch, un.machine, sizeof(arch));
    arch[sizeof(arch) - 1] = '\0';
    return arch;
}

/* ===== Manifest parsing ===== */

sc_update_manifest_t *sc_updater_parse_manifest(const char *json,
                                                 const char *arch)
{
    if (!json || !arch) return NULL;

    cJSON *root = cJSON_Parse(json);
    if (!root) {
        SC_LOG_ERROR(LOG_TAG, "Failed to parse manifest JSON");
        return NULL;
    }

    /* Get latest version */
    const cJSON *latest = cJSON_GetObjectItemCaseSensitive(root, "latest");
    if (!cJSON_IsString(latest) || !latest->valuestring[0]) {
        SC_LOG_ERROR(LOG_TAG, "Manifest missing 'latest' field");
        cJSON_Delete(root);
        return NULL;
    }

    sc_semver_t latest_ver;
    if (sc_semver_parse(latest->valuestring, &latest_ver) != 0) {
        SC_LOG_ERROR(LOG_TAG, "Invalid latest version: %s", latest->valuestring);
        cJSON_Delete(root);
        return NULL;
    }

    /* Navigate to releases -> <version> */
    const cJSON *releases = cJSON_GetObjectItemCaseSensitive(root, "releases");
    if (!cJSON_IsObject(releases)) {
        SC_LOG_ERROR(LOG_TAG, "Manifest missing 'releases' object");
        cJSON_Delete(root);
        return NULL;
    }

    const cJSON *release = cJSON_GetObjectItemCaseSensitive(releases,
                                                             latest->valuestring);
    if (!cJSON_IsObject(release)) {
        SC_LOG_ERROR(LOG_TAG, "No release entry for %s", latest->valuestring);
        cJSON_Delete(root);
        return NULL;
    }

    /* Changelog (optional) */
    const cJSON *changelog = cJSON_GetObjectItemCaseSensitive(release, "changelog");

    /* Navigate to artifacts -> <arch> */
    const cJSON *artifacts = cJSON_GetObjectItemCaseSensitive(release, "artifacts");
    if (!cJSON_IsObject(artifacts)) {
        SC_LOG_ERROR(LOG_TAG, "Release %s missing 'artifacts'", latest->valuestring);
        cJSON_Delete(root);
        return NULL;
    }

    const cJSON *art = cJSON_GetObjectItemCaseSensitive(artifacts, arch);
    if (!cJSON_IsObject(art)) {
        SC_LOG_ERROR(LOG_TAG, "No artifact for arch '%s'", arch);
        cJSON_Delete(root);
        return NULL;
    }

    /* Extract artifact fields */
    const cJSON *url = cJSON_GetObjectItemCaseSensitive(art, "url");
    const cJSON *sha256 = cJSON_GetObjectItemCaseSensitive(art, "sha256");
    const cJSON *size = cJSON_GetObjectItemCaseSensitive(art, "size");

    if (!cJSON_IsString(url) || !url->valuestring[0]) {
        SC_LOG_ERROR(LOG_TAG, "Artifact missing 'url'");
        cJSON_Delete(root);
        return NULL;
    }
    if (!cJSON_IsString(sha256) || !sha256->valuestring[0]) {
        SC_LOG_ERROR(LOG_TAG, "Artifact missing 'sha256'");
        cJSON_Delete(root);
        return NULL;
    }

    /* Build manifest result */
    sc_update_manifest_t *m = calloc(1, sizeof(*m));
    if (!m) { cJSON_Delete(root); return NULL; }

    m->latest = sc_strdup(latest->valuestring);
    m->latest_ver = latest_ver;
    m->changelog = (cJSON_IsString(changelog) && changelog->valuestring[0])
                       ? sc_strdup(changelog->valuestring) : NULL;

    m->artifact.arch = sc_strdup(arch);
    m->artifact.url = sc_strdup(url->valuestring);
    m->artifact.sha256 = sc_strdup(sha256->valuestring);
    m->artifact.size = cJSON_IsNumber(size) ? (size_t)size->valuedouble : 0;

    cJSON_Delete(root);
    return m;
}

/* ===== Binary path resolution ===== */

static const char *resolve_binary_path(void)
{
    if (g_binary_path_resolved) return g_binary_path;

    ssize_t len = readlink("/proc/self/exe", g_binary_path,
                           sizeof(g_binary_path) - 1);
    if (len <= 0) {
        SC_LOG_ERROR(LOG_TAG, "Could not resolve /proc/self/exe: %s",
                     strerror(errno));
        return NULL;
    }
    g_binary_path[len] = '\0';
    g_binary_path_resolved = 1;
    return g_binary_path;
}

/* ===== SHA-256 verification ===== */

int sc_updater_verify(const char *path, const sc_update_artifact_t *artifact)
{
    if (!path || !artifact || !artifact->sha256) return -1;

    /* Expected hash must be 64 hex chars */
    if (strlen(artifact->sha256) != 64) {
        SC_LOG_ERROR(LOG_TAG, "Invalid SHA-256 hash length");
        return -1;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        SC_LOG_ERROR(LOG_TAG, "Cannot open %s: %s", path, strerror(errno));
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return -1; }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(f);
        return -1;
    }

    unsigned char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(f);
            return -1;
        }
    }
    fclose(f);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    /* Convert to hex string */
    char hex[65];
    for (unsigned int i = 0; i < hash_len && i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", hash[i]);
    hex[64] = '\0';

    if (strcmp(hex, artifact->sha256) != 0) {
        SC_LOG_ERROR(LOG_TAG, "SHA-256 mismatch: expected %s, got %s",
                     artifact->sha256, hex);
        return -1;
    }

    SC_LOG_INFO(LOG_TAG, "SHA-256 verified: %s", hex);
    return 0;
}

/* ===== Atomic apply ===== */

/* fsync a directory to ensure rename durability */
static void fsync_dir(const char *path)
{
    /* Find parent directory */
    char *dir = sc_strdup(path);
    if (!dir) return;

    char *slash = strrchr(dir, '/');
    if (slash) *slash = '\0';
    else { free(dir); return; }

    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    free(dir);
    if (fd < 0) return;

    fsync(fd);
    close(fd);
}

int sc_updater_apply(const char *new_path)
{
    if (!new_path) return -1;

    const char *bin = resolve_binary_path();
    if (!bin) return -1;

    /* Verify new file has ELF magic */
    FILE *f = fopen(new_path, "rb");
    if (!f) {
        SC_LOG_ERROR(LOG_TAG, "Cannot open new binary: %s", strerror(errno));
        return -1;
    }

    unsigned char magic[4];
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, ELF_MAGIC, 4) != 0) {
        SC_LOG_ERROR(LOG_TAG, "New binary is not a valid ELF file");
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Create backup path */
    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s.bak", bin);
    char *backup_path = sc_strbuf_finish(&sb);
    if (!backup_path) return -1;

    /* Remove old backup if exists */
    unlink(backup_path);

    /* Hard-link current binary to .bak */
    if (link(bin, backup_path) != 0) {
        SC_LOG_ERROR(LOG_TAG, "Failed to create backup: %s", strerror(errno));
        free(backup_path);
        return -1;
    }

    /* Copy permissions from original binary */
    struct stat st;
    if (stat(bin, &st) == 0) {
        chmod(new_path, st.st_mode);
    }

    /* Atomic rename: new binary → current binary path */
    if (rename(new_path, bin) != 0) {
        SC_LOG_ERROR(LOG_TAG, "Failed to replace binary: %s", strerror(errno));
        /* Attempt rollback */
        rename(backup_path, bin);
        free(backup_path);
        return -1;
    }

    fsync_dir(bin);
    free(backup_path);

    SC_LOG_INFO(LOG_TAG, "Binary updated successfully at %s", bin);
    return 0;
}

/* ===== Rollback ===== */

int sc_updater_rollback(void)
{
    const char *bin = resolve_binary_path();
    if (!bin) return -1;

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_appendf(&sb, "%s.bak", bin);
    char *backup_path = sc_strbuf_finish(&sb);
    if (!backup_path) return -1;

    struct stat st;
    if (stat(backup_path, &st) != 0) {
        SC_LOG_ERROR(LOG_TAG, "No backup found at %s", backup_path);
        free(backup_path);
        return -1;
    }

    if (rename(backup_path, bin) != 0) {
        SC_LOG_ERROR(LOG_TAG, "Rollback failed: %s", strerror(errno));
        free(backup_path);
        return -1;
    }

    fsync_dir(bin);
    free(backup_path);

    SC_LOG_INFO(LOG_TAG, "Rolled back to previous binary");
    return 0;
}

/* ===== Updater lifecycle ===== */

sc_updater_t *sc_updater_new(sc_update_transport_t *transport)
{
    if (!transport) return NULL;

    sc_updater_t *u = calloc(1, sizeof(*u));
    if (!u) return NULL;

    u->transport = transport;

    const char *bin = resolve_binary_path();
    u->binary_path = bin ? sc_strdup(bin) : NULL;

    return u;
}

void sc_updater_free(sc_updater_t *u)
{
    if (!u) return;
    if (u->transport && u->transport->destroy)
        u->transport->destroy(u->transport);
    free(u->binary_path);
    free(u);
}

/* ===== Check for update ===== */

sc_update_manifest_t *sc_updater_check(sc_updater_t *u)
{
    if (!u || !u->transport || !u->transport->fetch_manifest) return NULL;

    sc_update_manifest_t *m = u->transport->fetch_manifest(u->transport);
    if (!m) {
        SC_LOG_ERROR(LOG_TAG, "Failed to fetch update manifest");
        return NULL;
    }

    /* Compare with current version */
    sc_semver_t current;
    if (sc_semver_parse(SC_VERSION, &current) != 0) {
        SC_LOG_ERROR(LOG_TAG, "Cannot parse current version: %s", SC_VERSION);
        sc_update_manifest_free(m);
        return NULL;
    }

    if (sc_semver_compare(&m->latest_ver, &current) <= 0) {
        SC_LOG_INFO(LOG_TAG, "Already up to date (%s)", SC_VERSION);
        sc_update_manifest_free(m);
        return NULL;
    }

    SC_LOG_INFO(LOG_TAG, "Update available: %s -> %s", SC_VERSION, m->latest);
    return m;
}

/* ===== Download and verify ===== */

sc_fetch_result_t *sc_updater_download(sc_updater_t *u,
                                        const sc_update_manifest_t *manifest)
{
    if (!u || !manifest || !u->transport || !u->transport->fetch_binary)
        return NULL;

    sc_fetch_result_t *r = u->transport->fetch_binary(u->transport,
                                                       &manifest->artifact);
    if (!r || !r->success) {
        SC_LOG_ERROR(LOG_TAG, "Failed to download update binary: %s",
                     r ? r->error : "unknown error");
        return r;
    }

    /* Verify SHA-256 */
    if (sc_updater_verify(r->path, &manifest->artifact) != 0) {
        SC_LOG_ERROR(LOG_TAG, "SHA-256 verification failed");
        unlink(r->path);
        free(r->error);
        r->error = sc_strdup("SHA-256 verification failed");
        r->success = 0;
        return r;
    }

    /* Check size limit */
    if (r->size > SC_UPDATE_MAX_BINARY_SIZE) {
        SC_LOG_ERROR(LOG_TAG, "Binary too large: %zu > %d",
                     r->size, SC_UPDATE_MAX_BINARY_SIZE);
        unlink(r->path);
        free(r->error);
        r->error = sc_strdup("Binary exceeds size limit");
        r->success = 0;
        return r;
    }

    SC_LOG_INFO(LOG_TAG, "Downloaded and verified: %s (%zu bytes)",
                r->path, r->size);
    return r;
}
