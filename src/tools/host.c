/*
 * tools/host.c - Read-only host introspection and retained host metrics
 *
 * Collects fixed host/process snapshots without using shell commands.
 * Designed for sandbox-friendly diagnostics on deployed hosts.
 */

#include "tools/host.h"
#include "sc_features.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#if SC_ENABLE_HOST_METRICS
#include <sqlite3.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "logger.h"
#if SC_ENABLE_MEMORY_SEARCH
#include "memory_index.h"
#endif
#include "util/sandbox.h"
#if SC_ENABLE_HOST_METRICS
#include "util/db_migrate.h"
#endif
#include "util/json_helpers.h"
#include "util/str.h"

#define HOST_TAG "host"
#define HOST_CTX_DIR "context/host"
#define HOST_INV_JSON "host_inventory.json"
#define HOST_INV_MD   "host_inventory.md"
#define HOST_METRICS_DB "state/host_metrics.db"
#define HOST_SAMPLE_INTERVAL_SEC 300
#define HOST_SAMPLE_RETENTION_DAYS 14
#define HOST_TREND_DEFAULT_HOURS 24
#define HOST_TREND_DEFAULT_MAX_SAMPLES 288
#define HOST_TREND_MAX_HOURS 720
#define HOST_TREND_MAX_SAMPLES 1000

typedef struct {
    long mem_total_kb;
    long mem_available_kb;
    long mem_free_kb;
    long swap_total_kb;
    long swap_free_kb;
} host_meminfo_t;

typedef struct {
    long vmrss_kb;
    long vmsize_kb;
    long threads;
    long fd_count;
} host_procinfo_t;

typedef struct {
    time_t ts;
    double load1;
    double load5;
    double load15;
    long mem_total_kb;
    long mem_available_kb;
    long swap_used_kb;
    long vmrss_kb;
    long vmsize_kb;
    long open_fds;
    long threads;
    long long rootfs_free_bytes;
    double cpu_temp_c;
} host_sample_t;

typedef struct {
    const char *name;
    char *version;
} tracked_pkg_t;

typedef struct {
    char *workspace;
    sc_memory_index_t *idx;  /* Borrowed, not owned */
    int sandbox_enabled;
} host_tool_data_t;

static const char *const tracked_dpkg_packages[] = {
    "libcamera0",
    "libcamera-apps",
    "libcamera-tools",
    "ffmpeg",
    "curl",
    "git",
    "openssl",
    "ca-certificates",
    "sqlite3",
    "libevent-2.1-7",
    "raspberrypi-kernel",
    NULL
};

#if SC_ENABLE_HOST_METRICS
static const char HOST_METRICS_MIGRATION_V1[] =
    "CREATE TABLE IF NOT EXISTS host_samples ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  ts INTEGER NOT NULL,"
    "  load1 REAL,"
    "  load5 REAL,"
    "  load15 REAL,"
    "  mem_total_kb INTEGER,"
    "  mem_available_kb INTEGER,"
    "  swap_used_kb INTEGER,"
    "  vmrss_kb INTEGER,"
    "  vmsize_kb INTEGER,"
    "  open_fds INTEGER,"
    "  threads INTEGER,"
    "  rootfs_free_bytes INTEGER,"
    "  cpu_temp_c REAL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_host_samples_ts ON host_samples(ts);";

static const char *const HOST_METRICS_MIGRATIONS[] = {
    HOST_METRICS_MIGRATION_V1,
};
#endif /* SC_ENABLE_HOST_METRICS */

static char *
read_small_file(const char *path, size_t max_bytes)
{
    if (!path || max_bytes == 0) return NULL;

    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return NULL;

    char *buf = malloc(max_bytes + 1);
    if (!buf) {
        close(fd);
        return NULL;
    }

    ssize_t n = read(fd, buf, max_bytes);
    close(fd);
    if (n < 0) {
        free(buf);
        return NULL;
    }

    buf[n] = '\0';
    return buf;
}

static void
trim_trailing_ws(char *s)
{
    if (!s) return;
    size_t len = strlen(s);
    while (len > 0) {
        char c = s[len - 1];
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t')
            break;
        s[--len] = '\0';
    }
}

static char *
trim_leading_ws(char *s)
{
    if (!s) return NULL;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    return s;
}

static char *
read_first_existing_file(const char *const *paths)
{
    if (!paths) return NULL;
    for (int i = 0; paths[i]; i++) {
        char *data = read_small_file(paths[i], 255);
        if (data && data[0]) {
            trim_trailing_ws(data);
            return data;
        }
        free(data);
    }
    return NULL;
}

static char *
read_os_value(const char *key)
{
    if (!key || !key[0]) return NULL;

    FILE *f = fopen("/etc/os-release", "r");
    if (!f) return NULL;

    char line[512];
    char *result = NULL;
    size_t key_len = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, key_len) != 0 || line[key_len] != '=')
            continue;
        char *v = line + key_len + 1;
        v = trim_leading_ws(v);
        trim_trailing_ws(v);
        size_t len = strlen(v);
        if (len >= 2 &&
            ((v[0] == '"' && v[len - 1] == '"') ||
             (v[0] == '\'' && v[len - 1] == '\''))) {
            v[len - 1] = '\0';
            v++;
        }
        result = sc_strdup(v);
        break;
    }
    fclose(f);
    return result;
}

static char *
read_os_pretty_name(void)
{
    return read_os_value("PRETTY_NAME");
}

static char *
read_cpu_model(void)
{
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return NULL;

    char line[512];
    char *result = NULL;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "model name", 10) == 0 ||
            strncmp(line, "Hardware", 8) == 0 ||
            strncmp(line, "Model", 5) == 0) {
            char *colon = strchr(line, ':');
            if (!colon) continue;
            colon++;
            colon = trim_leading_ws(colon);
            trim_trailing_ws(colon);
            result = sc_strdup(colon);
            break;
        }
    }
    fclose(f);
    return result;
}

static int
read_meminfo(host_meminfo_t *out)
{
    if (!out) return -1;
    memset(out, 0, sizeof(*out));

    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;

    char key[64];
    long val;
    char unit[32];
    while (fscanf(f, "%63[^:]: %ld %31s\n", key, &val, unit) == 3) {
        if (strcmp(key, "MemTotal") == 0)
            out->mem_total_kb = val;
        else if (strcmp(key, "MemAvailable") == 0)
            out->mem_available_kb = val;
        else if (strcmp(key, "MemFree") == 0)
            out->mem_free_kb = val;
        else if (strcmp(key, "SwapTotal") == 0)
            out->swap_total_kb = val;
        else if (strcmp(key, "SwapFree") == 0)
            out->swap_free_kb = val;
    }

    fclose(f);
    return 0;
}

static int
read_loadavg(double *l1, double *l5, double *l15)
{
    if (!l1 || !l5 || !l15) return -1;
    FILE *f = fopen("/proc/loadavg", "r");
    if (!f) return -1;
    int rc = fscanf(f, "%lf %lf %lf", l1, l5, l15) == 3 ? 0 : -1;
    fclose(f);
    return rc;
}

static int
read_uptime(double *uptime_sec)
{
    if (!uptime_sec) return -1;
    FILE *f = fopen("/proc/uptime", "r");
    if (!f) return -1;
    int rc = fscanf(f, "%lf", uptime_sec) == 1 ? 0 : -1;
    fclose(f);
    return rc;
}

static int
count_open_fds(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        count++;
    }
    closedir(d);
    return count;
}

static int
read_self_procinfo(host_procinfo_t *out)
{
    if (!out) return -1;
    memset(out, 0, sizeof(*out));

    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0)
            out->vmrss_kb = strtol(line + 6, NULL, 10);
        else if (strncmp(line, "VmSize:", 7) == 0)
            out->vmsize_kb = strtol(line + 7, NULL, 10);
        else if (strncmp(line, "Threads:", 8) == 0)
            out->threads = strtol(line + 8, NULL, 10);
    }
    fclose(f);

    out->fd_count = count_open_fds();
    return 0;
}

static char *
find_first_camera_device(void)
{
    DIR *d = opendir("/dev");
    if (!d) return NULL;

    struct dirent *ent;
    char *result = NULL;
    while ((ent = readdir(d)) != NULL) {
        if (strncmp(ent->d_name, "video", 5) == 0) {
            result = malloc(strlen("/dev/") + strlen(ent->d_name) + 1);
            if (result)
                sprintf(result, "/dev/%s", ent->d_name);
            break;
        }
    }
    closedir(d);
    return result;
}

static int
path_exists(const char *path)
{
    struct stat st;
    return path && stat(path, &st) == 0;
}

static void
add_number_if_nonneg(cJSON *obj, const char *key, long value)
{
    if (obj && key && value >= 0)
        cJSON_AddNumberToObject(obj, key, value);
}

static int
read_peak_temp_c(double *out_temp_c)
{
    if (!out_temp_c) return -1;
    *out_temp_c = -1.0;

    DIR *d = opendir("/sys/class/thermal");
    if (!d) return -1;

    struct dirent *ent;
    int found = 0;
    double peak = -1.0;
    while ((ent = readdir(d)) != NULL) {
        if (strncmp(ent->d_name, "thermal_zone", 12) != 0)
            continue;

        char temp_path[512];
        snprintf(temp_path, sizeof(temp_path),
                 "/sys/class/thermal/%s/temp", ent->d_name);
        char *temp = read_small_file(temp_path, 63);
        if (!temp)
            continue;

        trim_trailing_ws(temp);
        char *end = NULL;
        long temp_milli = strtol(temp, &end, 10);
        free(temp);
        if (end == temp || (*end != '\0' && *end != '\n'))
            continue;

        double val = (double)temp_milli / 1000.0;
        if (!found || val > peak)
            peak = val;
        found = 1;
    }

    closedir(d);
    if (!found)
        return -1;
    *out_temp_c = peak;
    return 0;
}

static void
add_temp_samples(cJSON *temps)
{
    if (!temps) return;

    DIR *d = opendir("/sys/class/thermal");
    if (!d) return;

    struct dirent *ent;
    int added = 0;
    while ((ent = readdir(d)) != NULL && added < 8) {
        if (strncmp(ent->d_name, "thermal_zone", 12) != 0)
            continue;

        char type_path[512];
        char temp_path[512];
        snprintf(type_path, sizeof(type_path),
                 "/sys/class/thermal/%s/type", ent->d_name);
        snprintf(temp_path, sizeof(temp_path),
                 "/sys/class/thermal/%s/temp", ent->d_name);

        char *type = read_small_file(type_path, 127);
        char *temp = read_small_file(temp_path, 63);
        if (!type || !temp) {
            free(type);
            free(temp);
            continue;
        }

        trim_trailing_ws(type);
        trim_trailing_ws(temp);
        char *end = NULL;
        long temp_milli = strtol(temp, &end, 10);
        if (end == temp || (*end != '\0' && *end != '\n')) {
            free(type);
            free(temp);
            continue;
        }

        cJSON_AddNumberToObject(temps, type, (double)temp_milli / 1000.0);
        added++;
        free(type);
        free(temp);
    }

    closedir(d);
}

static void
fill_identity(cJSON *root)
{
    struct utsname uts;
    memset(&uts, 0, sizeof(uts));
    uname(&uts);

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0)
        hostname[0] = '\0';
    hostname[sizeof(hostname) - 1] = '\0';

    char *os_pretty = read_os_pretty_name();
    char *os_id = read_os_value("ID");
    char *os_ver = read_os_value("VERSION_ID");

    cJSON_AddStringToObject(root, "hostname", hostname[0] ? hostname : "unknown");
    if (uts.sysname[0]) cJSON_AddStringToObject(root, "sysname", uts.sysname);
    if (uts.release[0]) cJSON_AddStringToObject(root, "kernel", uts.release);
    if (uts.machine[0]) cJSON_AddStringToObject(root, "arch", uts.machine);
    if (os_pretty) cJSON_AddStringToObject(root, "os", os_pretty);
    if (os_id) cJSON_AddStringToObject(root, "os_id", os_id);
    if (os_ver) cJSON_AddStringToObject(root, "os_version_id", os_ver);

    free(os_pretty);
    free(os_id);
    free(os_ver);
}

static void
fill_storage(cJSON *root)
{
    struct statvfs vfs;
    if (statvfs("/", &vfs) != 0)
        return;

    cJSON *disk = cJSON_AddObjectToObject(root, "rootfs_bytes");
    unsigned long long total =
        (unsigned long long)vfs.f_frsize * (unsigned long long)vfs.f_blocks;
    unsigned long long freeb =
        (unsigned long long)vfs.f_frsize * (unsigned long long)vfs.f_bavail;
    cJSON_AddNumberToObject(disk, "total", (double)total);
    cJSON_AddNumberToObject(disk, "free", (double)freeb);
    cJSON_AddNumberToObject(disk, "used", (double)(total - freeb));
}

static void
fill_camera(cJSON *root, int include_paths)
{
    char *camera_dev = find_first_camera_device();

    cJSON *camera = cJSON_AddObjectToObject(root, "camera");
    cJSON_AddBoolToObject(camera, "video_device_present", camera_dev != NULL);
    cJSON_AddBoolToObject(camera, "libcamera_still",
                          path_exists("/usr/bin/libcamera-still") ||
                          path_exists("/bin/libcamera-still"));
    cJSON_AddBoolToObject(camera, "libcamera_vid",
                          path_exists("/usr/bin/libcamera-vid") ||
                          path_exists("/bin/libcamera-vid"));
    cJSON_AddBoolToObject(camera, "libcamera_hello",
                          path_exists("/usr/bin/libcamera-hello") ||
                          path_exists("/bin/libcamera-hello"));
    if (include_paths && camera_dev)
        cJSON_AddStringToObject(camera, "first_video_device", camera_dev);

    free(camera_dev);
}

static void
fill_sandbox(cJSON *root, int sandbox_enabled)
{
    int avail = sc_sandbox_available();
    int landlock = (avail & SC_SANDBOX_LANDLOCK) != 0;
    int seccomp = (avail & SC_SANDBOX_SECCOMP) != 0;
    const char *status = "disabled";
    const char *summary =
        "OS-level exec sandbox is disabled in config.";

    if (sandbox_enabled) {
        if (landlock && seccomp) {
            status = "ok";
            summary =
                "Filesystem and syscall sandbox features are available.";
        } else if (!landlock && seccomp) {
            status = "degraded";
            summary =
                "Landlock filesystem sandbox is unavailable; exec children keep syscall filtering only.";
        } else if (landlock && !seccomp) {
            status = "degraded";
            summary =
                "seccomp syscall filtering is unavailable; exec children keep filesystem sandbox only.";
        } else {
            status = "degraded";
            summary =
                "Landlock and seccomp are unavailable; exec children cannot get the expected OS-level sandbox.";
        }
    }

    cJSON *sandbox = cJSON_AddObjectToObject(root, "sandbox");
    cJSON_AddBoolToObject(sandbox, "configured", sandbox_enabled != 0);
    cJSON_AddBoolToObject(sandbox, "landlock_available", landlock);
    cJSON_AddBoolToObject(sandbox, "seccomp_available", seccomp);
    cJSON_AddStringToObject(sandbox, "status", status);
    cJSON_AddStringToObject(sandbox, "summary", summary);
}

static char *
now_timestamp(void)
{
    char nowbuf[64];
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    strftime(nowbuf, sizeof(nowbuf), "%Y-%m-%dT%H:%M:%S%z", &tm_now);
    return sc_strdup(nowbuf);
}

static char *
format_timestamp(time_t ts)
{
    char buf[64];
    struct tm tmv;
    localtime_r(&ts, &tmv);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S%z", &tmv);
    return sc_strdup(buf);
}

static cJSON *
build_host_status_json(int include_paths, int sandbox_enabled)
{
    host_meminfo_t meminfo;
    host_procinfo_t procinfo;
    double load1 = 0.0, load5 = 0.0, load15 = 0.0;
    double uptime_sec = 0.0;
    char *cpu_model = read_cpu_model();
    char *board_model = read_first_existing_file((const char *const[]){
        "/sys/firmware/devicetree/base/model",
        "/sys/devices/virtual/dmi/id/product_name",
        NULL
    });
    char *sampled_at = now_timestamp();

    read_meminfo(&meminfo);
    read_self_procinfo(&procinfo);
    read_loadavg(&load1, &load5, &load15);
    read_uptime(&uptime_sec);

    cJSON *root = cJSON_CreateObject();
    fill_identity(root);
    fill_sandbox(root, sandbox_enabled);
    if (board_model) cJSON_AddStringToObject(root, "board_model", board_model);
    if (cpu_model) cJSON_AddStringToObject(root, "cpu_model", cpu_model);
    cJSON_AddNumberToObject(root, "uptime_sec", uptime_sec);

    cJSON *load = cJSON_AddObjectToObject(root, "loadavg");
    cJSON_AddNumberToObject(load, "1m", load1);
    cJSON_AddNumberToObject(load, "5m", load5);
    cJSON_AddNumberToObject(load, "15m", load15);

    cJSON *memory = cJSON_AddObjectToObject(root, "memory_kb");
    add_number_if_nonneg(memory, "total", meminfo.mem_total_kb);
    add_number_if_nonneg(memory, "available", meminfo.mem_available_kb);
    add_number_if_nonneg(memory, "free", meminfo.mem_free_kb);
    add_number_if_nonneg(memory, "swap_total", meminfo.swap_total_kb);
    add_number_if_nonneg(memory, "swap_free", meminfo.swap_free_kb);
    if (meminfo.swap_total_kb >= 0 && meminfo.swap_free_kb >= 0)
        add_number_if_nonneg(memory, "swap_used",
                             meminfo.swap_total_kb - meminfo.swap_free_kb);

    cJSON *process = cJSON_AddObjectToObject(root, "smolclaw_process");
    cJSON_AddNumberToObject(process, "pid", (double)getpid());
    add_number_if_nonneg(process, "vmrss_kb", procinfo.vmrss_kb);
    add_number_if_nonneg(process, "vmsize_kb", procinfo.vmsize_kb);
    add_number_if_nonneg(process, "threads", procinfo.threads);
    add_number_if_nonneg(process, "open_fds", procinfo.fd_count);

    fill_storage(root);
    fill_camera(root, include_paths);

    cJSON *temps = cJSON_AddObjectToObject(root, "thermal_c");
    add_temp_samples(temps);

    if (sampled_at) cJSON_AddStringToObject(root, "sampled_at", sampled_at);
    cJSON_AddStringToObject(root, "note",
        "Live snapshot only. Use repeated samples to detect leaks or long-term trends.");

    free(sampled_at);
    free(cpu_model);
    free(board_model);
    return root;
}

static int
collect_host_sample(host_sample_t *out)
{
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    out->ts = time(NULL);
    out->load1 = out->load5 = out->load15 = -1.0;
    out->mem_total_kb = -1;
    out->mem_available_kb = -1;
    out->swap_used_kb = -1;
    out->vmrss_kb = -1;
    out->vmsize_kb = -1;
    out->open_fds = -1;
    out->threads = -1;
    out->rootfs_free_bytes = -1;
    out->cpu_temp_c = -1.0;

    host_meminfo_t meminfo;
    host_procinfo_t procinfo;
    memset(&meminfo, 0, sizeof(meminfo));
    memset(&procinfo, 0, sizeof(procinfo));
    read_meminfo(&meminfo);
    read_self_procinfo(&procinfo);
    read_loadavg(&out->load1, &out->load5, &out->load15);

    out->mem_total_kb = meminfo.mem_total_kb;
    out->mem_available_kb = meminfo.mem_available_kb;
    if (meminfo.swap_total_kb >= 0 && meminfo.swap_free_kb >= 0)
        out->swap_used_kb = meminfo.swap_total_kb - meminfo.swap_free_kb;
    out->vmrss_kb = procinfo.vmrss_kb;
    out->vmsize_kb = procinfo.vmsize_kb;
    out->open_fds = procinfo.fd_count;
    out->threads = procinfo.threads;

    struct statvfs vfs;
    if (statvfs("/", &vfs) == 0) {
        out->rootfs_free_bytes =
            (long long)((unsigned long long)vfs.f_frsize *
                        (unsigned long long)vfs.f_bavail);
    }

    read_peak_temp_c(&out->cpu_temp_c);
    return 0;
}

static char *
detect_package_manager(const char **db_path_out)
{
    if (db_path_out) *db_path_out = NULL;

    if (path_exists("/var/lib/dpkg/status")) {
        if (db_path_out) *db_path_out = "/var/lib/dpkg/status";
        return sc_strdup("dpkg");
    }
    if (path_exists("/lib/apk/db/installed")) {
        if (db_path_out) *db_path_out = "/lib/apk/db/installed";
        return sc_strdup("apk");
    }
    if (path_exists("/var/lib/rpm/Packages")) {
        if (db_path_out) *db_path_out = "/var/lib/rpm/Packages";
        return sc_strdup("rpm");
    }
    if (path_exists("/usr/lib/sysimage/rpm/Packages")) {
        if (db_path_out) *db_path_out = "/usr/lib/sysimage/rpm/Packages";
        return sc_strdup("rpm");
    }
    if (path_exists("/usr/lib/opkg/status")) {
        if (db_path_out) *db_path_out = "/usr/lib/opkg/status";
        return sc_strdup("opkg");
    }
    if (path_exists("/var/lib/opkg/status")) {
        if (db_path_out) *db_path_out = "/var/lib/opkg/status";
        return sc_strdup("opkg");
    }
    return sc_strdup("unknown");
}

static tracked_pkg_t *
tracked_pkg_array_new(const char *const *names, int *out_count)
{
    int count = 0;
    while (names && names[count])
        count++;
    if (out_count) *out_count = count;
    if (count == 0) return NULL;

    tracked_pkg_t *items = calloc((size_t)count, sizeof(*items));
    if (!items) return NULL;
    for (int i = 0; i < count; i++)
        items[i].name = names[i];
    return items;
}

static void
tracked_pkg_array_free(tracked_pkg_t *items, int count)
{
    if (!items) return;
    for (int i = 0; i < count; i++)
        free(items[i].version);
    free(items);
}

static void
maybe_record_tracked_package(tracked_pkg_t *items, int count,
                             const char *name, const char *version)
{
    if (!items || !name || !version) return;
    for (int i = 0; i < count; i++) {
        if (strcmp(items[i].name, name) == 0) {
            free(items[i].version);
            items[i].version = sc_strdup(version);
            return;
        }
    }
}

static int
parse_status_db(const char *path, tracked_pkg_t *tracked, int tracked_count)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[1024];
    char pkg_name[256] = {0};
    char version[256] = {0};
    int installed = 0;
    int package_count = 0;

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '\n' || line[0] == '\r') {
            if (installed && pkg_name[0]) {
                package_count++;
                maybe_record_tracked_package(tracked, tracked_count,
                                             pkg_name,
                                             version[0] ? version : "installed");
            }
            pkg_name[0] = '\0';
            version[0] = '\0';
            installed = 0;
            continue;
        }

        if (strncmp(line, "Package:", 8) == 0) {
            char *v = trim_leading_ws(line + 8);
            trim_trailing_ws(v);
            snprintf(pkg_name, sizeof(pkg_name), "%s", v);
        } else if (strncmp(line, "Version:", 8) == 0) {
            char *v = trim_leading_ws(line + 8);
            trim_trailing_ws(v);
            snprintf(version, sizeof(version), "%s", v);
        } else if (strncmp(line, "Status:", 7) == 0) {
            installed = strstr(line, "install ok installed") != NULL ||
                        strstr(line, "ok installed") != NULL;
        }
    }

    if (installed && pkg_name[0]) {
        package_count++;
        maybe_record_tracked_package(tracked, tracked_count,
                                     pkg_name,
                                     version[0] ? version : "installed");
    }

    fclose(f);
    return package_count;
}

static void
fill_software_inventory(cJSON *root, int include_paths)
{
    const char *pkg_db_path = NULL;
    char *pkg_mgr = detect_package_manager(&pkg_db_path);
    int tracked_count = 0;
    tracked_pkg_t *tracked = tracked_pkg_array_new(tracked_dpkg_packages,
                                                   &tracked_count);
    int package_count = -1;

    if (pkg_db_path && pkg_mgr &&
        (strcmp(pkg_mgr, "dpkg") == 0 || strcmp(pkg_mgr, "opkg") == 0)) {
        package_count = parse_status_db(pkg_db_path, tracked, tracked_count);
    }

    cJSON *software = cJSON_AddObjectToObject(root, "software");
    if (pkg_mgr) cJSON_AddStringToObject(software, "package_manager", pkg_mgr);
    if (include_paths && pkg_db_path)
        cJSON_AddStringToObject(software, "package_db", pkg_db_path);
    if (package_count >= 0)
        cJSON_AddNumberToObject(software, "installed_package_count",
                                package_count);

    cJSON *tracked_obj = cJSON_AddObjectToObject(software, "tracked_packages");
    for (int i = 0; i < tracked_count; i++) {
        if (tracked[i].version)
            cJSON_AddStringToObject(tracked_obj, tracked[i].name,
                                    tracked[i].version);
    }

    cJSON *binaries = cJSON_AddObjectToObject(software, "binaries");
    cJSON_AddBoolToObject(binaries, "ffmpeg",
                          path_exists("/usr/bin/ffmpeg") ||
                          path_exists("/bin/ffmpeg"));
    cJSON_AddBoolToObject(binaries, "curl",
                          path_exists("/usr/bin/curl") ||
                          path_exists("/bin/curl"));
    cJSON_AddBoolToObject(binaries, "git",
                          path_exists("/usr/bin/git") ||
                          path_exists("/bin/git"));
    cJSON_AddBoolToObject(binaries, "smolclaw",
                          path_exists("/usr/local/bin/smolclaw") ||
                          path_exists("/usr/bin/smolclaw") ||
                          path_exists("/bin/smolclaw"));

    tracked_pkg_array_free(tracked, tracked_count);
    free(pkg_mgr);
}

static cJSON *
build_host_inventory_json(int include_paths, int sandbox_enabled)
{
    host_meminfo_t meminfo;
    char *cpu_model = read_cpu_model();
    char *board_model = read_first_existing_file((const char *const[]){
        "/sys/firmware/devicetree/base/model",
        "/sys/devices/virtual/dmi/id/product_name",
        NULL
    });
    char *sampled_at = now_timestamp();

    read_meminfo(&meminfo);

    cJSON *root = cJSON_CreateObject();
    fill_identity(root);
    fill_sandbox(root, sandbox_enabled);

    cJSON *hardware = cJSON_AddObjectToObject(root, "hardware");
    if (board_model) cJSON_AddStringToObject(hardware, "board_model", board_model);
    if (cpu_model) cJSON_AddStringToObject(hardware, "cpu_model", cpu_model);
    add_number_if_nonneg(hardware, "mem_total_kb", meminfo.mem_total_kb);

    fill_storage(root);
    fill_camera(root, include_paths);
    fill_software_inventory(root, include_paths);

    cJSON *temps = cJSON_AddObjectToObject(root, "thermal_c");
    add_temp_samples(temps);

    if (sampled_at) cJSON_AddStringToObject(root, "sampled_at", sampled_at);
    cJSON_AddStringToObject(root, "note",
        "Inventory is persisted under workspace/context/host/ for context_search.");

    free(sampled_at);
    free(cpu_model);
    free(board_model);
    return root;
}

static const char *
json_string(cJSON *obj, const char *key)
{
    cJSON *item = obj ? cJSON_GetObjectItemCaseSensitive(obj, key) : NULL;
    return cJSON_IsString(item) ? item->valuestring : NULL;
}

static double
json_number(cJSON *obj, const char *key, double fallback)
{
    cJSON *item = obj ? cJSON_GetObjectItemCaseSensitive(obj, key) : NULL;
    return cJSON_IsNumber(item) ? item->valuedouble : fallback;
}

static char *
render_inventory_markdown(cJSON *root)
{
    if (!root) return NULL;

    cJSON *hardware = cJSON_GetObjectItemCaseSensitive(root, "hardware");
    cJSON *sandbox = cJSON_GetObjectItemCaseSensitive(root, "sandbox");
    cJSON *software = cJSON_GetObjectItemCaseSensitive(root, "software");
    cJSON *camera = cJSON_GetObjectItemCaseSensitive(root, "camera");
    cJSON *rootfs = cJSON_GetObjectItemCaseSensitive(root, "rootfs_bytes");
    cJSON *tracked = software
        ? cJSON_GetObjectItemCaseSensitive(software, "tracked_packages")
        : NULL;
    cJSON *temps = cJSON_GetObjectItemCaseSensitive(root, "thermal_c");

    sc_strbuf_t sb;
    sc_strbuf_init(&sb);
    sc_strbuf_append(&sb, "# Host Inventory\n\n");

    const char *sampled_at = json_string(root, "sampled_at");
    if (sampled_at)
        sc_strbuf_appendf(&sb, "Sampled at: %s\n\n", sampled_at);

    sc_strbuf_append(&sb, "## System\n");
    if (json_string(root, "hostname"))
        sc_strbuf_appendf(&sb, "- Hostname: %s\n", json_string(root, "hostname"));
    if (json_string(root, "os"))
        sc_strbuf_appendf(&sb, "- OS: %s\n", json_string(root, "os"));
    if (json_string(root, "kernel"))
        sc_strbuf_appendf(&sb, "- Kernel: %s\n", json_string(root, "kernel"));
    if (json_string(root, "arch"))
        sc_strbuf_appendf(&sb, "- Arch: %s\n", json_string(root, "arch"));

    sc_strbuf_append(&sb, "\n## Sandbox\n");
    if (json_string(sandbox, "status"))
        sc_strbuf_appendf(&sb, "- Status: %s\n",
                          json_string(sandbox, "status"));
    sc_strbuf_appendf(&sb, "- Configured: %s\n",
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(sandbox, "configured"))
            ? "yes" : "no");
    sc_strbuf_appendf(&sb, "- Landlock available: %s\n",
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(sandbox, "landlock_available"))
            ? "yes" : "no");
    sc_strbuf_appendf(&sb, "- seccomp available: %s\n",
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(sandbox, "seccomp_available"))
            ? "yes" : "no");
    if (json_string(sandbox, "summary"))
        sc_strbuf_appendf(&sb, "- Summary: %s\n",
                          json_string(sandbox, "summary"));

    sc_strbuf_append(&sb, "\n## Hardware\n");
    if (json_string(hardware, "board_model"))
        sc_strbuf_appendf(&sb, "- Board model: %s\n",
                          json_string(hardware, "board_model"));
    if (json_string(hardware, "cpu_model"))
        sc_strbuf_appendf(&sb, "- CPU model: %s\n",
                          json_string(hardware, "cpu_model"));
    if (json_number(hardware, "mem_total_kb", -1) >= 0)
        sc_strbuf_appendf(&sb, "- Memory total: %.1f MiB\n",
                          json_number(hardware, "mem_total_kb", 0) / 1024.0);
    if (json_number(rootfs, "total", -1) >= 0)
        sc_strbuf_appendf(&sb, "- Rootfs total: %.1f GiB\n",
                          json_number(rootfs, "total", 0) / 1073741824.0);
    if (json_number(rootfs, "free", -1) >= 0)
        sc_strbuf_appendf(&sb, "- Rootfs free: %.1f GiB\n",
                          json_number(rootfs, "free", 0) / 1073741824.0);

    sc_strbuf_append(&sb, "\n## Software\n");
    if (json_string(software, "package_manager"))
        sc_strbuf_appendf(&sb, "- Package manager: %s\n",
                          json_string(software, "package_manager"));
    if (json_number(software, "installed_package_count", -1) >= 0)
        sc_strbuf_appendf(&sb, "- Installed packages: %.0f\n",
                          json_number(software, "installed_package_count", 0));
    if (tracked && tracked->child) {
        for (cJSON *it = tracked->child; it; it = it->next) {
            if (cJSON_IsString(it) && it->string)
                sc_strbuf_appendf(&sb, "- Package %s: %s\n",
                                  it->string, it->valuestring);
        }
    }

    sc_strbuf_append(&sb, "\n## Camera\n");
    sc_strbuf_appendf(&sb, "- Video device present: %s\n",
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(camera, "video_device_present"))
            ? "yes" : "no");
    sc_strbuf_appendf(&sb, "- libcamera-still: %s\n",
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(camera, "libcamera_still"))
            ? "yes" : "no");
    sc_strbuf_appendf(&sb, "- libcamera-vid: %s\n",
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(camera, "libcamera_vid"))
            ? "yes" : "no");
    sc_strbuf_appendf(&sb, "- libcamera-hello: %s\n",
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(camera, "libcamera_hello"))
            ? "yes" : "no");
    if (json_string(camera, "first_video_device"))
        sc_strbuf_appendf(&sb, "- First video device: %s\n",
                          json_string(camera, "first_video_device"));

    if (temps && temps->child) {
        sc_strbuf_append(&sb, "\n## Thermal\n");
        for (cJSON *it = temps->child; it; it = it->next) {
            if (cJSON_IsNumber(it) && it->string)
                sc_strbuf_appendf(&sb, "- %s: %.1f C\n",
                                  it->string, it->valuedouble);
        }
    }

    return sc_strbuf_finish(&sb);
}

static int
mkdirp_dir(const char *dir)
{
    char *tmp = sc_strdup(dir);
    if (!tmp) return -1;

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                free(tmp);
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        free(tmp);
        return -1;
    }
    free(tmp);
    return 0;
}

static int
write_atomic_text(const char *path, const char *content)
{
    char tmp_path[PATH_MAX];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return -1;

    size_t len = content ? strlen(content) : 0;
    ssize_t written = write(fd, content ? content : "", len);
    fsync(fd);
    close(fd);

    if (written != (ssize_t)len) {
        unlink(tmp_path);
        return -1;
    }
    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

static char *
join_path2(const char *a, const char *b)
{
    if (!a || !b) return NULL;
    size_t len_a = strlen(a);
    size_t len_b = strlen(b);
    char *out = malloc(len_a + 1 + len_b + 1);
    if (!out) return NULL;
    memcpy(out, a, len_a);
    out[len_a] = '/';
    memcpy(out + len_a + 1, b, len_b);
    out[len_a + 1 + len_b] = '\0';
    return out;
}

#if SC_ENABLE_HOST_METRICS
static int
host_db_open(const char *workspace, sqlite3 **out_db)
{
    if (out_db) *out_db = NULL;
    if (!workspace || !workspace[0] || !out_db)
        return -1;

    char *state_dir = join_path2(workspace, "state");
    char *db_path = join_path2(workspace, HOST_METRICS_DB);
    if (!state_dir || !db_path) {
        free(state_dir);
        free(db_path);
        return -1;
    }

    if (mkdirp_dir(state_dir) != 0) {
        free(state_dir);
        free(db_path);
        return -1;
    }
    free(state_dir);

    sqlite3 *db = NULL;
    int rc = sqlite3_open(db_path, &db);
    free(db_path);
    if (rc != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return -1;
    }

    sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA wal_autocheckpoint=1000", NULL, NULL, NULL);
    sqlite3_busy_timeout(db, 5000);

    int nmig = (int)(sizeof(HOST_METRICS_MIGRATIONS) /
                     sizeof(HOST_METRICS_MIGRATIONS[0]));
    if (sc_db_migrate(db, HOST_METRICS_MIGRATIONS, nmig, "host_metrics") < 0) {
        sqlite3_close(db);
        return -1;
    }

    *out_db = db;
    return 0;
}

static void
host_db_close(sqlite3 *db)
{
    if (db) sqlite3_close(db);
}

static int
host_db_latest_ts(sqlite3 *db, time_t *out_ts)
{
    if (!db || !out_ts) return -1;
    *out_ts = 0;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT ts FROM host_samples ORDER BY ts DESC LIMIT 1",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
        *out_ts = (time_t)sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return 0;
}

static void
host_db_cleanup(sqlite3 *db, int retention_days)
{
    if (!db) return;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "DELETE FROM host_samples WHERE ts < ?",
            -1, &stmt, NULL) != SQLITE_OK)
        return;

    sqlite3_bind_int64(stmt, 1,
        (sqlite3_int64)(time(NULL) - (time_t)retention_days * 86400));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

static int
host_db_insert_sample(sqlite3 *db, const host_sample_t *sample)
{
    if (!db || !sample) return -1;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO host_samples ("
        " ts, load1, load5, load15, mem_total_kb, mem_available_kb,"
        " swap_used_kb, vmrss_kb, vmsize_kb, open_fds, threads,"
        " rootfs_free_bytes, cpu_temp_c)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)sample->ts);
    if (sample->load1 >= 0) sqlite3_bind_double(stmt, 2, sample->load1);
    else sqlite3_bind_null(stmt, 2);
    if (sample->load5 >= 0) sqlite3_bind_double(stmt, 3, sample->load5);
    else sqlite3_bind_null(stmt, 3);
    if (sample->load15 >= 0) sqlite3_bind_double(stmt, 4, sample->load15);
    else sqlite3_bind_null(stmt, 4);
    if (sample->mem_total_kb >= 0) sqlite3_bind_int64(stmt, 5, sample->mem_total_kb);
    else sqlite3_bind_null(stmt, 5);
    if (sample->mem_available_kb >= 0) sqlite3_bind_int64(stmt, 6, sample->mem_available_kb);
    else sqlite3_bind_null(stmt, 6);
    if (sample->swap_used_kb >= 0) sqlite3_bind_int64(stmt, 7, sample->swap_used_kb);
    else sqlite3_bind_null(stmt, 7);
    if (sample->vmrss_kb >= 0) sqlite3_bind_int64(stmt, 8, sample->vmrss_kb);
    else sqlite3_bind_null(stmt, 8);
    if (sample->vmsize_kb >= 0) sqlite3_bind_int64(stmt, 9, sample->vmsize_kb);
    else sqlite3_bind_null(stmt, 9);
    if (sample->open_fds >= 0) sqlite3_bind_int64(stmt, 10, sample->open_fds);
    else sqlite3_bind_null(stmt, 10);
    if (sample->threads >= 0) sqlite3_bind_int64(stmt, 11, sample->threads);
    else sqlite3_bind_null(stmt, 11);
    if (sample->rootfs_free_bytes >= 0)
        sqlite3_bind_int64(stmt, 12, (sqlite3_int64)sample->rootfs_free_bytes);
    else sqlite3_bind_null(stmt, 12);
    if (sample->cpu_temp_c >= 0) sqlite3_bind_double(stmt, 13, sample->cpu_temp_c);
    else sqlite3_bind_null(stmt, 13);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

int
sc_host_record_sample(const char *workspace, int force)
{
    if (!workspace || !workspace[0])
        return -1;

    host_sample_t sample;
    if (collect_host_sample(&sample) != 0)
        return -1;

    sqlite3 *db = NULL;
    if (host_db_open(workspace, &db) != 0)
        return -1;

    time_t latest_ts = 0;
    if (!force && host_db_latest_ts(db, &latest_ts) == 0 &&
        latest_ts > 0 && sample.ts - latest_ts < HOST_SAMPLE_INTERVAL_SEC) {
        host_db_close(db);
        return 0;
    }

    host_db_cleanup(db, HOST_SAMPLE_RETENTION_DAYS);
    int rc = host_db_insert_sample(db, &sample);
    host_db_close(db);
    return rc;
}
#else /* !SC_ENABLE_HOST_METRICS */
int
sc_host_record_sample(const char *workspace, int force)
{
    (void)workspace;
    (void)force;
    return -1; /* metrics retention not built; callers treat as no-op */
}
#endif /* SC_ENABLE_HOST_METRICS */

int
sc_host_sample_interval_sec(void)
{
    return HOST_SAMPLE_INTERVAL_SEC;
}

#if SC_ENABLE_HOST_METRICS
static int
load_recent_samples(sqlite3 *db, int period_hours, int max_samples,
                    host_sample_t **out_samples, int *out_count)
{
    if (out_samples) *out_samples = NULL;
    if (out_count) *out_count = 0;
    if (!db || !out_samples || !out_count)
        return -1;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT ts, load1, load5, load15, mem_total_kb, mem_available_kb,"
        " swap_used_kb, vmrss_kb, vmsize_kb, open_fds, threads,"
        " rootfs_free_bytes, cpu_temp_c"
        " FROM host_samples"
        " WHERE ts >= ?"
        " ORDER BY ts DESC"
        " LIMIT ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    time_t cutoff = time(NULL) - (time_t)period_hours * 3600;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)cutoff);
    sqlite3_bind_int(stmt, 2, max_samples);

    int cap = 16;
    int count = 0;
    host_sample_t *items = calloc((size_t)cap, sizeof(*items));
    if (!items) {
        sqlite3_finalize(stmt);
        return -1;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (count == cap) {
            cap *= 2;
            host_sample_t *tmp = realloc(items, (size_t)cap * sizeof(*items));
            if (!tmp) {
                free(items);
                sqlite3_finalize(stmt);
                return -1;
            }
            items = tmp;
        }

        host_sample_t *s = &items[count++];
        memset(s, 0, sizeof(*s));
        s->ts = (time_t)sqlite3_column_int64(stmt, 0);
        s->load1 = sqlite3_column_type(stmt, 1) == SQLITE_NULL ? -1.0 : sqlite3_column_double(stmt, 1);
        s->load5 = sqlite3_column_type(stmt, 2) == SQLITE_NULL ? -1.0 : sqlite3_column_double(stmt, 2);
        s->load15 = sqlite3_column_type(stmt, 3) == SQLITE_NULL ? -1.0 : sqlite3_column_double(stmt, 3);
        s->mem_total_kb = sqlite3_column_type(stmt, 4) == SQLITE_NULL ? -1 : (long)sqlite3_column_int64(stmt, 4);
        s->mem_available_kb = sqlite3_column_type(stmt, 5) == SQLITE_NULL ? -1 : (long)sqlite3_column_int64(stmt, 5);
        s->swap_used_kb = sqlite3_column_type(stmt, 6) == SQLITE_NULL ? -1 : (long)sqlite3_column_int64(stmt, 6);
        s->vmrss_kb = sqlite3_column_type(stmt, 7) == SQLITE_NULL ? -1 : (long)sqlite3_column_int64(stmt, 7);
        s->vmsize_kb = sqlite3_column_type(stmt, 8) == SQLITE_NULL ? -1 : (long)sqlite3_column_int64(stmt, 8);
        s->open_fds = sqlite3_column_type(stmt, 9) == SQLITE_NULL ? -1 : (long)sqlite3_column_int64(stmt, 9);
        s->threads = sqlite3_column_type(stmt, 10) == SQLITE_NULL ? -1 : (long)sqlite3_column_int64(stmt, 10);
        s->rootfs_free_bytes = sqlite3_column_type(stmt, 11) == SQLITE_NULL ? -1 : (long long)sqlite3_column_int64(stmt, 11);
        s->cpu_temp_c = sqlite3_column_type(stmt, 12) == SQLITE_NULL ? -1.0 : sqlite3_column_double(stmt, 12);
    }
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        free(items);
        return -1;
    }

    for (int i = 0; i < count / 2; i++) {
        host_sample_t tmp = items[i];
        items[i] = items[count - 1 - i];
        items[count - 1 - i] = tmp;
    }

    *out_samples = items;
    *out_count = count;
    return 0;
}
#endif /* SC_ENABLE_HOST_METRICS */

static double
sample_value_rss(const host_sample_t *s) { return s ? (double)s->vmrss_kb : -1.0; }
static double
sample_value_fds(const host_sample_t *s) { return s ? (double)s->open_fds : -1.0; }
static double
sample_value_memavail(const host_sample_t *s) { return s ? (double)s->mem_available_kb : -1.0; }
static double
sample_value_load1(const host_sample_t *s) { return s ? s->load1 : -1.0; }

typedef double (*host_sample_value_fn)(const host_sample_t *s);

static double
compute_rising_ratio(const host_sample_t *samples, int count, host_sample_value_fn fn)
{
    if (!samples || count < 2 || !fn)
        return 0.0;

    int steps = 0;
    int rising = 0;
    double prev = fn(&samples[0]);
    for (int i = 1; i < count; i++) {
        double cur = fn(&samples[i]);
        if (prev < 0 || cur < 0) {
            prev = cur;
            continue;
        }
        steps++;
        if (cur > prev)
            rising++;
        prev = cur;
    }
    if (steps == 0) return 0.0;
    return (double)rising / (double)steps;
}

static const char *
trend_direction(double delta, double slope_per_hour, double stable_abs)
{
    if (delta <= -stable_abs)
        return "falling";
    if (delta >= stable_abs && slope_per_hour > 0)
        return "rising";
    return "stable";
}

static void
add_latest_sample_json(cJSON *root, const host_sample_t *s)
{
    if (!root || !s) return;
    cJSON *latest = cJSON_AddObjectToObject(root, "latest");
    if (!latest) return;

    char *ts = format_timestamp(s->ts);
    if (ts) {
        cJSON_AddStringToObject(latest, "sampled_at", ts);
        free(ts);
    }
    if (s->vmrss_kb >= 0) cJSON_AddNumberToObject(latest, "vmrss_kb", s->vmrss_kb);
    if (s->vmsize_kb >= 0) cJSON_AddNumberToObject(latest, "vmsize_kb", s->vmsize_kb);
    if (s->open_fds >= 0) cJSON_AddNumberToObject(latest, "open_fds", s->open_fds);
    if (s->threads >= 0) cJSON_AddNumberToObject(latest, "threads", s->threads);
    if (s->mem_total_kb >= 0) cJSON_AddNumberToObject(latest, "mem_total_kb", s->mem_total_kb);
    if (s->mem_available_kb >= 0) cJSON_AddNumberToObject(latest, "mem_available_kb", s->mem_available_kb);
    if (s->swap_used_kb >= 0) cJSON_AddNumberToObject(latest, "swap_used_kb", s->swap_used_kb);
    if (s->rootfs_free_bytes >= 0)
        cJSON_AddNumberToObject(latest, "rootfs_free_bytes", (double)s->rootfs_free_bytes);
    if (s->load1 >= 0) cJSON_AddNumberToObject(latest, "load1", s->load1);
    if (s->load5 >= 0) cJSON_AddNumberToObject(latest, "load5", s->load5);
    if (s->load15 >= 0) cJSON_AddNumberToObject(latest, "load15", s->load15);
    if (s->cpu_temp_c >= 0) cJSON_AddNumberToObject(latest, "cpu_temp_c", s->cpu_temp_c);
}

static void
add_trend_metric(cJSON *trend, const char *name,
                 double delta, double slope, double rising_ratio,
                 double stable_abs)
{
    if (!trend || !name) return;
    cJSON *obj = cJSON_AddObjectToObject(trend, name);
    if (!obj) return;

    cJSON_AddNumberToObject(obj, "delta", delta);
    cJSON_AddNumberToObject(obj, "slope_per_hour", slope);
    cJSON_AddNumberToObject(obj, "rising_ratio", rising_ratio);
    cJSON_AddStringToObject(obj, "direction",
                            trend_direction(delta, slope, stable_abs));
}

static cJSON *
build_host_trend_json(const host_sample_t *samples, int count,
                      int period_hours)
{
    if (!samples || count <= 0)
        return NULL;

    const host_sample_t *first = &samples[0];
    const host_sample_t *last = &samples[count - 1];
    double window_hours = count >= 2
        ? (double)(last->ts - first->ts) / 3600.0
        : 0.0;
    if (window_hours <= 0.0)
        window_hours = 0.0;

    double rss_delta = (first->vmrss_kb >= 0 && last->vmrss_kb >= 0)
        ? (double)(last->vmrss_kb - first->vmrss_kb) : 0.0;
    double fd_delta = (first->open_fds >= 0 && last->open_fds >= 0)
        ? (double)(last->open_fds - first->open_fds) : 0.0;
    double memavail_delta = (first->mem_available_kb >= 0 && last->mem_available_kb >= 0)
        ? (double)(last->mem_available_kb - first->mem_available_kb) : 0.0;
    double load1_delta = (first->load1 >= 0 && last->load1 >= 0)
        ? (last->load1 - first->load1) : 0.0;
    double rootfs_delta = (first->rootfs_free_bytes >= 0 && last->rootfs_free_bytes >= 0)
        ? (double)(last->rootfs_free_bytes - first->rootfs_free_bytes) : 0.0;
    double temp_delta = (first->cpu_temp_c >= 0 && last->cpu_temp_c >= 0)
        ? (last->cpu_temp_c - first->cpu_temp_c) : 0.0;

    double denom = window_hours > 0.0 ? window_hours : 1.0;
    double rss_slope = rss_delta / denom;
    double fd_slope = fd_delta / denom;
    double memavail_slope = memavail_delta / denom;
    double load1_slope = load1_delta / denom;
    double rootfs_slope = rootfs_delta / denom;
    double temp_slope = temp_delta / denom;

    double rss_rising_ratio = compute_rising_ratio(samples, count, sample_value_rss);
    double fd_rising_ratio = compute_rising_ratio(samples, count, sample_value_fds);
    double memavail_rising_ratio = compute_rising_ratio(samples, count, sample_value_memavail);
    double load1_rising_ratio = compute_rising_ratio(samples, count, sample_value_load1);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "sample_interval_sec", HOST_SAMPLE_INTERVAL_SEC);
    cJSON_AddNumberToObject(root, "retention_days", HOST_SAMPLE_RETENTION_DAYS);
    cJSON_AddNumberToObject(root, "sample_count", count);
    cJSON_AddNumberToObject(root, "period_hours", period_hours);
    cJSON_AddNumberToObject(root, "window_hours", window_hours);

    char *first_ts = format_timestamp(first->ts);
    char *last_ts = format_timestamp(last->ts);
    if (first_ts) cJSON_AddStringToObject(root, "first_sampled_at", first_ts);
    if (last_ts) cJSON_AddStringToObject(root, "last_sampled_at", last_ts);
    free(first_ts);
    free(last_ts);

    add_latest_sample_json(root, last);

    cJSON *trend = cJSON_AddObjectToObject(root, "trend");
    add_trend_metric(trend, "rss_kb", rss_delta, rss_slope, rss_rising_ratio, 1024.0);
    add_trend_metric(trend, "open_fds", fd_delta, fd_slope, fd_rising_ratio, 2.0);
    add_trend_metric(trend, "mem_available_kb", memavail_delta, memavail_slope,
                     memavail_rising_ratio, 2048.0);
    add_trend_metric(trend, "load1", load1_delta, load1_slope,
                     load1_rising_ratio, 0.25);
    add_trend_metric(trend, "rootfs_free_bytes", rootfs_delta, rootfs_slope,
                     0.0, 10485760.0);
    add_trend_metric(trend, "cpu_temp_c", temp_delta, temp_slope,
                     0.0, 1.0);

    cJSON *flags = cJSON_AddObjectToObject(root, "flags");
    int possible_rss_leak =
        count >= 4 && window_hours >= 0.5 &&
        rss_delta >= 4096.0 && rss_slope >= 1024.0 &&
        rss_rising_ratio >= 0.60;
    int possible_fd_leak =
        count >= 4 && window_hours >= 0.5 &&
        fd_delta >= 8.0 && fd_slope >= 4.0 &&
        fd_rising_ratio >= 0.60;
    int memory_pressure =
        last->mem_total_kb > 0 && last->mem_available_kb >= 0 &&
        ((double)last->mem_available_kb / (double)last->mem_total_kb) < 0.10;
    int swap_pressure = last->swap_used_kb >= 131072;
    int disk_pressure = last->rootfs_free_bytes >= 0 &&
                        last->rootfs_free_bytes < (long long)1073741824;

    cJSON_AddBoolToObject(flags, "possible_rss_leak", possible_rss_leak);
    cJSON_AddBoolToObject(flags, "possible_fd_leak", possible_fd_leak);
    cJSON_AddBoolToObject(flags, "memory_pressure", memory_pressure);
    cJSON_AddBoolToObject(flags, "swap_pressure", swap_pressure);
    cJSON_AddBoolToObject(flags, "disk_pressure", disk_pressure);

    cJSON_AddStringToObject(root, "note",
        count < 2
            ? "Only one retained sample is available. Wait for more samples before trusting trend output."
            : "Trend analysis is heuristic. Confirm suspected leaks with a longer window and code-level inspection.");
    return root;
}

static int
persist_inventory_artifacts(const char *workspace, sc_memory_index_t *idx,
                            const char *json_text, const char *md_text)
{
    if (!workspace || !workspace[0] || !json_text || !md_text)
        return -1;

    char *ctx_dir = NULL;
    char *json_path = NULL;
    char *md_path = NULL;

    ctx_dir = join_path2(workspace, HOST_CTX_DIR);
    json_path = ctx_dir ? join_path2(ctx_dir, HOST_INV_JSON) : NULL;
    md_path = ctx_dir ? join_path2(ctx_dir, HOST_INV_MD) : NULL;
    if (!ctx_dir || !json_path || !md_path) {
        free(ctx_dir);
        free(json_path);
        free(md_path);
        return -1;
    }

    if (mkdirp_dir(ctx_dir) != 0) {
        SC_LOG_WARN(HOST_TAG, "Failed to create %s: %s", ctx_dir, strerror(errno));
        free(ctx_dir);
        free(json_path);
        free(md_path);
        return -1;
    }
    if (write_atomic_text(json_path, json_text) != 0) {
        SC_LOG_WARN(HOST_TAG, "Failed to write %s: %s", json_path, strerror(errno));
        free(ctx_dir);
        free(json_path);
        free(md_path);
        return -1;
    }
    if (write_atomic_text(md_path, md_text) != 0) {
        SC_LOG_WARN(HOST_TAG, "Failed to write %s: %s", md_path, strerror(errno));
        free(ctx_dir);
        free(json_path);
        free(md_path);
        return -1;
    }

    if (idx) {
#if SC_ENABLE_MEMORY_SEARCH
        sc_memory_index_put_chunked(idx, "ctx:" HOST_INV_JSON, json_text);
        sc_memory_index_put_chunked(idx, "ctx:" HOST_INV_MD, md_text);
#endif
    }

    free(ctx_dir);
    free(json_path);
    free(md_path);
    return 0;
}

int
sc_host_refresh_inventory_artifacts(const char *workspace,
                                    sc_memory_index_t *idx,
                                    int sandbox_enabled)
{
    if (!workspace || !workspace[0])
        return -1;

    cJSON *root = build_host_inventory_json(1, sandbox_enabled);
    if (!root)
        return -1;

    cJSON_AddStringToObject(root, "artifact_dir", HOST_CTX_DIR);
    char *json_text = cJSON_Print(root);
    char *md_text = render_inventory_markdown(root);
    cJSON_Delete(root);

    if (!json_text || !md_text) {
        free(json_text);
        free(md_text);
        return -1;
    }

    int rc = persist_inventory_artifacts(workspace, idx, json_text, md_text);
    free(json_text);
    free(md_text);
    return rc;
}

static host_tool_data_t *
host_tool_data_new(const char *workspace, sc_memory_index_t *idx,
                   int sandbox_enabled)
{
    host_tool_data_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    if (workspace) {
        d->workspace = sc_strdup(workspace);
        if (!d->workspace) {
            free(d);
            return NULL;
        }
    }
    d->idx = idx;
    d->sandbox_enabled = sandbox_enabled;
    return d;
}

static void
host_tool_data_free(host_tool_data_t *d)
{
    if (!d) return;
    free(d->workspace);
    free(d);
}

static cJSON *
host_status_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    cJSON *props = cJSON_GetObjectItem(schema, "properties");
    if (props) {
        cJSON *item = cJSON_AddObjectToObject(props, "include_paths");
        cJSON_AddStringToObject(item, "type", "boolean");
        cJSON_AddStringToObject(item, "description",
            "Include camera and mount path details in the result.");

        cJSON *record = cJSON_AddObjectToObject(props, "record_sample");
        cJSON_AddStringToObject(record, "type", "boolean");
        cJSON_AddStringToObject(record, "description",
            "Record this snapshot into retained host metrics if workspace state is writable.");
    }
    return schema;
}

static void
host_status_destroy(sc_tool_t *self)
{
    if (!self) return;
    host_tool_data_free((host_tool_data_t *)self->data);
    free(self);
}

static sc_tool_result_t *
host_status_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    host_tool_data_t *d = self ? self->data : NULL;

    int include_paths = sc_json_get_bool(args, "include_paths", 0);
    int record_sample = sc_json_get_bool(args, "record_sample", 1);
    if (record_sample && d && d->workspace)
        sc_host_record_sample(d->workspace, 0);

    cJSON *root = build_host_status_json(include_paths, d->sandbox_enabled);
    if (!root)
        return sc_tool_result_error("failed to build host status");

    char *json = cJSON_Print(root);
    cJSON_Delete(root);
    if (!json)
        return sc_tool_result_error("failed to render host status");

    sc_tool_result_t *result = sc_tool_result_user(json);
    free(json);
    return result;
}

static cJSON *
host_inventory_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    cJSON *props = cJSON_GetObjectItem(schema, "properties");
    if (props) {
        cJSON *paths = cJSON_AddObjectToObject(props, "include_paths");
        cJSON_AddStringToObject(paths, "type", "boolean");
        cJSON_AddStringToObject(paths, "description",
            "Include package DB and device path details in the result.");

        cJSON *persist = cJSON_AddObjectToObject(props, "persist_context");
        cJSON_AddStringToObject(persist, "type", "boolean");
        cJSON_AddStringToObject(persist, "description",
            "Refresh workspace/context/host inventory artifacts (default true).");
    }
    return schema;
}

static void
host_inventory_destroy(sc_tool_t *self)
{
    if (!self) return;
    host_tool_data_free((host_tool_data_t *)self->data);
    free(self);
}

static sc_tool_result_t *
host_inventory_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    host_tool_data_t *d = self ? self->data : NULL;
    int include_paths = sc_json_get_bool(args, "include_paths", 0);
    int persist_context = sc_json_get_bool(args, "persist_context", 1);

    cJSON *root = build_host_inventory_json(include_paths,
                                            d ? d->sandbox_enabled : 0);
    if (!root)
        return sc_tool_result_error("failed to build host inventory");

    cJSON_AddStringToObject(root, "artifact_dir", HOST_CTX_DIR);
    if (persist_context) {
        int ok = d && d->workspace &&
                 sc_host_refresh_inventory_artifacts(d->workspace, d->idx,
                                                     d->sandbox_enabled) == 0;
        cJSON_AddBoolToObject(root, "context_refreshed", ok);
    }

    char *json = cJSON_Print(root);
    cJSON_Delete(root);
    if (!json)
        return sc_tool_result_error("failed to render host inventory");

    sc_tool_result_t *result = sc_tool_result_user(json);
    free(json);
    return result;
}

static cJSON *
host_trend_parameters(sc_tool_t *self)
{
    (void)self;
    cJSON *schema = sc_schema_new();
    cJSON *props = cJSON_GetObjectItem(schema, "properties");
    if (props) {
        cJSON *hours = cJSON_AddObjectToObject(props, "period_hours");
        cJSON_AddStringToObject(hours, "type", "integer");
        cJSON_AddStringToObject(hours, "description",
            "Look-back window in hours (default 24, max 720).");

        cJSON *samples = cJSON_AddObjectToObject(props, "max_samples");
        cJSON_AddStringToObject(samples, "type", "integer");
        cJSON_AddStringToObject(samples, "description",
            "Maximum retained samples to analyze (default 288, max 1000).");

        cJSON *record = cJSON_AddObjectToObject(props, "record_sample");
        cJSON_AddStringToObject(record, "type", "boolean");
        cJSON_AddStringToObject(record, "description",
            "Record a fresh sample before analyzing trends (default true).");
    }
    return schema;
}

static void
host_trend_destroy(sc_tool_t *self)
{
    if (!self) return;
    host_tool_data_free((host_tool_data_t *)self->data);
    free(self);
}

static sc_tool_result_t *
host_trend_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
#if !SC_ENABLE_HOST_METRICS
    (void)self; (void)args; (void)ctx;
    return sc_tool_result_error(
        "host metrics retention not built (SC_ENABLE_HOST_METRICS=n)");
#else
    (void)ctx;
    host_tool_data_t *d = self ? self->data : NULL;
    if (!d || !d->workspace)
        return sc_tool_result_error("host trend tool not initialized");

    int period_hours = sc_json_get_int(args, "period_hours",
                                       HOST_TREND_DEFAULT_HOURS);
    int max_samples = sc_json_get_int(args, "max_samples",
                                      HOST_TREND_DEFAULT_MAX_SAMPLES);
    int record_sample = sc_json_get_bool(args, "record_sample", 1);

    if (period_hours < 1) period_hours = HOST_TREND_DEFAULT_HOURS;
    if (period_hours > HOST_TREND_MAX_HOURS) period_hours = HOST_TREND_MAX_HOURS;
    if (max_samples < 1) max_samples = HOST_TREND_DEFAULT_MAX_SAMPLES;
    if (max_samples > HOST_TREND_MAX_SAMPLES) max_samples = HOST_TREND_MAX_SAMPLES;

    if (record_sample)
        sc_host_record_sample(d->workspace, 0);

    sqlite3 *db = NULL;
    if (host_db_open(d->workspace, &db) != 0)
        return sc_tool_result_error("failed to open host metrics database");

    host_sample_t *samples = NULL;
    int count = 0;
    int rc = load_recent_samples(db, period_hours, max_samples, &samples, &count);
    host_db_close(db);
    if (rc != 0) {
        free(samples);
        return sc_tool_result_error("failed to query host metrics");
    }
    if (count == 0) {
        free(samples);
        return sc_tool_result_new("No retained host samples yet.");
    }

    cJSON *root = build_host_trend_json(samples, count, period_hours);
    free(samples);
    if (!root)
        return sc_tool_result_error("failed to build host trend report");

    char *json = cJSON_Print(root);
    cJSON_Delete(root);
    if (!json)
        return sc_tool_result_error("failed to render host trend report");

    sc_tool_result_t *result = sc_tool_result_user(json);
    free(json);
    return result;
#endif /* SC_ENABLE_HOST_METRICS */
}

sc_tool_t *
sc_tool_host_status_new(const char *workspace, int sandbox_enabled)
{
    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    host_tool_data_t *d = host_tool_data_new(workspace, NULL,
                                             sandbox_enabled);
    if (!d) {
        free(t);
        return NULL;
    }

    t->name = "host_status";
    t->description =
        "Return a live read-only snapshot of this host and the running smolclaw process. "
        "Use for CPU load, memory, disk, FD count, uptime, thermal, and camera-device checks.";
    t->parameters = host_status_parameters;
    t->execute = host_status_execute;
    t->destroy = host_status_destroy;
    t->needs_confirm = 0;
    t->data = d;
    return t;
}

sc_tool_t *
sc_tool_host_inventory_new(const char *workspace, sc_memory_index_t *idx,
                           int sandbox_enabled)
{
    host_tool_data_t *d = host_tool_data_new(workspace, idx,
                                             sandbox_enabled);
    if (!d) return NULL;

    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) {
        host_tool_data_free(d);
        return NULL;
    }

    t->name = "host_inventory";
    t->description =
        "Capture slower-changing host inventory and refresh searchable context docs. "
        "Use for OS, board, CPU, memory size, camera stack, package manager, and key package versions.";
    t->parameters = host_inventory_parameters;
    t->execute = host_inventory_execute;
    t->destroy = host_inventory_destroy;
    t->needs_confirm = 0;
    t->data = d;
    return t;
}

sc_tool_t *
sc_tool_host_trend_new(const char *workspace)
{
    host_tool_data_t *d = host_tool_data_new(workspace, NULL, 0);
    if (!d) return NULL;

    sc_tool_t *t = calloc(1, sizeof(*t));
    if (!t) {
        host_tool_data_free(d);
        return NULL;
    }

    t->name = "host_trend";
    t->description =
        "Analyze retained host samples for RSS, FD, memory, load, disk, and thermal trends. "
        "Use to spot possible leaks or resource pressure over time.";
    t->parameters = host_trend_parameters;
    t->execute = host_trend_execute;
    t->destroy = host_trend_destroy;
    t->needs_confirm = 0;
    t->data = d;
    return t;
}
