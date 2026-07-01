/*
 * util/sandbox.c - OS-level sandbox for exec children (Landlock + seccomp-bpf)
 *
 * Applied after fork(), before exec() to restrict filesystem access and
 * block dangerous syscalls. Graceful fallback on unsupported kernels.
 */

#ifdef __linux__

/* O_PATH requires _GNU_SOURCE on glibc */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "util/sandbox.h"
#include "logger.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

/* SECCOMP_RET_KILL_PROCESS is Linux 4.14+; define it if building against older
 * UAPI headers so a wrong-ABI syscall still terminates the process. */
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

/* Map compile-time arch to AUDIT_ARCH_* for seccomp BPF filter.
 * The filter checks this at runtime to ensure syscall numbers match. */
#if defined(__x86_64__)
#define SC_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SC_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__arm__)
#define SC_AUDIT_ARCH AUDIT_ARCH_ARM
#endif

/* Defensive guards for syscalls that may not exist on all architectures.
 * Value 0x7fffffff will never match a real syscall number.
 *
 * 32-bit musl (ARM) renames time-related syscalls: settimeofday →
 * settimeofday_time32, clock_settime → clock_settime32. Map them back
 * so the seccomp filter compiles. Also block clock_settime64 on 32-bit
 * since that's what musl actually uses. */
#ifndef __NR_kexec_file_load
#define __NR_kexec_file_load 0x7fffffff
#endif

#ifndef __NR_settimeofday
#ifdef __NR_settimeofday_time32
#define __NR_settimeofday __NR_settimeofday_time32
#else
#define __NR_settimeofday 0x7fffffff
#endif
#endif

#ifndef __NR_clock_settime
#ifdef __NR_clock_settime32
#define __NR_clock_settime __NR_clock_settime32
#else
#define __NR_clock_settime 0x7fffffff
#endif
#endif

#define LOG_TAG "sandbox"

/* ========================================================================
 * Landlock syscall wrappers (glibc on Debian 12 has no wrappers)
 * ======================================================================== */

static int ll_create_ruleset(struct landlock_ruleset_attr *attr, size_t size,
                             uint32_t flags)
{
    return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static int ll_add_rule(int ruleset_fd, enum landlock_rule_type type,
                       void *attr, uint32_t flags)
{
    return (int)syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}

static int ll_restrict_self(int ruleset_fd, uint32_t flags)
{
    return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

/* ========================================================================
 * Landlock filesystem sandbox
 * ======================================================================== */

/* Full read-write access (workspace, tmp) */
#define LL_ACCESS_RW ( \
    LANDLOCK_ACCESS_FS_EXECUTE      | \
    LANDLOCK_ACCESS_FS_WRITE_FILE   | \
    LANDLOCK_ACCESS_FS_READ_FILE    | \
    LANDLOCK_ACCESS_FS_READ_DIR     | \
    LANDLOCK_ACCESS_FS_REMOVE_DIR   | \
    LANDLOCK_ACCESS_FS_REMOVE_FILE  | \
    LANDLOCK_ACCESS_FS_MAKE_CHAR    | \
    LANDLOCK_ACCESS_FS_MAKE_DIR     | \
    LANDLOCK_ACCESS_FS_MAKE_REG     | \
    LANDLOCK_ACCESS_FS_MAKE_SOCK    | \
    LANDLOCK_ACCESS_FS_MAKE_FIFO    | \
    LANDLOCK_ACCESS_FS_MAKE_BLOCK   | \
    LANDLOCK_ACCESS_FS_MAKE_SYM     | \
    LANDLOCK_ACCESS_FS_REFER        )

/* Read + execute (system binary dirs) */
#define LL_ACCESS_RX ( \
    LANDLOCK_ACCESS_FS_EXECUTE    | \
    LANDLOCK_ACCESS_FS_READ_FILE  | \
    LANDLOCK_ACCESS_FS_READ_DIR   )

/* Read only (config dirs like /etc) */
#define LL_ACCESS_RO ( \
    LANDLOCK_ACCESS_FS_READ_FILE  | \
    LANDLOCK_ACCESS_FS_READ_DIR   )

/* Read + write for device nodes */
#define LL_ACCESS_DEV_RW ( \
    LANDLOCK_ACCESS_FS_READ_FILE  | \
    LANDLOCK_ACCESS_FS_WRITE_FILE )

/* Read only for device nodes */
#define LL_ACCESS_DEV_RO ( \
    LANDLOCK_ACCESS_FS_READ_FILE  )

/* Add a Landlock path rule.
 * mandatory=1: fail closed if path missing or ll_add_rule fails.
 * mandatory=0: silently skip missing optional system paths. */
static int ll_add_path_rule(int ruleset_fd, const char *path, uint64_t access,
                            int mandatory)
{
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        if (mandatory) {
            SC_LOG_WARN(LOG_TAG, "mandatory path unavailable: %s: %s",
                        path, strerror(errno));
            return -1;
        }
        return 0;  /* optional path doesn't exist on this system — skip */
    }

    struct landlock_path_beneath_attr attr = {
        .allowed_access = access,
        .parent_fd = fd,
    };
    int rc = ll_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
    close(fd);
    if (rc < 0) {
        if (mandatory) {
            SC_LOG_WARN(LOG_TAG, "landlock add_rule failed for %s: %s",
                        path, strerror(errno));
            return -1;
        }
        SC_LOG_WARN(LOG_TAG, "landlock add_rule skipped for %s: %s",
                    path, strerror(errno));
        return 0;
    }
    return 0;
}

static int apply_landlock(const sc_sandbox_opts_t *opts)
{
    /* Probe Landlock ABI version */
    int abi = ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        if (errno == ENOSYS || errno == EOPNOTSUPP) {
            SC_LOG_WARN(LOG_TAG, "Landlock not available (kernel too old or disabled)");
            return 0;  /* graceful fallback */
        }
        return -1;
    }

    /* ABI v1 has all the access rights we need; v2 adds REFER.
     * Mask to what the running kernel supports. */
    uint64_t all_access = LL_ACCESS_RW;
    if (abi < 2)
        all_access &= ~LANDLOCK_ACCESS_FS_REFER;

    struct landlock_ruleset_attr rs_attr = {
        .handled_access_fs = all_access,
    };
    int ruleset_fd = ll_create_ruleset(&rs_attr, sizeof(rs_attr), 0);
    if (ruleset_fd < 0) {
        SC_LOG_WARN(LOG_TAG, "Landlock create_ruleset failed: %s", strerror(errno));
        return -1;
    }

    /* Mask path rules to what the ruleset handles */
    uint64_t rw = LL_ACCESS_RW & all_access;
    uint64_t rx = LL_ACCESS_RX & all_access;
    uint64_t ro = LL_ACCESS_RO & all_access;
    uint64_t dev_rw = LL_ACCESS_DEV_RW & all_access;
    uint64_t dev_ro = LL_ACCESS_DEV_RO & all_access;

    /* Workspace access: if per-server capabilities are set, use them
     * instead of blanket workspace rw. Otherwise default to full workspace. */
    if (opts->cap_fs_read_count > 0 || opts->cap_fs_write_count > 0) {
        /* Capability mode: explicit paths only */
        for (int i = 0; i < opts->cap_fs_read_count; i++) {
            if (ll_add_path_rule(ruleset_fd, opts->cap_fs_read[i], ro, 1) != 0)
                goto landlock_fail;
        }
        for (int i = 0; i < opts->cap_fs_write_count; i++) {
            if (ll_add_path_rule(ruleset_fd, opts->cap_fs_write[i], rw, 1) != 0)
                goto landlock_fail;
        }
    } else if (opts->workspace) {
        /* Default: blanket workspace rw */
        if (ll_add_path_rule(ruleset_fd, opts->workspace, rw, 1) != 0)
            goto landlock_fail;
    }

    /* Temp dir: full rw (mandatory — created by exec child before sandbox) */
    {
        const char *tmpdir = opts->tmpdir ? opts->tmpdir : "/tmp";
        if (ll_add_path_rule(ruleset_fd, tmpdir, rw, 1) != 0)
            goto landlock_fail;
    }

    /* System binary dirs: read + execute */
    static const char *rx_paths[] = {
        "/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", NULL
    };
    for (int i = 0; rx_paths[i]; i++)
        ll_add_path_rule(ruleset_fd, rx_paths[i], rx, 0);

    /* Extra binary dir (e.g. ~/.local/bin for user-installed MCP servers) */
    if (opts->bin_dir)
        ll_add_path_rule(ruleset_fd, opts->bin_dir, rx, 0);

    /* Config dirs: read only */
    ll_add_path_rule(ruleset_fd, "/etc", ro, 0);

    /* Kernel/system views for read-only host introspection */
    ll_add_path_rule(ruleset_fd, "/proc", ro, 0);
    ll_add_path_rule(ruleset_fd, "/sys", ro, 0);

    /* Device nodes */
    ll_add_path_rule(ruleset_fd, "/dev/null", dev_rw, 0);
    ll_add_path_rule(ruleset_fd, "/dev/zero", dev_ro, 0);
    ll_add_path_rule(ruleset_fd, "/dev/urandom", dev_ro, 0);
    ll_add_path_rule(ruleset_fd, "/dev/random", dev_ro, 0);
    ll_add_path_rule(ruleset_fd, "/dev/tty", dev_rw, 0);
    ll_add_path_rule(ruleset_fd, "/dev/pts", dev_rw, 0);

    /* Enforce */
    if (ll_restrict_self(ruleset_fd, 0) != 0) {
        SC_LOG_WARN(LOG_TAG, "Landlock restrict_self failed: %s", strerror(errno));
        close(ruleset_fd);
        return -1;
    }

    close(ruleset_fd);
    return 0;

landlock_fail:
    close(ruleset_fd);
    return -1;
}

/* ========================================================================
 * seccomp-bpf syscall denylist
 * ======================================================================== */

/*
 * BPF program layout (static, all syscall numbers known at compile time):
 * [0]  Load arch
 * [1]  JEQ SC_AUDIT_ARCH → skip next insn
 * [2]  ALLOW (wrong-arch bail — defense-in-depth if binary runs under QEMU
 *       for a different arch, preventing wrong syscall numbers from matching)
 * [3]  Load syscall number
 * [4..4+N-1] N JEQ checks → ERRNO (at 4+N+1)
 * [4+N] ALLOW (default)
 * [4+N+1] ERRNO(EPERM)
 *
 * N = SC_SECCOMP_NSYSCALLS (26 on 64-bit, 27 on 32-bit ARM which adds
 * clock_settime64 — the syscall musl actually uses on 32-bit).
 *
 * __NR_* macros resolve to correct per-arch values at compile time.
 * Supported: x86_64, aarch64, armv7l. Unsupported arches skip seccomp.
 */

#ifdef SC_AUDIT_ARCH

/*
 * KNOWN LIMITATION: This is a denylist (block specific syscalls, allow all
 * others). New kernel syscalls are automatically allowed. For high-security
 * deployments, consider an allowlist-based seccomp policy instead. The
 * denylist approach is chosen here for broad compatibility — an allowlist
 * would break many common tools (git, compilers, package managers, etc.).
 *
 * The filter is built at runtime (task 4.2) so per-MCP-server capabilities can
 * vary the denied set: the base list is always blocked; cap_no_process and
 * cap_no_network append their syscall sets. With no capabilities set, the
 * resulting filter is equivalent in effect to the historical static denylist.
 */

/* Base denylist — blocked for every sandboxed child. clock_settime64 is added
 * on 32-bit ARM (the syscall musl actually uses there). */
static const int sc_seccomp_base[] = {
    __NR_mount, __NR_umount2, __NR_pivot_root, __NR_reboot,
    __NR_kexec_load, __NR_kexec_file_load, __NR_init_module,
    __NR_finit_module, __NR_delete_module, __NR_ptrace,
    __NR_process_vm_readv, __NR_process_vm_writev, __NR_swapon,
    __NR_swapoff, __NR_settimeofday, __NR_clock_settime,
    __NR_sethostname, __NR_setdomainname, __NR_bpf,
    __NR_perf_event_open, __NR_userfaultfd, __NR_move_pages,
    __NR_migrate_pages, __NR_keyctl, __NR_request_key, __NR_add_key,
#if defined(__arm__)
    __NR_clock_settime64,
#endif
};

/* Process-creation syscalls — appended when cap_no_process is set.
 * fork/vfork do not exist on aarch64 (it uses clone); clone3 is recent. */
static const int sc_seccomp_no_process[] = {
    __NR_execve,
#ifdef __NR_execveat
    __NR_execveat,
#endif
#ifdef __NR_fork
    __NR_fork,
#endif
#ifdef __NR_vfork
    __NR_vfork,
#endif
    __NR_clone,
#ifdef __NR_clone3
    __NR_clone3,
#endif
};

/* Network syscalls — appended when cap_no_network is set. socketcall is the
 * legacy multiplexer on 32-bit arches; absent on x86_64/aarch64. */
static const int sc_seccomp_no_network[] = {
    __NR_socket, __NR_connect,
#ifdef __NR_socketcall
    __NR_socketcall,
#endif
};

#define SC_ARRLEN(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* Build and install a seccomp-bpf denylist tailored to `opts`.
 *
 * Filter layout (BPF):
 *   [0] load arch; [1] if correct-arch skip to [3] else fall to [2] KILL;
 *   [2] KILL_PROCESS (wrong-ABI syscall — i386/x32 on x86-64 — is an escape
 *       attempt: seccomp can't meaningfully filter numbers across ABIs, so
 *       deny hard instead of the old fail-open ALLOW);
 *   [3] load nr; [4..4+N-1] one JEQ per blocked syscall jumping to ERRNO;
 *   [4+N] ALLOW (default); [4+N+1] ERRNO(EPERM).
 * A matching syscall at index i jumps (N - i) forward to reach ERRNO. */
static int apply_seccomp(const sc_sandbox_opts_t *opts)
{
    int blocked[SC_ARRLEN(sc_seccomp_base)
                + SC_ARRLEN(sc_seccomp_no_process)
                + SC_ARRLEN(sc_seccomp_no_network)];
    int n = 0;
    for (int i = 0; i < SC_ARRLEN(sc_seccomp_base); i++)
        blocked[n++] = sc_seccomp_base[i];
    if (opts && opts->cap_no_process)
        for (int i = 0; i < SC_ARRLEN(sc_seccomp_no_process); i++)
            blocked[n++] = sc_seccomp_no_process[i];
    if (opts && opts->cap_no_network)
        for (int i = 0; i < SC_ARRLEN(sc_seccomp_no_network); i++)
            blocked[n++] = sc_seccomp_no_network[i];

    struct sock_filter filter[6 + SC_ARRLEN(sc_seccomp_base)
                              + SC_ARRLEN(sc_seccomp_no_process)
                              + SC_ARRLEN(sc_seccomp_no_network)];
    int k = 0;
    filter[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                      offsetof(struct seccomp_data, arch));
    filter[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                      SC_AUDIT_ARCH, 1, 0);
    /* Wrong arch (mismatch) falls through here: kill, do not ALLOW. */
    filter[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                      SECCOMP_RET_KILL_PROCESS);
    filter[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                      offsetof(struct seccomp_data, nr));
    for (int i = 0; i < n; i++)
        filter[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                          blocked[i], (n - i), 0);
    filter[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    filter[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                      SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));

    struct sock_fprog fprog = {
        .len = (unsigned short)k,
        .filter = filter,
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog) != 0) {
        if (errno == EINVAL || errno == ENOSYS) {
            SC_LOG_WARN(LOG_TAG, "seccomp-bpf not available: %s", strerror(errno));
            return 0;  /* graceful fallback */
        }
        SC_LOG_WARN(LOG_TAG, "seccomp install failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

#else /* !SC_AUDIT_ARCH */

static int apply_seccomp(const sc_sandbox_opts_t *opts)
{
    (void)opts;
    SC_LOG_WARN(LOG_TAG, "seccomp-bpf not supported on this architecture — skipping");
    return 0;
}

#endif /* SC_AUDIT_ARCH */

/* ========================================================================
 * Public API
 * ======================================================================== */

int sc_sandbox_apply(const sc_sandbox_opts_t *opts)
{
    if (!opts)
        return -1;

    /* PR_SET_NO_NEW_PRIVS required for both Landlock and seccomp */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        SC_LOG_WARN(LOG_TAG, "PR_SET_NO_NEW_PRIVS failed: %s", strerror(errno));
        return -1;
    }

    int rc = 0;

    /* Apply Landlock (filesystem restrictions) */
    if (apply_landlock(opts) != 0) {
        SC_LOG_WARN(LOG_TAG, "Landlock setup failed — continuing without filesystem sandbox");
        rc = -1;
    }

    /* Apply seccomp (syscall restrictions) */
    if (apply_seccomp(opts) != 0) {
        SC_LOG_WARN(LOG_TAG, "seccomp setup failed — continuing without syscall sandbox");
        rc = -1;
    }

    return rc;
}

int sc_sandbox_available(void)
{
    int flags = 0;

    /* Probe Landlock */
    int abi = (int)syscall(__NR_landlock_create_ruleset, NULL, 0,
                           LANDLOCK_CREATE_RULESET_VERSION);
    if (abi >= 0)
        flags |= SC_SANDBOX_LANDLOCK;

    /* Probe seccomp — check if PR_SET_SECCOMP is accepted.
     * We can't actually install a filter without NO_NEW_PRIVS, but we
     * can check via prctl(PR_GET_SECCOMP) which returns 0 if available. */
    if (prctl(PR_GET_SECCOMP) >= 0)
        flags |= SC_SANDBOX_SECCOMP;

    return flags;
}

#else /* !__linux__ */

#include "util/sandbox.h"

int sc_sandbox_apply(const sc_sandbox_opts_t *opts)
{
    (void)opts;
    return 0;  /* no-op on non-Linux */
}

int sc_sandbox_available(void)
{
    return 0;  /* nothing available */
}

#endif /* __linux__ */
