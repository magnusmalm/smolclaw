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

/* Add a Landlock path rule. Silently skip missing paths. */
static int ll_add_path_rule(int ruleset_fd, const char *path, uint64_t access)
{
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0)
        return 0;  /* path doesn't exist on this system — skip */

    struct landlock_path_beneath_attr attr = {
        .allowed_access = access,
        .parent_fd = fd,
    };
    int rc = ll_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
    close(fd);
    return rc;
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

    /* Workspace: full rw */
    if (opts->workspace)
        ll_add_path_rule(ruleset_fd, opts->workspace, rw);

    /* Temp dir: full rw */
    const char *tmpdir = opts->tmpdir ? opts->tmpdir : "/tmp";
    ll_add_path_rule(ruleset_fd, tmpdir, rw);

    /* System binary dirs: read + execute */
    static const char *rx_paths[] = {
        "/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", NULL
    };
    for (int i = 0; rx_paths[i]; i++)
        ll_add_path_rule(ruleset_fd, rx_paths[i], rx);

    /* Config dirs: read only */
    ll_add_path_rule(ruleset_fd, "/etc", ro);

    /* /proc: read only */
    ll_add_path_rule(ruleset_fd, "/proc", ro);

    /* Device nodes */
    ll_add_path_rule(ruleset_fd, "/dev/null", dev_rw);
    ll_add_path_rule(ruleset_fd, "/dev/zero", dev_ro);
    ll_add_path_rule(ruleset_fd, "/dev/urandom", dev_ro);
    ll_add_path_rule(ruleset_fd, "/dev/random", dev_ro);
    ll_add_path_rule(ruleset_fd, "/dev/tty", dev_rw);
    ll_add_path_rule(ruleset_fd, "/dev/pts", dev_rw);

    /* Enforce */
    if (ll_restrict_self(ruleset_fd, 0) != 0) {
        SC_LOG_WARN(LOG_TAG, "Landlock restrict_self failed: %s", strerror(errno));
        close(ruleset_fd);
        return -1;
    }

    close(ruleset_fd);
    return 0;
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

/* 32-bit ARM: also block clock_settime64 (musl uses this, not clock_settime) */
#if defined(__arm__)
#define SC_SECCOMP_NSYSCALLS 27
#else
#define SC_SECCOMP_NSYSCALLS 26
#endif

/* Helper macro: JEQ for blocked syscall at position i (0-based among N checks) */
#define SC_SECCOMP_JEQ(nr, i) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), (SC_SECCOMP_NSYSCALLS - (i)), 0)

static struct sock_filter sc_seccomp_filter[] = {
    /* [0] Load architecture */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    /* [1] If correct arch, skip to [3] */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_AUDIT_ARCH, 1, 0),
    /* [2] Wrong arch: allow (defense-in-depth) */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    /* [3] Load syscall number */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* [4..4+N-1] Blocked syscalls (N = SC_SECCOMP_NSYSCALLS) */
    SC_SECCOMP_JEQ(__NR_mount,              0),
    SC_SECCOMP_JEQ(__NR_umount2,            1),
    SC_SECCOMP_JEQ(__NR_pivot_root,         2),
    SC_SECCOMP_JEQ(__NR_reboot,             3),
    SC_SECCOMP_JEQ(__NR_kexec_load,         4),
    SC_SECCOMP_JEQ(__NR_kexec_file_load,    5),
    SC_SECCOMP_JEQ(__NR_init_module,        6),
    SC_SECCOMP_JEQ(__NR_finit_module,       7),
    SC_SECCOMP_JEQ(__NR_delete_module,      8),
    SC_SECCOMP_JEQ(__NR_ptrace,             9),
    SC_SECCOMP_JEQ(__NR_process_vm_readv,   10),
    SC_SECCOMP_JEQ(__NR_process_vm_writev,  11),
    SC_SECCOMP_JEQ(__NR_swapon,             12),
    SC_SECCOMP_JEQ(__NR_swapoff,            13),
    SC_SECCOMP_JEQ(__NR_settimeofday,       14),
    SC_SECCOMP_JEQ(__NR_clock_settime,      15),
    SC_SECCOMP_JEQ(__NR_sethostname,        16),
    SC_SECCOMP_JEQ(__NR_setdomainname,      17),
    SC_SECCOMP_JEQ(__NR_bpf,               18),
    SC_SECCOMP_JEQ(__NR_perf_event_open,    19),
    SC_SECCOMP_JEQ(__NR_userfaultfd,        20),
    SC_SECCOMP_JEQ(__NR_move_pages,         21),
    SC_SECCOMP_JEQ(__NR_migrate_pages,      22),
    SC_SECCOMP_JEQ(__NR_keyctl,             23),
    SC_SECCOMP_JEQ(__NR_request_key,        24),
    SC_SECCOMP_JEQ(__NR_add_key,            25),
#if defined(__arm__)
    SC_SECCOMP_JEQ(__NR_clock_settime64,    26),
#endif
    /* Default: ALLOW */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    /* ERRNO(EPERM) for blocked syscalls */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
};

static int apply_seccomp(void)
{
    struct sock_fprog fprog = {
        .len = (unsigned short)(sizeof(sc_seccomp_filter) / sizeof(sc_seccomp_filter[0])),
        .filter = sc_seccomp_filter,
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

static int apply_seccomp(void)
{
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
    if (apply_seccomp() != 0) {
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
