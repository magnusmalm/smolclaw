/*
 * tools/exec_common.c - Shared exec infrastructure
 *
 * Deny pattern matching, environment sanitization, and command guard
 * logic shared between shell.c and background.c.
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "tools/exec_common.h"
#include "tools/deny_patterns.h"
#include "util/str.h"
#include "util/sandbox.h"
#include "logger.h"

/* ---------- Safe environment ---------- */

static const char *safe_env_keys[] = {
    "PATH", "HOME", "TERM", "LANG", "LC_ALL", "USER",
    "SHELL", "LOGNAME", "TMPDIR", "TZ", NULL
};

void sc_exec_build_safe_envp(char *envp[SC_EXEC_MAX_SAFE_ENV],
                             const char *tmpdir_override)
{
    int n = 0;
    for (int i = 0; safe_env_keys[i]; i++) {
        const char *val =
            (tmpdir_override && strcmp(safe_env_keys[i], "TMPDIR") == 0)
                ? tmpdir_override
                : getenv(safe_env_keys[i]);
        if (!val) continue;
        size_t klen = strlen(safe_env_keys[i]);
        size_t vlen = strlen(val);
        char *entry = malloc(klen + 1 + vlen + 1);
        if (entry) {
            memcpy(entry, safe_env_keys[i], klen);
            entry[klen] = '=';
            memcpy(entry + klen + 1, val, vlen + 1);
            envp[n++] = entry;
        }
    }
    envp[n] = NULL;
}

void sc_exec_prepare(const char *command, int sandbox_enabled,
                     sc_exec_prep_t *prep)
{
    memset(prep, 0, sizeof(*prep));
    prep->ok = 1;

    /* ASCII-strip the command in the parent so the shell sees the same bytes
     * the deny patterns analyzed (C-2 hardening) — and so the child does not
     * malloc. */
    prep->safe_cmd = sc_strdup(command);
    if (prep->safe_cmd) {
        char *dst = prep->safe_cmd, *src = prep->safe_cmd;
        while (*src) {
            if (!((unsigned char)*src & 0x80))
                *dst++ = *src;
            src++;
        }
        *dst = '\0';
    } else {
        prep->ok = 0;
    }

    if (sandbox_enabled) {
        /* Per-process tmpdir so the child does not share /tmp with other users.
         * Created here (parent) rather than in the child: mkdtemp is not
         * async-signal-safe. */
        char tmpl[] = "/tmp/sc_exec_XXXXXX";
        if (mkdtemp(tmpl)) {
            snprintf(prep->tmpdir, sizeof(prep->tmpdir), "%s", tmpl);
            /* ~/.local for user-installed tools (cmake, pip packages, …). */
            const char *home = getenv("HOME");
            if (home)
                snprintf(prep->bin_dir, sizeof(prep->bin_dir),
                         "%s/.local", home);
        } else {
            prep->ok = 0;
        }
    }

    sc_exec_build_safe_envp(prep->envp,
        (sandbox_enabled && prep->tmpdir[0]) ? prep->tmpdir : NULL);
}

void sc_exec_prep_free(sc_exec_prep_t *prep)
{
    if (!prep) return;
    free(prep->safe_cmd);
    prep->safe_cmd = NULL;
    for (int i = 0; i < SC_EXEC_MAX_SAFE_ENV && prep->envp[i]; i++) {
        free(prep->envp[i]);
        prep->envp[i] = NULL;
    }
}

/* ---------- Deny patterns ---------- */

static sc_deny_list_t g_deny;
static pthread_once_t g_deny_once = PTHREAD_ONCE_INIT;

static void deny_do_init(void)
{
    sc_deny_list_init(&g_deny);
}

const sc_deny_list_t *sc_deny_list_get(void)
{
    pthread_once(&g_deny_once, deny_do_init);
    return &g_deny;
}

int sc_deny_list_is_initialized(void)
{
    return g_deny.patterns != NULL;
}

int sc_deny_list_init_from(sc_deny_list_t *dl, const char **patterns, int count)
{
    dl->count = count;
    dl->patterns = calloc((size_t)count, sizeof(regex_t));
    dl->compiled = calloc((size_t)count, sizeof(int));
    if (!dl->patterns || !dl->compiled) {
        free(dl->patterns);
        free(dl->compiled);
        dl->patterns = NULL;
        dl->compiled = NULL;
        dl->count = 0;
        return -1;
    }

    for (int i = 0; i < count; i++) {
        int rc = regcomp(&dl->patterns[i], patterns[i],
                         REG_EXTENDED | REG_NOSUB);
        if (rc != 0) {
            SC_LOG_WARN("exec", "Failed to compile deny pattern %d", i);
            for (int j = 0; j < i; j++)
                regfree(&dl->patterns[j]);
            free(dl->patterns);
            free(dl->compiled);
            dl->patterns = NULL;
            dl->compiled = NULL;
            dl->count = 0;
            return -1;
        }
        dl->compiled[i] = 1;
    }
    return 0;
}

int sc_deny_list_init(sc_deny_list_t *dl)
{
    return sc_deny_list_init_from(dl, sc_deny_patterns,
                                  (int)SC_DENY_PATTERN_COUNT);
}

void sc_deny_list_free(sc_deny_list_t *dl)
{
    if (!dl->patterns) return;
    for (int i = 0; i < dl->count; i++) {
        if (dl->compiled && dl->compiled[i])
            regfree(&dl->patterns[i]);
    }
    free(dl->patterns);
    free(dl->compiled);
    dl->patterns = NULL;
    dl->compiled = NULL;
    dl->count = 0;
}

int sc_deny_list_matches(const sc_deny_list_t *dl, const char *cmd)
{
    for (int i = 0; i < dl->count; i++) {
        if (!dl->compiled || !dl->compiled[i])
            continue;
        if (regexec(&dl->patterns[i], cmd, 0, NULL, 0) == 0)
            return 1;
    }
    return 0;
}

/* ---------- Command guard ---------- */

static int is_cmd_separator(char c)
{
    return c == ';' || c == '|' || c == '&';
}

/* Normalize command for deny pattern matching: lowercase, newlines→';',
 * strip non-ASCII bytes. Returns malloc'd string. Caller owns. */
char *sc_exec_normalize_command(const char *command)
{
    char *lower = sc_strdup(command);
    if (!lower) return NULL;

    for (char *p = lower; *p; p++)
        *p = (char)tolower((unsigned char)*p);

    /* Normalize newlines and other line separators to semicolons
     * (sh -c treats \n as command separator; \r, \v, \f can also separate) */
    for (char *p = lower; *p; p++) {
        if (*p == '\n' || *p == '\r' || *p == '\v' || *p == '\f') *p = ';';
    }

    /* Strip non-ASCII bytes — prevents zero-width Unicode chars from
     * breaking deny patterns. */
    char *dst = lower, *src = lower;
    while (*src) {
        if (!((unsigned char)*src & 0x80))
            *dst++ = *src;
        src++;
    }
    *dst = '\0';

    return lower;
}

/* Check every command segment's first word is in allowed_commands[].
 * Returns NULL if allowed, or static error string if blocked. */
static const char *check_allowlist(const char *lower,
                                    char *const *allowed_commands,
                                    int allowed_count)
{
    const char *seg = lower;
    while (*seg) {
        /* Skip whitespace and separators */
        while (*seg && (isspace((unsigned char)*seg) || is_cmd_separator(*seg)))
            seg++;
        if (!*seg) break;

        /* Extract first word of segment (strip leading quotes) */
        while (*seg == '"' || *seg == '\'') seg++;
        const char *start = seg;
        while (*seg && !isspace((unsigned char)*seg) && !is_cmd_separator(*seg)
               && *seg != '(' && *seg != '<' && *seg != '>'
               && *seg != '$' && *seg != '`' && *seg != '\\'
               && *seg != '"' && *seg != '\'') seg++;
        size_t word_len = (size_t)(seg - start);
        if (word_len == 0) { seg++; continue; }

        /* Skip redirect targets: purely numeric words (FD numbers like
         * "2" in "2>&1") and words starting with "/" after ">" (redirect
         * destinations like "/dev/null") are not commands. */
        int is_redirect = 1;
        for (size_t k = 0; k < word_len; k++) {
            if (!isdigit((unsigned char)start[k])) {
                is_redirect = 0;
                break;
            }
        }
        if (is_redirect) {
            /* Skip past the redirect operator */
            while (*seg && (*seg == '>' || *seg == '<' || *seg == '&'
                            || *seg == '!' || isdigit((unsigned char)*seg)))
                seg++;
            continue;
        }

        /* For allowlist matching, strip directory prefix from absolute
         * paths: "/home/user/.local/bin/cmake" → "cmake". */
        const char *basename = start;
        for (const char *s = start; s < start + word_len; s++) {
            if (*s == '/') basename = s + 1;
        }
        size_t base_len = word_len - (size_t)(basename - start);

        int allowed = 0;
        for (int i = 0; i < allowed_count; i++) {
            size_t alen = strlen(allowed_commands[i]);
            if ((alen == word_len && strncmp(start, allowed_commands[i], word_len) == 0) ||
                (alen == base_len && strncmp(basename, allowed_commands[i], base_len) == 0)) {
                allowed = 1;
                break;
            }
        }
        if (!allowed)
            return "Command blocked: not in exec allowlist";

        /* Skip to next separator */
        while (*seg && !is_cmd_separator(*seg)) seg++;
    }
    return NULL;
}

const char *sc_exec_guard_command(const sc_deny_list_t *deny,
                                   const char *command,
                                   int use_allowlist,
                                   char *const *allowed_commands,
                                   int allowed_count,
                                   int restrict_to_workspace)
{
    const sc_deny_list_t *dl = deny ? deny : sc_deny_list_get();
    /* Reject commands with control characters that could cause
     * normalization-vs-execution mismatch (C-2 hardening) */
    for (const char *p = command; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 && c != '\n' && c != '\t')
            return "Command blocked: contains control characters";
    }

    char *normalized = sc_exec_normalize_command(command);
    if (!normalized) return "out of memory";

    if (use_allowlist && allowed_commands) {
        const char *err = check_allowlist(normalized, allowed_commands,
                                          allowed_count);
        if (err) {
            SC_LOG_WARN("exec", "Allowlist blocked: %.200s", command);
            free(normalized);
            return err;
        }
    }

    if (sc_deny_list_matches(dl, normalized)) {
        SC_LOG_WARN("exec", "Deny pattern blocked: %.200s", command);
        free(normalized);
        return "Command blocked by safety guard (dangerous pattern detected)";
    }

    /* Check path traversal on the normalized form */
    if (restrict_to_workspace) {
        if (strstr(normalized, "../") || strstr(normalized, "..\\")) {
            free(normalized);
            return "Command blocked by safety guard (path traversal detected)";
        }
    }
    free(normalized);
    return NULL;
}

/* ---------- Shared child process setup ---------- */

void sc_exec_child(const sc_exec_prep_t *prep, const char *working_dir,
                   const char *workspace, int sandbox_enabled,
                   int pipe_write_fd)
{
    dup2(pipe_write_fd, STDOUT_FILENO);
    dup2(pipe_write_fd, STDERR_FILENO);
    close(pipe_write_fd);

    /* Close inherited FDs (bus pipes, sockets, audit log, …). close_range() is
     * a single syscall vs a close()-per-fd loop up to RLIMIT_NOFILE (which can
     * be ~1M on a server). Both paths use only async-signal-safe calls. */
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3, ~0U, 0) != 0)
#endif
    {
        int max_fd = (int)sysconf(_SC_OPEN_MAX);
        if (max_fd < 0) max_fd = 1024;
        for (int fd = 3; fd < max_fd; fd++)
            close(fd);
    }

    /* All non-async-signal-safe work (command strip, envp, mkdtemp, getenv)
     * was done in the parent by sc_exec_prepare(). Bail if it failed. */
    if (!prep || !prep->ok) {
        const char msg[] = "exec: preparation failed, refusing to execute\n";
        (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
        _exit(126);
    }

    /* OS-level sandbox (Landlock + seccomp) — must be applied post-fork in the
     * child; uses the tmpdir/bin_dir the parent prepared. */
    if (sandbox_enabled) {
        sc_sandbox_opts_t sandbox_opts = {
            .workspace = workspace,
            .tmpdir = prep->tmpdir,
            .bin_dir = prep->bin_dir[0] ? prep->bin_dir : NULL,
        };
        if (sc_sandbox_apply(&sandbox_opts) != 0) {
            const char sb_msg[] =
                "sandbox: failed to apply, refusing to execute\n";
            (void)write(STDERR_FILENO, sb_msg, sizeof(sb_msg) - 1);
            _exit(126);
        }
    }

    if (working_dir && *working_dir) {
        if (chdir(working_dir) != 0) {
            const char cd_msg[] = "exec: chdir failed, refusing to execute\n";
            (void)write(STDERR_FILENO, cd_msg, sizeof(cd_msg) - 1);
            _exit(126);
        }
    }

    execle("/bin/sh", "sh", "-c",
           prep->safe_cmd ? prep->safe_cmd : "",
           (char *)NULL, prep->envp);
    _exit(127);
}

void sc_exec_data_free(sc_deny_list_t *deny, char **allowed_commands,
                       int allowed_count, char *workspace)
{
    if (deny)
        sc_deny_list_free(deny);
    for (int i = 0; i < allowed_count; i++)
        free(allowed_commands[i]);
    free(allowed_commands);
    free(workspace);
}

void sc_exec_set_allowlist(int *use_allowlist, char ***allowed_commands,
                           int *allowed_count, int enable,
                           char *const *commands, int count)
{
    *use_allowlist = enable;
    if (commands && count > 0) {
        *allowed_commands = calloc((size_t)count, sizeof(char *));
        if (*allowed_commands) {
            *allowed_count = count;
            for (int i = 0; i < count; i++)
                (*allowed_commands)[i] = sc_strdup(commands[i]);
        }
    }
}
