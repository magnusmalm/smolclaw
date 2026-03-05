/*
 * tools/exec_common.c - Shared exec infrastructure
 *
 * Deny pattern matching, environment sanitization, and command guard
 * logic shared between shell.c and background.c.
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

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

void sc_exec_build_safe_envp(char *envp[SC_EXEC_MAX_SAFE_ENV])
{
    int n = 0;
    for (int i = 0; safe_env_keys[i]; i++) {
        const char *val = getenv(safe_env_keys[i]);
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

/* ---------- Deny patterns ---------- */

int sc_deny_list_init(sc_deny_list_t *dl)
{
    dl->count = (int)SC_DENY_PATTERN_COUNT;
    dl->patterns = calloc((size_t)dl->count, sizeof(regex_t));
    if (!dl->patterns) return -1;

    for (int i = 0; i < dl->count; i++) {
        int rc = regcomp(&dl->patterns[i], sc_deny_patterns[i],
                         REG_EXTENDED | REG_NOSUB);
        if (rc != 0) {
            SC_LOG_WARN("exec", "Failed to compile deny pattern %d", i);
        }
    }
    return 0;
}

void sc_deny_list_free(sc_deny_list_t *dl)
{
    if (!dl->patterns) return;
    for (int i = 0; i < dl->count; i++)
        regfree(&dl->patterns[i]);
    free(dl->patterns);
    dl->patterns = NULL;
    dl->count = 0;
}

int sc_deny_list_matches(const sc_deny_list_t *dl, const char *cmd)
{
    for (int i = 0; i < dl->count; i++) {
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

        int allowed = 0;
        for (int i = 0; i < allowed_count; i++) {
            if (strlen(allowed_commands[i]) == word_len &&
                strncmp(start, allowed_commands[i], word_len) == 0) {
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
        if (err) { free(normalized); return err; }
    }

    if (sc_deny_list_matches(deny, normalized)) {
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

void sc_exec_child(const char *command, const char *working_dir,
                   const char *workspace, int sandbox_enabled,
                   int pipe_write_fd)
{
    dup2(pipe_write_fd, STDOUT_FILENO);
    dup2(pipe_write_fd, STDERR_FILENO);
    close(pipe_write_fd);

    /* Close all inherited FDs (bus pipes, sockets, audit log, etc.) */
    int max_fd = (int)sysconf(_SC_OPEN_MAX);
    if (max_fd < 0) max_fd = 1024;
    for (int fd = 3; fd < max_fd; fd++)
        close(fd);

    /* OS-level sandbox (Landlock + seccomp).
     * Create per-process tmpdir to avoid sharing /tmp with other users. */
    char proc_tmp[] = "/tmp/sc_exec_XXXXXX";
    if (sandbox_enabled) {
        const char *tmpdir = mkdtemp(proc_tmp) ? proc_tmp : "/tmp";
        sc_sandbox_opts_t sandbox_opts = {
            .workspace = workspace,
            .tmpdir = tmpdir,
        };
        sc_sandbox_apply(&sandbox_opts);
        /* Point TMPDIR at per-process dir so child programs use it */
        setenv("TMPDIR", tmpdir, 1);
    }

    if (working_dir && *working_dir)
        if (chdir(working_dir) != 0) { /* ignore */ }

    /* Strip non-ASCII from command before exec so that the shell sees
     * the same bytes the deny patterns analyzed (C-2 hardening). */
    char *safe_cmd = sc_strdup(command);
    if (safe_cmd) {
        char *dst = safe_cmd, *src = safe_cmd;
        while (*src) {
            if (!((unsigned char)*src & 0x80))
                *dst++ = *src;
            src++;
        }
        *dst = '\0';
    }

    char *envp[SC_EXEC_MAX_SAFE_ENV];
    sc_exec_build_safe_envp(envp);
    execle("/bin/sh", "sh", "-c", safe_cmd ? safe_cmd : command,
           (char *)NULL, envp);
    _exit(127);
}

void sc_exec_data_free(sc_deny_list_t *deny, char **allowed_commands,
                       int allowed_count, char *workspace)
{
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
