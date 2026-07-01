#ifndef SC_EXEC_COMMON_H
#define SC_EXEC_COMMON_H

#include <regex.h>
#include <limits.h>

/* Safe environment variables for exec children */
#define SC_EXEC_MAX_SAFE_ENV 11

/* Build a sanitized NULL-terminated envp from the parent's environment. If
 * tmpdir_override is non-NULL it is used as the TMPDIR value (instead of the
 * inherited one). Entries are heap-allocated; free with sc_exec_prep_free or
 * manually. */
void sc_exec_build_safe_envp(char *envp[SC_EXEC_MAX_SAFE_ENV],
                             const char *tmpdir_override);

/* Exec parameters computed in the PARENT before fork(). fork() clones only the
 * calling thread, so any malloc/getenv/setenv/mkdtemp done between fork and
 * exec can deadlock on a lock another thread held at fork time. Building these
 * up front keeps sc_exec_child() to async-signal-safe calls only. */
typedef struct {
    char  *safe_cmd;                    /* ASCII-stripped command (heap)      */
    char  *envp[SC_EXEC_MAX_SAFE_ENV];  /* NULL-terminated; entries heap      */
    char   tmpdir[64];                  /* per-process sandbox tmpdir, "" none */
    char   bin_dir[PATH_MAX];           /* ~/.local for the sandbox, "" none  */
    int    ok;                          /* 0 if preparation failed            */
} sc_exec_prep_t;

/* Build exec parameters (parent side, before fork). Always leaves prep in a
 * valid state; on failure sets prep->ok=0 (sc_exec_child then exits the child). */
void sc_exec_prepare(const char *command, int sandbox_enabled,
                     sc_exec_prep_t *prep);

/* Free heap owned by prep. Call in the PARENT after fork. */
void sc_exec_prep_free(sc_exec_prep_t *prep);

/* Compiled deny pattern list */
typedef struct {
    regex_t *patterns;
    int *compiled;   /* 1 if regcomp succeeded for this slot */
    int count;
} sc_deny_list_t;

const sc_deny_list_t *sc_deny_list_get(void);
int  sc_deny_list_is_initialized(void);
int  sc_deny_list_init(sc_deny_list_t *dl);
/* Testable entry point: compile an arbitrary pattern array. */
int  sc_deny_list_init_from(sc_deny_list_t *dl, const char **patterns, int count);
void sc_deny_list_free(sc_deny_list_t *dl);
int  sc_deny_list_matches(const sc_deny_list_t *dl, const char *cmd);

/* Normalize command: lowercase, newlines→';', strip non-ASCII.
 * Returns malloc'd string. Caller owns. */
char *sc_exec_normalize_command(const char *command);

/*
 * Full command guard: normalize, allowlist check, denylist check, path traversal.
 * Returns NULL if command is allowed, or a static error string if blocked.
 */
const char *sc_exec_guard_command(const sc_deny_list_t *deny,
                                   const char *command,
                                   int use_allowlist,
                                   char *const *allowed_commands,
                                   int allowed_count,
                                   int restrict_to_workspace);

/*
 * Set up child process after fork(): redirect stdout/stderr to pipe_write_fd,
 * close inherited FDs, apply sandbox, chdir to workspace, exec command with
 * sanitized env. Does NOT return on success.
 */
void sc_exec_child(const sc_exec_prep_t *prep, const char *working_dir,
                   const char *workspace, int sandbox_enabled,
                   int pipe_write_fd);

/* Free exec-related data: deny list, allowed commands array, workspace string */
void sc_exec_data_free(sc_deny_list_t *deny, char **allowed_commands,
                       int allowed_count, char *workspace);

/* Copy allowlist into exec data fields */
void sc_exec_set_allowlist(int *use_allowlist, char ***allowed_commands,
                           int *allowed_count, int enable,
                           char *const *commands, int count);

#endif /* SC_EXEC_COMMON_H */
