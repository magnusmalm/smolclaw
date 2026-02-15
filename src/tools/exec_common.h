#ifndef SC_EXEC_COMMON_H
#define SC_EXEC_COMMON_H

#include <regex.h>

/* Safe environment variables for exec children */
#define SC_EXEC_MAX_SAFE_ENV 11

void sc_exec_build_safe_envp(char *envp[SC_EXEC_MAX_SAFE_ENV]);

/* Compiled deny pattern list */
typedef struct {
    regex_t *patterns;
    int count;
} sc_deny_list_t;

int  sc_deny_list_init(sc_deny_list_t *dl);
void sc_deny_list_free(sc_deny_list_t *dl);
int  sc_deny_list_matches(const sc_deny_list_t *dl, const char *cmd);

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
void sc_exec_child(const char *command, const char *working_dir,
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
