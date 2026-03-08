/*
 * mcp/client.c - MCP (Model Context Protocol) client
 *
 * Manages an MCP server subprocess. Communication is JSON-RPC 2.0 over
 * newline-delimited JSON on stdin (write) / stdout (read).
 */

#include "mcp/client.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <sys/wait.h>

#include "cJSON.h"
#include "constants.h"
#include "logger.h"
#include "util/str.h"
#include "util/json_helpers.h"
#include "util/sandbox.h"

#define LOG_TAG "mcp"

struct sc_mcp_client {
    char *name;
    pid_t pid;
    int stdin_fd;    /* write to server */
    int stdout_fd;   /* read from server */
    int next_id;
    int alive;
    char *tmpdir;    /* per-process temp dir (to clean up on stop) */
    sc_strbuf_t readbuf;  /* persistent read buffer for partial lines */
};

/* ---------- Internal helpers ---------- */

/* Send a JSON object as a newline-delimited message to the server's stdin */
static int mcp_send(sc_mcp_client_t *client, cJSON *msg)
{
    char *str = cJSON_PrintUnformatted(msg);
    if (!str) return -1;

    size_t len = strlen(str);
    /* Append newline */
    char *buf = malloc(len + 2);
    if (!buf) { free(str); return -1; }
    memcpy(buf, str, len);
    buf[len] = '\n';
    buf[len + 1] = '\0';
    free(str);

    ssize_t written = 0;
    size_t total = len + 1;
    while ((size_t)written < total) {
        ssize_t n = write(client->stdin_fd, buf + written, total - (size_t)written);
        if (n < 0) {
            if (errno == EINTR) continue;
            SC_LOG_ERROR(LOG_TAG, "[%s] write failed: %s", client->name, strerror(errno));
            free(buf);
            return -1;
        }
        written += n;
    }
    free(buf);
    return 0;
}

/* Read a single newline-delimited line from server stdout with timeout.
 * Uses client->readbuf as a persistent buffer so data after the first
 * newline in a read() chunk is not lost.
 * Returns parsed cJSON or NULL on error/timeout. Caller owns result. */
static cJSON *mcp_read_line(sc_mcp_client_t *client, int timeout_ms)
{
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    for (;;) {
        /* Check if there's already a complete line in the persistent buffer */
        if (client->readbuf.data) {
            char *nl = memchr(client->readbuf.data, '\n', client->readbuf.len);
            if (nl) {
                size_t line_len = (size_t)(nl - client->readbuf.data);
                char *line = malloc(line_len + 1);
                if (!line) return NULL;
                memcpy(line, client->readbuf.data, line_len);
                line[line_len] = '\0';

                /* Shift remaining data forward */
                size_t remaining = client->readbuf.len - line_len - 1;
                if (remaining > 0)
                    memmove(client->readbuf.data, nl + 1, remaining);
                client->readbuf.len = remaining;

                /* Skip empty lines */
                if (line[0] == '\0') { free(line); continue; }

                cJSON *json = cJSON_Parse(line);
                free(line);
                if (!json) {
                    SC_LOG_ERROR(LOG_TAG, "[%s] failed to parse JSON response", client->name);
                    return NULL;
                }
                return json;
            }
        }

        /* No complete line — read more data */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        int remaining_ms = (int)((deadline.tv_sec - now.tv_sec) * 1000
                           + (deadline.tv_nsec - now.tv_nsec) / 1000000);
        if (remaining_ms <= 0) break;

        struct pollfd pfd = { .fd = client->stdout_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, remaining_ms);
        if (ret < 0) {
            if (errno == EINTR) continue;
            SC_LOG_ERROR(LOG_TAG, "[%s] poll failed: %s", client->name, strerror(errno));
            return NULL;
        }
        if (ret == 0) break;

        char buf[4096];
        ssize_t n = read(client->stdout_fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            SC_LOG_ERROR(LOG_TAG, "[%s] read failed: %s", client->name, strerror(errno));
            return NULL;
        }
        if (n == 0) {
            SC_LOG_ERROR(LOG_TAG, "[%s] server closed stdout", client->name);
            return NULL;
        }

        /* Append to persistent buffer */
        for (ssize_t i = 0; i < n; i++)
            sc_strbuf_append_char(&client->readbuf, buf[i]);

        /* Cap buffer size to prevent OOM */
        if (client->readbuf.len > SC_MCP_MAX_RESPONSE_SIZE) {
            SC_LOG_ERROR(LOG_TAG, "[%s] response too large", client->name);
            sc_strbuf_free(&client->readbuf);
            sc_strbuf_init(&client->readbuf);
            return NULL;
        }
    }

    SC_LOG_ERROR(LOG_TAG, "[%s] read timeout (%dms)", client->name, timeout_ms);
    return NULL;
}

/* Send a JSON-RPC request and read the response */
static cJSON *mcp_request(sc_mcp_client_t *client, const char *method,
                           cJSON *params, int timeout_ms)
{
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "jsonrpc", "2.0");
    cJSON_AddNumberToObject(req, "id", client->next_id++);
    cJSON_AddStringToObject(req, "method", method);
    if (params)
        cJSON_AddItemToObject(req, "params", params);
    else
        cJSON_AddItemToObject(req, "params", cJSON_CreateObject());

    SC_LOG_DEBUG(LOG_TAG, "[%s] -> %s (id=%d)", client->name, method, client->next_id - 1);

    if (mcp_send(client, req) < 0) {
        cJSON_Delete(req);
        return NULL;
    }
    cJSON_Delete(req);

    int expected_id = client->next_id - 1;

    /* Read response — skip notifications (no "id" field) */
    for (int attempts = 0; attempts < 50; attempts++) {
        cJSON *resp = mcp_read_line(client, timeout_ms);
        if (!resp) return NULL;

        /* JSON-RPC response must have "id" field */
        cJSON *id_item = cJSON_GetObjectItem(resp, "id");
        if (id_item) {
            /* Validate response ID matches our request */
            if (cJSON_IsNumber(id_item) && (int)id_item->valuedouble != expected_id) {
                SC_LOG_WARN(LOG_TAG, "[%s] response id %d doesn't match expected %d, skipping",
                            client->name, (int)id_item->valuedouble, expected_id);
                cJSON_Delete(resp);
                continue;
            }
            return resp;
        }

        /* It's a notification — log and skip */
        const char *notif_method = sc_json_get_string(resp, "method", "unknown");
        SC_LOG_DEBUG(LOG_TAG, "[%s] skipping notification: %s", client->name, notif_method);
        cJSON_Delete(resp);
    }

    SC_LOG_ERROR(LOG_TAG, "[%s] too many notifications without response", client->name);
    return NULL;
}

/* Send a JSON-RPC notification (no id, no response expected) */
static int mcp_notify(sc_mcp_client_t *client, const char *method, cJSON *params)
{
    cJSON *notif = cJSON_CreateObject();
    cJSON_AddStringToObject(notif, "jsonrpc", "2.0");
    cJSON_AddStringToObject(notif, "method", method);
    if (params)
        cJSON_AddItemToObject(notif, "params", params);

    SC_LOG_DEBUG(LOG_TAG, "[%s] -> notification: %s", client->name, method);

    int ret = mcp_send(client, notif);
    cJSON_Delete(notif);
    return ret;
}

/* ---------- Public API ---------- */

sc_mcp_client_t *sc_mcp_client_start(const char *name,
                                      char **command, int command_count,
                                      char **env_keys, char **env_values,
                                      int env_count,
                                      const char *workspace)
{
    if (!name || !command || command_count < 1) return NULL;

    /* Ignore SIGPIPE so pipe writes return EPIPE instead of killing us */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_IGN;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGPIPE, &sa, NULL);
    }

    /* Create pipes: parent writes to child stdin, reads from child stdout */
    int pipe_stdin[2];   /* [0]=child reads, [1]=parent writes */
    int pipe_stdout[2];  /* [0]=parent reads, [1]=child writes */

    if (pipe(pipe_stdin) < 0) {
        SC_LOG_ERROR(LOG_TAG, "[%s] pipe(stdin) failed: %s", name, strerror(errno));
        return NULL;
    }
    if (pipe(pipe_stdout) < 0) {
        SC_LOG_ERROR(LOG_TAG, "[%s] pipe(stdout) failed: %s", name, strerror(errno));
        close(pipe_stdin[0]);
        close(pipe_stdin[1]);
        return NULL;
    }

    /* Create per-process temp dir before fork so parent can track it */
    char *mcp_tmpdir = NULL;
    if (workspace) {
        char mcp_tmp[] = "/tmp/sc_mcp_XXXXXX";
        if (mkdtemp(mcp_tmp))
            mcp_tmpdir = sc_strdup(mcp_tmp);
    }

    pid_t pid = fork();
    if (pid < 0) {
        SC_LOG_ERROR(LOG_TAG, "[%s] fork failed: %s", name, strerror(errno));
        close(pipe_stdin[0]); close(pipe_stdin[1]);
        close(pipe_stdout[0]); close(pipe_stdout[1]);
        if (mcp_tmpdir) { rmdir(mcp_tmpdir); free(mcp_tmpdir); }
        return NULL;
    }

    if (pid == 0) {
        /* Child process */
        close(pipe_stdin[1]);   /* close parent's write end */
        close(pipe_stdout[0]);  /* close parent's read end */

        dup2(pipe_stdin[0], STDIN_FILENO);
        dup2(pipe_stdout[1], STDOUT_FILENO);
        close(pipe_stdin[0]);
        close(pipe_stdout[1]);

        /* Redirect stderr to /dev/null to prevent server logs polluting our stdout */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        /* Close inherited file descriptors (bus pipes, sockets, etc.) */
        int max_fd = (int)sysconf(_SC_OPEN_MAX);
        if (max_fd < 0) max_fd = 1024;
        for (int fd = 3; fd < max_fd; fd++)
            close(fd);

        /* Apply OS-level sandbox (Landlock + seccomp) — restrict MCP
         * server to workspace + per-process tmpdir (C-3, L-5) */
        if (workspace) {
            const char *tmpdir = mcp_tmpdir ? mcp_tmpdir : "/tmp";
            sc_sandbox_opts_t sandbox_opts = {
                .workspace = workspace,
                .tmpdir = tmpdir,
            };
            sc_sandbox_apply(&sandbox_opts);
            setenv("TMPDIR", tmpdir, 1);
        }

        /* Block dangerous environment variables */
        static const char *blocked_env[] = {
            "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
            "PYTHONPATH", "PYTHONSTARTUP", "RUBYLIB", "RUBY_OPT",
            "NODE_PATH", "NODE_OPTIONS", "PERL5LIB", "PERL5OPT",
            "BASH_ENV", "ENV", "SHELLOPTS", "ZDOTDIR",
        };
        for (size_t b = 0; b < sizeof(blocked_env) / sizeof(blocked_env[0]); b++)
            unsetenv(blocked_env[b]);

        /* Set environment variables */
        for (int i = 0; i < env_count; i++) {
            if (!env_keys[i] || !env_values[i]) continue;
            /* Skip if it's a blocked var */
            int skip = 0;
            for (size_t b = 0; b < sizeof(blocked_env) / sizeof(blocked_env[0]); b++) {
                if (strcmp(env_keys[i], blocked_env[b]) == 0) { skip = 1; break; }
            }
            if (!skip)
                setenv(env_keys[i], env_values[i], 1);
        }

        /* Reset SIGPIPE to default for the child process */
        signal(SIGPIPE, SIG_DFL);

        /* Build argv — null-terminated */
        char **argv = calloc((size_t)(command_count + 1), sizeof(char *));
        if (!argv) _exit(127);
        for (int i = 0; i < command_count; i++)
            argv[i] = command[i];
        argv[command_count] = NULL;

        execvp(argv[0], argv);
        _exit(127); /* exec failed */
    }

    /* Parent process */
    close(pipe_stdin[0]);   /* close child's read end */
    close(pipe_stdout[1]);  /* close child's write end */

    sc_mcp_client_t *client = calloc(1, sizeof(*client));
    if (!client) {
        close(pipe_stdin[1]);
        close(pipe_stdout[0]);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return NULL;
    }

    client->name = sc_strdup(name);
    client->pid = pid;
    client->stdin_fd = pipe_stdin[1];
    client->stdout_fd = pipe_stdout[0];
    client->next_id = 1;
    client->alive = 1;
    client->tmpdir = mcp_tmpdir;  /* parent owns cleanup */
    sc_strbuf_init(&client->readbuf);

    SC_LOG_INFO(LOG_TAG, "[%s] started server (pid=%d, cmd=%s)", name, pid, command[0]);

    /* Initialize handshake */
    cJSON *init_params = cJSON_CreateObject();
    cJSON_AddStringToObject(init_params, "protocolVersion", SC_MCP_PROTOCOL_VERSION);
    cJSON *caps = cJSON_AddObjectToObject(init_params, "capabilities");
    (void)caps; /* empty capabilities object */
    cJSON *client_info = cJSON_AddObjectToObject(init_params, "clientInfo");
    cJSON_AddStringToObject(client_info, "name", SC_NAME);
    cJSON_AddStringToObject(client_info, "version", SC_VERSION);

    cJSON *resp = mcp_request(client, "initialize", init_params, SC_MCP_INIT_TIMEOUT_MS);
    if (!resp) {
        SC_LOG_ERROR(LOG_TAG, "[%s] init handshake failed", name);
        sc_mcp_client_free(client);
        return NULL;
    }

    /* Check for error */
    cJSON *error = cJSON_GetObjectItem(resp, "error");
    if (error) {
        const char *msg = sc_json_get_string(error, "message", "unknown error");
        SC_LOG_ERROR(LOG_TAG, "[%s] init error: %s", name, msg);
        cJSON_Delete(resp);
        sc_mcp_client_free(client);
        return NULL;
    }

    cJSON_Delete(resp);

    /* Send initialized notification */
    if (mcp_notify(client, "notifications/initialized", NULL) < 0) {
        SC_LOG_WARN(LOG_TAG, "[%s] failed to send initialized notification", name);
        /* Non-fatal — some servers may not require it */
    }

    SC_LOG_INFO(LOG_TAG, "[%s] init handshake completed", name);
    return client;
}

sc_mcp_tool_def_t *sc_mcp_client_list_tools(sc_mcp_client_t *client, int *out_count)
{
    if (!client || !out_count) return NULL;
    *out_count = 0;

    cJSON *resp = mcp_request(client, "tools/list", NULL, SC_MCP_CALL_TIMEOUT_MS);
    if (!resp) return NULL;

    cJSON *error = cJSON_GetObjectItem(resp, "error");
    if (error) {
        const char *msg = sc_json_get_string(error, "message", "unknown error");
        SC_LOG_ERROR(LOG_TAG, "[%s] tools/list error: %s", client->name, msg);
        cJSON_Delete(resp);
        return NULL;
    }

    cJSON *result = cJSON_GetObjectItem(resp, "result");
    cJSON *tools = result ? cJSON_GetObjectItem(result, "tools") : NULL;
    if (!tools || !cJSON_IsArray(tools)) {
        SC_LOG_WARN(LOG_TAG, "[%s] tools/list returned no tools array", client->name);
        cJSON_Delete(resp);
        return NULL;
    }

    int n = cJSON_GetArraySize(tools);
    if (n == 0) {
        cJSON_Delete(resp);
        return NULL;
    }

    sc_mcp_tool_def_t *defs = calloc((size_t)n, sizeof(sc_mcp_tool_def_t));
    if (!defs) {
        cJSON_Delete(resp);
        return NULL;
    }

    int count = 0;
    cJSON *item;
    cJSON_ArrayForEach(item, tools) {
        const char *tname = sc_json_get_string(item, "name", NULL);
        if (!tname) continue;

        defs[count].name = sc_strdup(tname);
        defs[count].description = sc_strdup(
            sc_json_get_string(item, "description", ""));

        cJSON *schema = cJSON_GetObjectItem(item, "inputSchema");
        if (schema)
            defs[count].input_schema = cJSON_Duplicate(schema, 1);

        count++;
    }

    cJSON_Delete(resp);
    *out_count = count;

    SC_LOG_INFO(LOG_TAG, "[%s] discovered %d tools", client->name, count);
    return defs;
}

char *sc_mcp_client_call_tool(sc_mcp_client_t *client,
                               const char *tool_name, cJSON *args,
                               int *is_error)
{
    if (!client || !tool_name) {
        if (is_error) *is_error = 1;
        return sc_strdup("MCP client error: invalid arguments");
    }
    if (is_error) *is_error = 0;

    if (!sc_mcp_client_is_alive(client)) {
        if (is_error) *is_error = 1;
        return sc_strdup("MCP server is not running");
    }

    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "name", tool_name);
    if (args)
        cJSON_AddItemToObject(params, "arguments", cJSON_Duplicate(args, 1));
    else
        cJSON_AddItemToObject(params, "arguments", cJSON_CreateObject());

    cJSON *resp = mcp_request(client, "tools/call", params, SC_MCP_CALL_TIMEOUT_MS);
    if (!resp) {
        if (is_error) *is_error = 1;
        return sc_strdup("MCP server did not respond");
    }

    /* Check JSON-RPC error */
    cJSON *error = cJSON_GetObjectItem(resp, "error");
    if (error) {
        const char *msg = sc_json_get_string(error, "message", "unknown error");
        if (is_error) *is_error = 1;
        char *result = sc_strdup(msg);
        cJSON_Delete(resp);
        return result;
    }

    cJSON *result = cJSON_GetObjectItem(resp, "result");
    if (!result) {
        cJSON_Delete(resp);
        if (is_error) *is_error = 1;
        return sc_strdup("MCP server returned empty result");
    }

    /* Check isError flag in result */
    int tool_error = sc_json_get_bool(result, "isError", 0);
    if (is_error) *is_error = tool_error;

    /* Extract text content from content array */
    cJSON *content = cJSON_GetObjectItem(result, "content");
    if (content && cJSON_IsArray(content)) {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);

        cJSON *piece;
        cJSON_ArrayForEach(piece, content) {
            const char *type = sc_json_get_string(piece, "type", "");
            if (strcmp(type, "text") == 0) {
                const char *text = sc_json_get_string(piece, "text", "");
                if (sb.len > 0) sc_strbuf_append(&sb, "\n");
                sc_strbuf_append(&sb, text);
            }
        }

        char *text = sc_strbuf_finish(&sb);
        cJSON_Delete(resp);
        return text;
    }

    cJSON_Delete(resp);
    return sc_strdup("");
}

int sc_mcp_client_is_alive(sc_mcp_client_t *client)
{
    if (!client || !client->alive) return 0;

    int status;
    pid_t ret = waitpid(client->pid, &status, WNOHANG);
    if (ret == 0) return 1;  /* still running */

    /* Process exited */
    client->alive = 0;
    if (WIFEXITED(status)) {
        SC_LOG_WARN(LOG_TAG, "[%s] server exited (code=%d)",
                    client->name, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        SC_LOG_WARN(LOG_TAG, "[%s] server killed by signal %d",
                    client->name, WTERMSIG(status));
    }
    return 0;
}

void sc_mcp_client_stop(sc_mcp_client_t *client)
{
    if (!client) return;

    /* Close stdin to signal server to exit */
    if (client->stdin_fd >= 0) {
        close(client->stdin_fd);
        client->stdin_fd = -1;
    }

    if (!client->alive) goto close_stdout;

    /* Wait briefly for graceful exit */
    int waited_ms = 0;
    while (waited_ms < SC_MCP_SHUTDOWN_WAIT_MS) {
        int status;
        pid_t ret = waitpid(client->pid, &status, WNOHANG);
        if (ret != 0) {
            client->alive = 0;
            SC_LOG_INFO(LOG_TAG, "[%s] server stopped gracefully", client->name);
            goto close_stdout;
        }
        usleep(50000); /* 50ms */
        waited_ms += 50;
    }

    /* SIGTERM */
    SC_LOG_WARN(LOG_TAG, "[%s] sending SIGTERM to pid %d", client->name, client->pid);
    kill(client->pid, SIGTERM);
    usleep(500000); /* 500ms grace */

    {
        int status;
        pid_t ret = waitpid(client->pid, &status, WNOHANG);
        if (ret != 0) {
            client->alive = 0;
            SC_LOG_INFO(LOG_TAG, "[%s] server stopped after SIGTERM", client->name);
            goto close_stdout;
        }
    }

    /* SIGKILL */
    SC_LOG_WARN(LOG_TAG, "[%s] sending SIGKILL to pid %d", client->name, client->pid);
    kill(client->pid, SIGKILL);
    waitpid(client->pid, NULL, 0);
    client->alive = 0;

close_stdout:
    if (client->stdout_fd >= 0) {
        close(client->stdout_fd);
        client->stdout_fd = -1;
    }
}

void sc_mcp_client_free(sc_mcp_client_t *client)
{
    if (!client) return;
    sc_mcp_client_stop(client);
    /* Clean up per-process temp dir (best-effort, may fail if non-empty) */
    if (client->tmpdir) {
        rmdir(client->tmpdir);
        free(client->tmpdir);
    }
    sc_strbuf_free(&client->readbuf);
    free(client->name);
    free(client);
}

void sc_mcp_tool_defs_free(sc_mcp_tool_def_t *defs, int count)
{
    if (!defs) return;
    for (int i = 0; i < count; i++) {
        free(defs[i].name);
        free(defs[i].description);
        if (defs[i].input_schema)
            cJSON_Delete(defs[i].input_schema);
    }
    free(defs);
}
