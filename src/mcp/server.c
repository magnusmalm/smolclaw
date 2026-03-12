/*
 * mcp/server.c — MCP server mode (JSON-RPC 2.0 over stdio)
 *
 * Lightweight: tool registry only, no LLM/agent/bus/channels.
 * Communicates via newline-delimited JSON on stdin/stdout.
 *
 * Implements:
 *   initialize → tools/list → tools/call → ... → EOF
 */

#include "mcp/server.h"
#include "tools/registry.h"
#include "tools/types.h"
#include "logger.h"
#include "util/str.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#define LOG_TAG "mcp_server"
#define READ_BUF_SIZE 65536

/* Forward declaration */
int sc_shutdown_requested(void);

/* ========== I/O ========== */

/* Persistent read buffer for stdin */
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} line_buf_t;

static void line_buf_init(line_buf_t *lb)
{
    lb->cap = READ_BUF_SIZE;
    lb->buf = malloc(lb->cap);
    lb->len = 0;
    if (lb->buf) lb->buf[0] = '\0';
}

static void line_buf_free(line_buf_t *lb)
{
    free(lb->buf);
    lb->buf = NULL;
    lb->len = 0;
}

/* Read one newline-delimited JSON line from stdin.
 * Returns parsed cJSON or NULL on EOF/error. */
static cJSON *mcp_server_read_line(line_buf_t *lb)
{
    for (;;) {
        /* Check for complete line in buffer */
        char *nl = memchr(lb->buf, '\n', lb->len);
        if (nl) {
            size_t line_len = (size_t)(nl - lb->buf);
            char *line = malloc(line_len + 1);
            if (!line) return NULL;
            memcpy(line, lb->buf, line_len);
            line[line_len] = '\0';

            /* Shift buffer */
            size_t remaining = lb->len - line_len - 1;
            if (remaining > 0)
                memmove(lb->buf, nl + 1, remaining);
            lb->len = remaining;

            /* Skip empty lines */
            if (line_len == 0 || (line_len == 1 && line[0] == '\r')) {
                free(line);
                continue;
            }

            /* Strip trailing \r */
            if (line_len > 0 && line[line_len - 1] == '\r')
                line[line_len - 1] = '\0';

            cJSON *json = cJSON_Parse(line);
            free(line);
            if (!json)
                SC_LOG_WARN(LOG_TAG, "Invalid JSON on stdin");
            return json;
        }

        /* Need more data */
        if (lb->len + 4096 > lb->cap) {
            size_t new_cap = lb->cap * 2;
            char *tmp = realloc(lb->buf, new_cap);
            if (!tmp) return NULL;
            lb->buf = tmp;
            lb->cap = new_cap;
        }

        /* Poll stdin with timeout */
        struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
        int pr = poll(&pfd, 1, 1000);

        if (pr < 0) return NULL;
        if (pr == 0) {
            if (sc_shutdown_requested()) return NULL;
            continue;
        }

        ssize_t n = read(STDIN_FILENO, lb->buf + lb->len, lb->cap - lb->len - 1);
        if (n <= 0) return NULL; /* EOF or error */
        lb->len += (size_t)n;
        lb->buf[lb->len] = '\0';
    }
}

/* Write JSON response + newline to stdout */
static void mcp_server_write(cJSON *json)
{
    char *str = cJSON_PrintUnformatted(json);
    if (!str) return;

    size_t len = strlen(str);
    fwrite(str, 1, len, stdout);
    fputc('\n', stdout);
    fflush(stdout);
    free(str);
}

/* ========== Error responses ========== */

static cJSON *make_error(cJSON *id, int code, const char *message)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    if (id)
        cJSON_AddItemToObject(resp, "id", cJSON_Duplicate(id, 1));
    else
        cJSON_AddNullToObject(resp, "id");

    cJSON *err = cJSON_AddObjectToObject(resp, "error");
    cJSON_AddNumberToObject(err, "code", code);
    cJSON_AddStringToObject(err, "message", message);
    return resp;
}

/* ========== Request handlers ========== */

static cJSON *handle_initialize(cJSON *id)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    cJSON_AddItemToObject(resp, "id", cJSON_Duplicate(id, 1));

    cJSON *result = cJSON_AddObjectToObject(resp, "result");
    cJSON_AddStringToObject(result, "protocolVersion", "2024-11-05");

    cJSON *caps = cJSON_AddObjectToObject(result, "capabilities");
    cJSON *tools_cap = cJSON_AddObjectToObject(caps, "tools");
    cJSON_AddBoolToObject(tools_cap, "listChanged", 0);

    cJSON *info = cJSON_AddObjectToObject(result, "serverInfo");
    cJSON_AddStringToObject(info, "name", "smolclaw");
    cJSON_AddStringToObject(info, "version", "0.9.1");

    return resp;
}

static cJSON *handle_tools_list(cJSON *id, sc_tool_registry_t *reg)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    cJSON_AddItemToObject(resp, "id", cJSON_Duplicate(id, 1));

    cJSON *result = cJSON_AddObjectToObject(resp, "result");
    cJSON *tools = cJSON_AddArrayToObject(result, "tools");

    for (int i = 0; i < reg->count; i++) {
        sc_tool_t *t = reg->tools[i];
        if (!sc_tool_registry_is_allowed(reg, t->name))
            continue;

        cJSON *tool = cJSON_CreateObject();
        cJSON_AddStringToObject(tool, "name", t->name);
        cJSON_AddStringToObject(tool, "description",
                                t->description ? t->description : "");

        /* Get input schema from tool's parameters() */
        cJSON *schema = t->parameters ? t->parameters(t) : NULL;
        if (schema) {
            cJSON_AddItemToObject(tool, "inputSchema", schema);
        } else {
            cJSON *empty = cJSON_CreateObject();
            cJSON_AddStringToObject(empty, "type", "object");
            cJSON_AddItemToObject(tool, "inputSchema", empty);
        }

        cJSON_AddItemToArray(tools, tool);
    }

    return resp;
}

static cJSON *handle_tools_call(cJSON *id, cJSON *params,
                                 sc_tool_registry_t *reg)
{
    const char *name = NULL;
    cJSON *name_item = cJSON_GetObjectItem(params, "name");
    if (name_item && cJSON_IsString(name_item))
        name = name_item->valuestring;

    if (!name || name[0] == '\0')
        return make_error(id, -32602, "missing tool name");

    cJSON *arguments = cJSON_GetObjectItem(params, "arguments");
    if (!arguments)
        arguments = cJSON_CreateObject();

    sc_tool_result_t *result = sc_tool_registry_execute(
        reg, name, arguments, "mcp", "stdio", NULL);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    cJSON_AddItemToObject(resp, "id", cJSON_Duplicate(id, 1));

    cJSON *r = cJSON_AddObjectToObject(resp, "result");

    cJSON *content = cJSON_AddArrayToObject(r, "content");
    cJSON *item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "type", "text");
    cJSON_AddStringToObject(item, "text",
        result && result->for_llm ? result->for_llm : "(no output)");
    cJSON_AddItemToArray(content, item);

    if (result && result->is_error)
        cJSON_AddBoolToObject(r, "isError", 1);

    sc_tool_result_free(result);
    return resp;
}

/* ========== Main loop ========== */

int sc_mcp_server_run(sc_tool_registry_t *registry)
{
    if (!registry) return -1;

    SC_LOG_INFO(LOG_TAG, "MCP server starting on stdio");

    line_buf_t lb;
    line_buf_init(&lb);

    int initialized = 0;

    while (!sc_shutdown_requested()) {
        cJSON *request = mcp_server_read_line(&lb);
        if (!request) break; /* EOF */

        /* Extract method and id */
        cJSON *method_item = cJSON_GetObjectItem(request, "method");
        cJSON *id = cJSON_GetObjectItem(request, "id");
        cJSON *params = cJSON_GetObjectItem(request, "params");

        const char *method = NULL;
        if (method_item && cJSON_IsString(method_item))
            method = method_item->valuestring;

        if (!method) {
            /* Could be a notification (no method) or invalid */
            cJSON_Delete(request);
            continue;
        }

        SC_LOG_DEBUG(LOG_TAG, "Received: %s", method);

        cJSON *response = NULL;

        if (strcmp(method, "initialize") == 0) {
            response = handle_initialize(id);
            initialized = 1;
        } else if (strcmp(method, "notifications/initialized") == 0) {
            /* Client notification, no response needed */
            cJSON_Delete(request);
            continue;
        } else if (!initialized) {
            response = make_error(id, -32002, "server not initialized");
        } else if (strcmp(method, "tools/list") == 0) {
            response = handle_tools_list(id, registry);
        } else if (strcmp(method, "tools/call") == 0) {
            response = handle_tools_call(id, params, registry);
        } else if (strcmp(method, "ping") == 0) {
            response = cJSON_CreateObject();
            cJSON_AddStringToObject(response, "jsonrpc", "2.0");
            if (id)
                cJSON_AddItemToObject(response, "id", cJSON_Duplicate(id, 1));
            cJSON_AddObjectToObject(response, "result");
        } else {
            response = make_error(id, -32601, "method not found");
        }

        if (response) {
            mcp_server_write(response);
            cJSON_Delete(response);
        }

        cJSON_Delete(request);
    }

    line_buf_free(&lb);
    SC_LOG_INFO(LOG_TAG, "MCP server stopped");
    return 0;
}
