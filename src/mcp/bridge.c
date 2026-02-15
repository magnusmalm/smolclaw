/*
 * mcp/bridge.c - MCP tool registry bridge
 *
 * For each configured MCP server: starts the client, discovers tools via
 * tools/list, and creates proxy sc_tool_t entries in the agent registry.
 * Tool names are prefixed as "server__tool" (double underscore).
 */

#include "mcp/bridge.h"
#include "mcp/client.h"

#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "logger.h"
#include "util/str.h"

#define LOG_TAG "mcp"

struct sc_mcp_bridge {
    sc_mcp_client_t **clients;
    int client_count;
};

/* Per-tool proxy data stored in sc_tool_t.data */
typedef struct {
    sc_mcp_client_t *client;    /* borrowed ref to bridge's client */
    char *tool_name;            /* original MCP tool name (for tools/call) */
    char *server_name;          /* for error messages */
    cJSON *schema;              /* cached input_schema */
} mcp_proxy_data_t;

/* ---------- Proxy tool vtable ---------- */

static cJSON *proxy_parameters(sc_tool_t *self)
{
    mcp_proxy_data_t *d = self->data;
    if (d->schema)
        return cJSON_Duplicate(d->schema, 1);
    /* Fallback: empty object schema */
    cJSON *s = cJSON_CreateObject();
    cJSON_AddStringToObject(s, "type", "object");
    cJSON_AddItemToObject(s, "properties", cJSON_CreateObject());
    return s;
}

static sc_tool_result_t *proxy_execute(sc_tool_t *self, cJSON *args, void *ctx)
{
    (void)ctx;
    mcp_proxy_data_t *d = self->data;

    if (!sc_mcp_client_is_alive(d->client)) {
        sc_strbuf_t sb;
        sc_strbuf_init(&sb);
        sc_strbuf_appendf(&sb, "MCP server '%s' is not running", d->server_name);
        char *msg = sc_strbuf_finish(&sb);
        sc_tool_result_t *r = sc_tool_result_error(msg);
        free(msg);
        return r;
    }

    int is_error = 0;
    char *result = sc_mcp_client_call_tool(d->client, d->tool_name, args, &is_error);

    if (is_error) {
        sc_tool_result_t *r = sc_tool_result_error(result ? result : "MCP tool error");
        free(result);
        return r;
    }

    sc_tool_result_t *r = sc_tool_result_new(result ? result : "");
    free(result);
    return r;
}

static void proxy_destroy(sc_tool_t *self)
{
    if (!self) return;
    mcp_proxy_data_t *d = self->data;
    if (d) {
        free(d->tool_name);
        free(d->server_name);
        if (d->schema) cJSON_Delete(d->schema);
        free(d);
    }
    free((char *)self->name);
    free((char *)self->description);
    free(self);
}

/* Validate MCP tool/server name: alphanumeric + single underscore + hyphen,
 * no double underscore (reserved separator), max 64 chars. */
static int is_valid_mcp_name(const char *name)
{
    if (!name || !name[0]) return 0;
    size_t len = strlen(name);
    if (len > 64) return 0;

    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) return 0;
        /* Reject double underscore */
        if (c == '_' && i + 1 < len && name[i + 1] == '_') return 0;
    }
    return 1;
}

/* ---------- Public API ---------- */

sc_mcp_bridge_t *sc_mcp_bridge_start(const sc_mcp_config_t *cfg,
                                      sc_tool_registry_t *registry)
{
    if (!cfg || cfg->server_count == 0 || !registry) return NULL;

    sc_mcp_bridge_t *bridge = calloc(1, sizeof(*bridge));
    if (!bridge) return NULL;

    bridge->clients = calloc((size_t)cfg->server_count, sizeof(sc_mcp_client_t *));
    if (!bridge->clients) {
        free(bridge);
        return NULL;
    }

    for (int i = 0; i < cfg->server_count; i++) {
        const sc_mcp_server_config_t *srv = &cfg->servers[i];
        if (!srv->name || srv->command_count < 1) continue;

        /* Validate server name */
        if (!is_valid_mcp_name(srv->name)) {
            SC_LOG_WARN(LOG_TAG, "Skipping MCP server '%s': invalid name "
                        "(alphanumeric/underscore/hyphen only, no '__', max 64 chars)",
                        srv->name);
            continue;
        }

        SC_LOG_INFO(LOG_TAG, "Starting MCP server '%s' (%s)", srv->name, srv->command[0]);

        sc_mcp_client_t *client = sc_mcp_client_start(
            srv->name, srv->command, srv->command_count,
            srv->env_keys, srv->env_values, srv->env_count);

        if (!client) {
            SC_LOG_WARN(LOG_TAG, "Failed to start MCP server '%s', skipping", srv->name);
            continue;
        }

        /* Discover tools */
        int tool_count = 0;
        sc_mcp_tool_def_t *tools = sc_mcp_client_list_tools(client, &tool_count);

        if (!tools || tool_count == 0) {
            SC_LOG_WARN(LOG_TAG, "MCP server '%s' has no tools", srv->name);
            sc_mcp_tool_defs_free(tools, tool_count);
            bridge->clients[bridge->client_count++] = client;
            continue;
        }

        /* Register proxy tools */
        for (int t = 0; t < tool_count; t++) {
            /* Validate tool name */
            if (!is_valid_mcp_name(tools[t].name)) {
                SC_LOG_WARN(LOG_TAG, "Skipping MCP tool '%s' from server '%s': "
                            "invalid name", tools[t].name ? tools[t].name : "(null)",
                            srv->name);
                continue;
            }

            sc_tool_t *proxy = calloc(1, sizeof(sc_tool_t));
            if (!proxy) continue;

            mcp_proxy_data_t *data = calloc(1, sizeof(mcp_proxy_data_t));
            if (!data) { free(proxy); continue; }

            data->client = client;
            data->tool_name = sc_strdup(tools[t].name);
            data->server_name = sc_strdup(srv->name);
            data->schema = tools[t].input_schema;
            tools[t].input_schema = NULL; /* transfer ownership */

            /* Build prefixed name: "server__tool" */
            sc_strbuf_t name_buf;
            sc_strbuf_init(&name_buf);
            sc_strbuf_appendf(&name_buf, "%s__%s", srv->name, tools[t].name);
            proxy->name = sc_strbuf_finish(&name_buf);

            /* Build description: "[MCP: server] original_description" */
            sc_strbuf_t desc_buf;
            sc_strbuf_init(&desc_buf);
            sc_strbuf_appendf(&desc_buf, "[MCP: %s] %s", srv->name,
                              tools[t].description ? tools[t].description : "");
            proxy->description = sc_strbuf_finish(&desc_buf);

            proxy->parameters = proxy_parameters;
            proxy->execute = proxy_execute;
            proxy->set_context = NULL;
            proxy->destroy = proxy_destroy;
            proxy->data = data;

            sc_tool_registry_register(registry, proxy);
            SC_LOG_INFO(LOG_TAG, "Registered MCP tool: %s", proxy->name);
        }

        sc_mcp_tool_defs_free(tools, tool_count);
        bridge->clients[bridge->client_count++] = client;
    }

    if (bridge->client_count == 0) {
        free(bridge->clients);
        free(bridge);
        return NULL;
    }

    SC_LOG_INFO(LOG_TAG, "MCP bridge started with %d server(s)", bridge->client_count);
    return bridge;
}

void sc_mcp_bridge_free(sc_mcp_bridge_t *bridge)
{
    if (!bridge) return;
    for (int i = 0; i < bridge->client_count; i++) {
        sc_mcp_client_free(bridge->clients[i]);
    }
    free(bridge->clients);
    free(bridge);
}
