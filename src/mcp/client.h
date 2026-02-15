/*
 * mcp/client.h - MCP (Model Context Protocol) client
 *
 * Launches an MCP server as a subprocess, communicates via JSON-RPC 2.0
 * over stdin/stdout with newline-delimited JSON.
 */

#ifndef SC_MCP_CLIENT_H
#define SC_MCP_CLIENT_H

#include <sys/types.h>
#include "cJSON.h"

typedef struct sc_mcp_client sc_mcp_client_t;

/* Tool definition returned by tools/list */
typedef struct {
    char *name;
    char *description;
    cJSON *input_schema;  /* owned */
} sc_mcp_tool_def_t;

/* Start an MCP server subprocess and perform init handshake.
 * Returns NULL on failure. */
sc_mcp_client_t *sc_mcp_client_start(const char *name,
                                      char **command, int command_count,
                                      char **env_keys, char **env_values,
                                      int env_count);

/* List available tools. Caller owns the returned array and contents. */
sc_mcp_tool_def_t *sc_mcp_client_list_tools(sc_mcp_client_t *client, int *out_count);

/* Call a tool. Returns text content (caller owns). Sets *is_error on tool error. */
char *sc_mcp_client_call_tool(sc_mcp_client_t *client,
                               const char *tool_name, cJSON *args,
                               int *is_error);

/* Check if server process is still alive */
int sc_mcp_client_is_alive(sc_mcp_client_t *client);

/* Stop server (close stdin, wait, SIGTERM, SIGKILL) */
void sc_mcp_client_stop(sc_mcp_client_t *client);

/* Free client struct (calls stop if still alive) */
void sc_mcp_client_free(sc_mcp_client_t *client);

/* Free tool def array */
void sc_mcp_tool_defs_free(sc_mcp_tool_def_t *defs, int count);

#endif /* SC_MCP_CLIENT_H */
