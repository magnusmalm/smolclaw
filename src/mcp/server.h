/*
 * mcp/server.h — MCP server mode (JSON-RPC 2.0 over stdio)
 *
 * Exposes smolclaw's tool registry as an MCP server, usable from
 * Claude Code, Cursor, and other MCP clients.
 */

#ifndef SC_MCP_SERVER_H
#define SC_MCP_SERVER_H

#include "tools/registry.h"

/* Run the MCP server on stdin/stdout.
 * Blocks until EOF on stdin or shutdown requested.
 * Returns 0 on clean exit, -1 on error. */
int sc_mcp_server_run(sc_tool_registry_t *registry);

#endif /* SC_MCP_SERVER_H */
