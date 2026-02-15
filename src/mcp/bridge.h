/*
 * mcp/bridge.h - MCP tool registry bridge
 *
 * Starts MCP server clients, discovers their tools, and registers
 * proxy tools in the agent's tool registry.
 */

#ifndef SC_MCP_BRIDGE_H
#define SC_MCP_BRIDGE_H

#include "config.h"
#include "tools/registry.h"

typedef struct sc_mcp_bridge sc_mcp_bridge_t;

/* Start all configured MCP servers and register their tools.
 * Returns bridge handle (or NULL if no servers configured/started). */
sc_mcp_bridge_t *sc_mcp_bridge_start(const sc_mcp_config_t *cfg,
                                      sc_tool_registry_t *registry);

/* Stop all MCP servers and free bridge */
void sc_mcp_bridge_free(sc_mcp_bridge_t *bridge);

#endif /* SC_MCP_BRIDGE_H */
