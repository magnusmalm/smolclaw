# MCP Cookbook

smolclaw is an **MCP client**: it can spawn [Model Context Protocol](https://modelcontextprotocol.io)
servers and expose their tools to the agent. This guide covers configuring
servers, the security sandbox, and working recipes.

Requires a build with `SC_ENABLE_MCP`.

---

## How it works

- Each configured server is started as a **subprocess** and spoken to over
  **stdio** (JSON-RPC). smolclaw performs the `initialize` handshake, calls
  `tools/list`, and registers each discovered tool with the agent.
- A server's tools are namespaced as **`<server>__<tool>`** (double
  underscore). E.g. the filesystem server's `read_text_file` becomes
  `fs__read_text_file`.
- Servers are started when the agent/gateway starts; if a server fails to
  start it is skipped (the rest of smolclaw runs normally).

## Configuration

```json
{
  "mcp": {
    "enabled": true,
    "servers": {
      "<name>": {
        "command": ["executable", "arg1", "arg2"],
        "env": { "API_KEY": "vault://my-key" },
        "capabilities": { }
      }
    }
  }
}
```

| Field | Type | Notes |
|-------|------|-------|
| `mcp.enabled` | bool | Master switch (default true when the section is present). |
| `servers.<name>.command` | string[] | argv; `command[0]` is the executable. **Required.** |
| `servers.<name>.env` | object | Extra env vars for the server. Values support `vault://` references. A fixed set of dangerous vars (`LD_PRELOAD`, `NODE_OPTIONS`, …) is always stripped. |
| `servers.<name>.capabilities` | object | Sandbox controls — see below. |

The server `<name>` must be a simple identifier (letters, digits, `_`, `-`).

---

## The sandbox (important)

By default every MCP server runs under an **OS-level sandbox** (Landlock +
seccomp): its filesystem access is confined to the agent **workspace**, a
per-process **tmpdir**, and the directory of `command[0]`. Outbound behaviour
is further restricted by seccomp.

`capabilities` adjusts this per server:

| Key | Effect |
|-----|--------|
| `fs_read`  | string[] of extra paths granted **read** access. Setting this disables the blanket workspace grant — list every path the server needs. |
| `fs_write` | string[] of paths granted **read-write** access. |
| `process`  | `[]` (empty array) → block `execve`/`fork`/`clone` (no subprocesses). |
| `network`  | `[]` or `false` → block outbound sockets. |
| `sandbox`  | `false` → **run the server with NO sandbox at all** (trusted). See below. |

### ⚠️ npx / Node servers need `sandbox: false`

Most MCP servers are distributed as `npx -y <package>`. **`npx` does not work
under the default sandbox** — it spawns a child `node` process whose
multi-process startup the Landlock/seccomp confinement cannot host, and the
server dies silently at the handshake (`init handshake failed` /
`server closed stdout`).

Two options:

1. **Trust the server and disable its sandbox** (simplest):

   ```json
   "fs": {
     "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"],
     "capabilities": { "sandbox": false }
   }
   ```

   `sandbox: false` turns off OS isolation **for that server only**. Use it
   only for servers you trust — the server then runs with your normal user
   permissions. Pair it with the agent's tool allowlist and the MCP server's
   own scoping (e.g. the filesystem server already restricts itself to the
   directory you pass it).

2. **Run a single-process server sandboxed** — invoke the package's entry
   script directly with `node` (no `npx` wrapper), and grant the Node runtime
   read access:

   ```json
   "fs": {
     "command": ["node", "/path/to/server-filesystem/dist/index.js", "/data"],
     "capabilities": {
       "fs_read":  ["/usr", "/etc", "/lib", "/lib64", "/dev", "/proc",
                    "/home/you/.nvm", "/data"],
       "fs_write": ["/data"]
     }
   }
   ```

   This keeps OS isolation but is fiddly (you must enumerate the runtime
   paths). Prefer option 1 for trusted servers.

---

## Recipes

### Filesystem (read/write a directory)

```json
"fs": {
  "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/srv/data"],
  "capabilities": { "sandbox": false }
}
```

Exposes `fs__read_text_file`, `fs__write_file`, `fs__list_directory`, … scoped
to `/srv/data` by the server itself.

### A server that needs an API key (kept in the vault)

```json
"weather": {
  "command": ["npx", "-y", "@example/mcp-weather"],
  "env": { "WEATHER_API_KEY": "vault://weather-key" },
  "capabilities": { "sandbox": false }
}
```

Store the secret with `smolclaw vault set weather-key`; the `vault://` ref is
resolved at load time so the plaintext key never sits in `config.json`.

### A read-only, network-only server (tighten instead of disabling)

For a server that should reach the network but never touch your files, keep the
sandbox and deny what it doesn't need:

```json
"search": {
  "command": ["node", "/opt/mcp/search/index.js"],
  "capabilities": {
    "fs_read": ["/usr", "/etc", "/lib", "/lib64", "/dev", "/proc", "/opt/mcp/search"],
    "process": []
  }
}
```

### Using MCP tools

MCP tools appear to the model as `<server>__<tool>` and behave like any other
tool. To restrict which ones the model may call, use the agent / per-channel
`allowed_tools` list with the prefixed names (e.g. `"fs__read_text_file"`).

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `init handshake failed` / `server closed stdout` with an `npx` command | The sandbox is killing `npx`. Set `capabilities.sandbox: false` (trusted) or use the direct-`node` recipe. |
| `MCP server '<name>' has no tools` | The server started but `tools/list` was empty — check the server's own args/config. |
| `Skipping MCP server: invalid name` | Rename the server to letters/digits/`_`/`-`. |
| Server starts standalone but not under smolclaw | Run with `SC_MCP_DEBUG_STDERR=1` to see the server's stderr (normally sent to `/dev/null`). |
| Tool calls fail with permission errors | The sandbox is blocking a path the server needs — add it to `capabilities.fs_read`/`fs_write`, or use `sandbox: false` for a trusted server. |

### Debugging a server that won't start

```bash
SC_MCP_DEBUG_STDERR=1 smolclaw agent -d -m "noop"
```

This passes the MCP server's stderr through to your terminal so you can see why
it exited.
