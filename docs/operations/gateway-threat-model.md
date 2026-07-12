# Gateway Threat Model

**Audience:** operators exposing `smolclaw gateway` beyond a single trusted
user on loopback.

**Related:** [`SECURITY.md`](../SECURITY.md),
[`session-isolation.md`](session-isolation.md),
[`CONFIGURATION.md`](../CONFIGURATION.md)

---

## Summary

A running gateway is an **unattended agent with tool access**. Anyone who can
deliver an inbound message to an enabled channel can steer the LLM through
the tool loop (filesystem, exec, git, memory, delegation, etc.) for tools that
remain enabled.

Defense is layered: channel auth, **gateway exec allowlist requirement**,
exec deny patterns, Landlock/seccomp (fail-closed), SSRF pinning, and workspace
restrictions. Treat network exposure + full tool surface as granting
**shell-equivalent capability** to authenticated / allowlisted callers.

---

## Gateway vs CLI

| Mode      | Tool confirmation                         | Exec policy |
|-----------|-------------------------------------------|-------------|
| `agent`   | Interactive `[CONFIRM]` for risky tools   | Denylist by default (CLI) |
| `gateway` | Auto-approved (`gateway_auto_confirm`)    | **Must** use exec allowlist if exec tools available |

In gateway mode tools marked `needs_confirm` run **without a human prompt**.
Guards are:

1. **Exec allowlist** (required at gateway start unless lab override)
2. Deny patterns (105 POSIX ERE patterns in `deny_patterns.h`)
3. Landlock/seccomp (fail-closed on apply failure)
4. `allowed_tools` / per-channel `tools`
5. Channel DM policy / web bearer

### Gateway exec policy (SML-002)

On `smolclaw gateway` start, if `exec` or `exec_background` is available
(empty global `allowed_tools`, or list includes those names), config **must**
have:

```json
"agents": {
  "defaults": {
    "exec_mode": "allowlist",
    "exec_allowed_commands": ["ls", "cat", "grep", "git"]
  }
}
```

**Lab-only escape hatch:** `"allow_unrestricted_exec": true` (or env
`SMOLCLAW_AGENTS_DEFAULTS_ALLOW_UNRESTRICTED_EXEC=1`). Prefer removing exec
from `allowed_tools` instead.

---

## Web channel (HTTP API)

### Bearer token is mandatory

The web channel **refuses to start** without a non-empty
`channels.web.bearer_token`. Sensitive API routes require
`Authorization: Bearer <token>`.

### Network binding

- Default bind: `127.0.0.1`. Prefer loopback + reverse proxy for remote access.
- Non-loopback bind without TLS logs a warning; set TLS cert/key or terminate
  TLS at nginx/Caddy.
- HTTP bypasses chat-channel DM `allow_from` / pairing — only bearer auth and
  rate limits apply. Restrict tools via `channels.web.tools`.

### Rate limiting

`POST /api/message` uses `agents.defaults.rate_limit_per_minute` keyed by
**client IP + bearer-token hash**.

### Session isolation

Orchestrator delegates should use `channels.web.isolation_pattern` (default
`wf-*`). See [`session-isolation.md`](session-isolation.md).

---

## Other channels

Telegram, Discord, Slack, IRC, Signal, and X route through
`sc_channel_handle_message`:

- Factory default `dm_policy` is **`allowlist`** (not open)
- Explicit `dm_policy: "open"` with empty `allow_from` is **quarantined**
  (channel not started) unless `agents.defaults.accept_open_dms: true`
- Pairing challenges when policy is `pairing`

---

## Recommended deployment postures

### Development (loopback)

```jsonc
"agents": {
  "defaults": {
    "exec_mode": "allowlist",
    "exec_allowed_commands": ["ls", "cat", "grep", "pwd"]
  }
},
"channels": {
  "web": {
    "enabled": true,
    "bind_addr": "127.0.0.1",
    "bearer_token": "file:///path/to/token",
    "tools": ["web_search", "web_fetch", "memory_search"]
  }
}
```

### Production (internet-facing)

1. Bind web to loopback; expose via TLS reverse proxy with auth at the edge.
2. Strong random bearer token (vault or `file://`); rotate on compromise.
3. Set `rate_limit_per_minute` appropriately.
4. Restrict `agents.defaults.allowed_tools` and per-channel `tools` arrays
   (companion: never leave unrestricted `exec` on web).
5. Keep `restrict_to_workspace: true`; **require** `exec_mode: "allowlist"`.
6. Keep `sandbox: true` (fail-closed on apply failure).
7. Use session isolation for multi-tenant delegate traffic.
8. Keep `dm_policy` as `allowlist` or `pairing` with real `allow_from` entries.
9. Do **not** set `accept_open_dms` or `allow_unrestricted_exec` in production.

### Lab-only open DMs (discouraged)

```jsonc
"agents": {
  "defaults": {
    "accept_open_dms": true,
    "allow_unrestricted_exec": true
  }
},
"channels": {
  "telegram": {
    "enabled": true,
    "dm_policy": "open"
  }
}
```

---

## What this document does not cover

- Provider API key handling (see vault docs in `CONFIGURATION.md`)
- Prompt injection resistance (CDATA wrapping, prompt guard)

## Audit references

Remediations for crystal-box findings SML-001 (DM defaults/quarantine),
SML-002 (gateway exec allowlist + denylist), SML-006 (MCP sandbox fail-closed):
see `docs/security-audits/`.
