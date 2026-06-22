# Gateway Threat Model

**Audience:** operators exposing `smolclaw gateway` beyond a single trusted
user on loopback.

**Related:** [`SECURITY.md`](../SECURITY.md),
[`session-isolation.md`](session-isolation.md),
[`CONFIGURATION.md`](../CONFIGURATION.md)

**Audit:** repo-audit `4298ba13` (PR-1, PR-6 hardening)

---

## Summary

A running gateway is an **unattended agent with tool access**. Anyone who can
deliver an inbound message to an enabled channel can steer the LLM through
the full tool loop (filesystem, exec, git, memory, delegation, etc.).

Defense is layered: channel auth, exec deny/allow patterns, Landlock/seccomp,
SSRF pinning, and workspace restrictions — but **misconfiguration can remove
the outer perimeter** while inner guards still run. Treat network exposure +
`auto_confirm` as granting **shell-equivalent capability** to authenticated
callers.

---

## Gateway vs CLI

| Mode      | Tool confirmation                         | Typical use              |
|-----------|-------------------------------------------|--------------------------|
| `agent`   | Interactive `[CONFIRM]` for risky tools   | Operator at keyboard     |
| `gateway` | Auto-approved (`gateway_auto_confirm`)    | Headless services, bots  |

In gateway mode, `agents.defaults.auto_confirm: true` (common in examples)
registers an approve-all callback. Tools marked `needs_confirm` (exec, git
push, file writes, etc.) run **without a human prompt**. Deny patterns,
exec allowlist mode, Landlock, and per-channel tool allowlists remain the
guards — not an operator in the loop.

**Implication:** A gateway on a reachable address with weak channel auth is
equivalent to leaving a shell open to that audience.

---

## Web channel (HTTP API)

### Bearer token is mandatory

Since audit remediation PR-1, the web channel **refuses to start** without a
non-empty `channels.web.bearer_token`. All sensitive API routes require
`Authorization: Bearer <token>`:

- `POST /api/message`
- `POST /api/memory/log`, `POST /api/memory/search`
- `GET /api/audit`, `GET /api/progress`, `GET /api/media`
- `GET /api/health` (PR-6 — no longer anonymous)
- `GET /api/ui-config`

`GET /` (embedded chat UI) remains public HTML; the UI stores the bearer
token client-side (`sessionStorage`). Protect the bind address accordingly.

### Network binding

- Default bind: `127.0.0.1`. Prefer loopback + reverse proxy for remote access.
- Non-loopback bind without TLS logs a warning; set `channels.web.tls_cert`
  and `channels.web.tls_key` for built-in HTTPS (requires OpenSSL build), or
  terminate TLS at nginx/Caddy.
- HTTP bypasses chat-channel controls (`allow_from`, pairing) — only bearer
  auth and rate limits apply.

### Rate limiting (PR-6)

`POST /api/message` consumes the global `agents.defaults.rate_limit_per_minute`
token bucket keyed by **client IP + bearer-token hash**. Bursts return HTTP 429.
Tune `rate_limit_per_minute` for your deployment; `0` disables limiting.

### Session isolation

Orchestrator delegates should use `channels.web.isolation_pattern` (default
`wf-*`) so parallel callers do not share consolidated memory. See
[`session-isolation.md`](session-isolation.md).

---

## Other channels

Telegram, Discord, Slack, IRC, and X route through `sc_channel_handle_message`:

- `allow_from` / DM policy (`open`, `allowlist`, `pairing`)
- Per-channel rate limits (same `rate_limit_per_minute` setting)
- Pairing challenges for unknown senders when policy is `pairing`

These controls **do not** apply to the web HTTP API.

---

## Recommended deployment postures

### Development (loopback)

```jsonc
"channels": {
  "web": {
    "enabled": true,
    "bind_addr": "127.0.0.1",
    "bearer_token": "file:///path/to/token"
  }
}
```

### Production (internet-facing)

1. Bind web to loopback; expose via TLS reverse proxy with auth at the edge.
2. Strong random bearer token (vault or `file://`); rotate on compromise.
3. Set `rate_limit_per_minute` appropriately.
4. Restrict `agents.defaults.allowed_tools` and per-channel `tools` arrays.
5. Keep `restrict_to_workspace: true`; use `exec_mode: "allowlist"` when feasible.
6. Enable `sandbox` / Landlock where the kernel supports it.
7. Use session isolation for multi-tenant delegate traffic.
8. Do **not** rely on `auto_confirm: false` in gateway today — gateway always
   auto-approves; use deny/allow patterns and network isolation instead.

---

## What this document does not cover

- Provider API key handling (see vault docs in `CONFIGURATION.md`)
- MCP server command injection (see `SECURITY.md` MCP section)
- Prompt injection resistance (CDATA wrapping, prompt guard)

Future work (not in this remediation arc): configurable `gateway.confirm_policy`
to deny dangerous tools in unattended mode without disabling the gateway.