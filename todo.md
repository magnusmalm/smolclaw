# smolclaw TODO

## Audit low-severity fixes

Remaining items from the deep code audit (AUDIT_REPORT.md). All low severity.

### Won't fix

- **#23** `agent_turn.c` clones all messages at turn start — doubles memory (`agent_turn.c:544-552`). Borrowing requires invasive ownership tracking for modest savings. Current approach is correct, just not memory-optimal. Not worth the complexity risk.
- **#28** `sc_validate_path` 8KB stack from two PATH_MAX buffers (`str.c:115-116`). PATH_MAX is 4096 on Linux. 8KB stack is well within default thread stack sizes (1-8MB). Heap-allocating adds malloc/free overhead for no real benefit.
- **#32** Cost tracker `fsync` on every turn (`cost.c:132-177`). Ensures cost data survives crashes. The I/O cost is negligible on modern SSDs and happens once per turn (not per tool call). Correctness over performance here.
- **#34** CDATA wrap byte-by-byte append around `]]>` (`str.c:383-386`). No length-bounded `sc_strbuf_append` exists; adding one or using malloc is worse than the loop. Trivial cost relative to I/O.

## Notification tool enhancements

The `notify` tool (`src/tools/notify.c`) currently supports Discord,
Telegram, and generic JSON webhooks. Potential additions:

- **Slack webhook** (`slack://hook-url`) — POST to Slack incoming webhook
- **ntfy** (`ntfy://host/topic`) — POST to ntfy.sh or self-hosted instance
- **Post-tool hook integration** — auto-notify on task completion via
  the pre/post tool hook chain, similar to HolyClaude's Stop hook pattern.
  Would allow headless agents to ping on session end without explicit
  tool calls.

Low priority — the current 3 backends cover the main use cases.

---

## Port conflict logging

When the web channel fails to bind, the error could be more helpful.
Log what's holding the port (equivalent of `ss -tlnp | grep :PORT`)
to help diagnose conflicts without manual investigation.

Note: auto-port (`"auto_port": true`) is already implemented — tries
configured port, then increments up to +10.

## ~~X (Twitter) channel~~ ✓

Done. See `src/channels/x.c`, `tests/test_x.c`.

## X tools: `note_tweet` support

Add `note_tweet` to `tweet.fields` in `x_get_thread` and `x_search` API
requests so long tweets (up to 25k chars, Premium feature) return the
full untruncated text instead of the 280-char truncation.

Currently only `x_get_tweet` requests `note_tweet`. The `format_tweet()`
helper already handles `note_tweet.text` — just needs the field requested
in the other endpoints' `tweet.fields` params.

## Optional microsandbox exec backend

Inspired by [microsandbox](https://github.com/zerocore-ai/microsandbox) —
a Rust microVM sandbox platform using libkrun/KVM for hardware-level isolation.

### Goal

Add a new exec mode `agents.defaults.exec_mode: "microsandbox"` that routes
`exec` and `exec_background` tool calls through microsandbox's REST API
instead of fork+exec. This provides hardware VM isolation (own kernel per
sandbox) as defense-in-depth on top of existing deny patterns + Landlock +
seccomp.

### Why

smolclaw's current sandbox (Landlock + seccomp-bpf) runs on the shared host
kernel. A kernel exploit could escape it. microsandbox runs each sandbox in
a separate microVM with its own kernel — a fundamentally stronger boundary.
For running AI-generated code or untrusted user scripts, this is a material
security upgrade.

### Design

```
Tool call: exec("pip install requests && python script.py")
  current path:  fork → seccomp+Landlock → exec (shared kernel)
  msb path:      HTTP POST localhost:5555 → sandbox.run_command → microVM
```

### Implementation plan

1. **Add `exec_mode` value**: extend `config.c` to accept `"microsandbox"`
   alongside `"denylist"` and `"allowlist"`. Store as enum/int in config.

2. **Add microsandbox client** (`src/tools/msb_client.c`):
   - HTTP POST to `http://localhost:5555/api/json-rpc` (configurable via
     `agents.defaults.microsandbox_url`)
   - JSON-RPC 2.0 requests: `sandbox.start`, `sandbox.run_command`,
     `sandbox.run_code`, `sandbox.stop`
   - Uses libcurl (already a dependency)
   - Manages a persistent sandbox per session (start on first exec, reuse)

3. **Wire into exec tools** (`src/tools/shell.c`, `src/tools/background.c`):
   - At top of `exec_execute()`, check `exec_mode`
   - If `"microsandbox"`, delegate to `sc_msb_run_command()` instead of
     fork+exec
   - Deny patterns still run first (defense-in-depth)
   - Background procs: `sandbox.run_command` with async flag, poll via
     `sandbox.get_metrics`

4. **Sandbox lifecycle**:
   - Start sandbox on first exec call per session (lazy init)
   - Configure via `agents.defaults.microsandbox_image` (default:
     `"ubuntu:22.04"`)
   - Resource limits: `microsandbox_memory_mb` (default 512),
     `microsandbox_cpus` (default 1)
   - Stop sandbox on agent shutdown or session end

5. **Fallback**: if microsandbox-server is unreachable, log error and fall
   back to native exec with Landlock+seccomp (don't silently degrade —
   warn the user).

### Prerequisites

- microsandbox-server running on localhost:5555
- Linux with KVM support (Intel VT-x / AMD-V)
- `msb` CLI installed for initial setup

### Files to modify

- `src/config.h` / `src/config.c` — new config fields
- `src/tools/shell.c` — exec routing
- `src/tools/background.c` — background exec routing
- New: `src/tools/msb_client.c` / `src/tools/msb_client.h` — HTTP client
- `CMakeLists.txt` — new source file + Kconfig flag `SC_ENABLE_MICROSANDBOX`

### Effort estimate

Multi-week. The HTTP client and sandbox lifecycle management are the bulk of
the work. Testing requires a KVM-capable host with microsandbox installed.
