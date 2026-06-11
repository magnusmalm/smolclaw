# Operator Guide: Session Isolation

**Audience**: anyone running smolclaw as a delegate target for one or more
multi-tenant callers (e.g. a smolswarm fleet, a multi-user IRC bot,
multiple MCP clients).

**Related**: [`design/session-isolation-plan.md`](../design/session-isolation-plan.md)

---

## Why this exists

A single smolclaw agent process is often shared by many independent
callers: every smolswarm delegate, every IRC user, every MCP client.
Without isolation, those callers share one workspace memory
(`{workspace}/memory/`) — and smolclaw's normal turn-end consolidation
appends a summary of every turn to today's memory file. The *next* turn,
from any caller, then reads that same memory file back into its system
prompt.

The result: caller B can see caller A's consolidated content, and the
LLM has been observed to continue caller A's narrative inside caller B's
turn. This is the contamination documented in the 2026-05-24 smolswarm
investigation.

Session isolation routes specific inbound calls through a per-session
memory namespace and skips the shared `# Memory` block in the system
prompt, while leaving the agent's persistent identity (bootstrap files,
skills, tools) intact.

---

## When isolation triggers (web channel)

Isolation is decided per inbound web request. The deciding inputs:

| Input              | Where it lives                                      |
|--------------------|-----------------------------------------------------|
| `isolation_pattern`| `channels.web.isolation_pattern` (config)           |
| `session`          | the `session` field in the POST body to `/api/message` |

If `isolation_pattern` is non-empty and the request's `session` matches
it as a glob (`*` = any characters, `?` = one character), the message
runs isolated. Otherwise it runs shared (the legacy behavior).

**Defaults:**

- `isolation_pattern` defaults to `"wf-*"` (smolswarm's delegate
  convention). A fresh install with smolswarm pointed at it gets
  isolation out of the box.
- All other web sessions (chat sessions, dashboard usage) keep shared
  behavior.

**To disable:**

Set `isolation_pattern` to an empty string in the agent's config:

```jsonc
{
  "channels": {
    "web": {
      "isolation_pattern": ""
    }
  }
}
```

Or via env:

```
SMOLCLAW_CHANNELS_WEB_ISOLATION_PATTERN=""
```

**To customize:**

Use any glob pattern. Examples:

| Pattern    | Matches                          | Doesn't match                 |
|------------|----------------------------------|-------------------------------|
| `wf-*`     | `wf-researcher-abc`, `wf-`       | `chat-1`, `x-wf-y`            |
| `task-*`   | `task-foo`                       | `wf-foo`                      |
| `*-iso`    | `smoke-iso`, `-iso`              | `iso`, `iso-x`                |
| `iso?`     | `iso1`, `isoX`                   | `iso`, `iso12`                |
| (empty)    | nothing — isolation disabled     | everything                    |

Only the web channel honors `isolation_pattern` today. Other channels
(IRC, CLI, Slack, Discord, Telegram, X) always run shared.

---

## On-disk layout

After at least one isolated session has run, the workspace has an extra
`memory/_sessions/` subtree:

```
{workspace}/
  memory/
    202605/                      # shared YYYYMMDD.md notes (unchanged)
      20260524.md
    MEMORY.md                    # shared long-term notes (unchanged)
    search.db                    # memory search index (unchanged)
    _sessions/                   # NEW: per-isolated-session dirs
      a3f17b9e2c8d4f10/          #   namespace_id (SHA-256 prefix)
        today.md                 #   per-session consolidated notes
        scratchpad.md            #   per-session post-compact scratchpad
        last_access              #   UNIX epoch, refreshed on r/w
      b71e0c5a3d49f823/
        today.md
        ...
  state/
    scratchpad.md                # shared scratchpad (unchanged)
```

**namespace_id derivation:** the web channel computes
`SHA-256(session_key)` and uses the first 16 hex digits. Same
`session_key` (i.e. same caller + same `session` name) deterministically
maps to the same namespace, so multi-turn delegate sessions retain
their own continuity within isolation.

---

## Operator workflow

### Mapping a per-session dir back to a caller

The `namespace_id` on disk is opaque. To find the caller behind it, grep
the audit log (`{workspace}/audit.log` by default) for `session_key`
entries; the consolidation log line includes the original session_key:

```
[INFO] agent: Consolidated memory from session web:0123456789abcdef:wf-researcher-XYZ in 119.5s
```

The middle component (`0123456789abcdef`) is the hashed bearer-token
identifier, and the suffix is the caller-supplied `session` field.

### Inspecting a session's content

```sh
ls {workspace}/memory/_sessions/
cat {workspace}/memory/_sessions/<namespace_id>/today.md
```

`today.md` contains the consolidated notes emitted by every turn in
that session.

### Cleanup behavior

The agent loop runs `sc_memory_cleanup_sessions` opportunistically on
inbound traffic. Defaults:

- **Tick**: every 1 hour (`SC_ISOLATION_CLEANUP_TICK_SECS_DEFAULT`).
- **TTL**: 24 hours since last write (`SC_ISOLATION_TTL_SECS_DEFAULT`).

A session directory is removed when its `last_access` epoch is older
than `now - TTL` (or the directory's mtime, if `last_access` is missing).

Cleanup is tied to inbound traffic. A completely idle agent doesn't
prune. To force cleanup, send any message through the agent.

To change the cadence at build time, edit `src/constants_limits.h`.
Tests can override per-agent via the public fields
`agent->isolation_cleanup_tick_secs` and `agent->isolation_ttl_secs`.

### Forcing immediate cleanup

There's no admin endpoint yet. Set `isolation_ttl_secs = 0` and tick to
1 second on the agent, send one message, and any session whose
`last_access` is in the past will be reaped. For ad-hoc cleanup from
the host:

```sh
rm -rf {workspace}/memory/_sessions/<namespace_id>
```

This is safe — the agent doesn't hold open file descriptors into these
dirs between turns.

---

## What isolation does NOT do

- **It is not a security boundary.** An isolated session still runs
  with the same agent's tool registry, the same bearer token, the same
  workspace. A misbehaving model can still call `read_file` and
  `write_file` against the full workspace. Isolation prevents
  prompt/memory contamination across delegate sessions; it is not
  authentication or sandboxing.
- **It does not affect the workspace's `state/scratchpad.md`** for
  non-isolated callers. Their post-compact reinjection still uses the
  shared scratchpad as before.
- **It does not protect against a misconfigured pattern.** A pattern
  like `*` would isolate every web caller, including the dashboard chat
  UI — useful for one-off testing, harmful as a default.

---

## Migration from a contaminated workspace

If a workspace has been contaminated under the legacy (pre-isolation)
behavior, the shared `memory/YYYYMM/YYYYMMDD.md` files contain
consolidated content from many callers' turns. Once you turn on
isolation:

- **Existing files are not touched.** Non-isolated sessions continue
  to read and write them as before.
- **Isolated sessions never read them.** A `wf-*` delegate run after
  isolation lands will not see any of the historical contamination.

If you want a clean slate for shared callers as well, back up
`memory/YYYYMM/` and delete the dated files. The next consolidation
will start fresh.

---

## Verification checklist after enabling

1. `cmake --build build && ctest --test-dir build` — full suite green.
2. Issue a smolswarm `implement_feature` orchestrate against the agent.
   In the smolclaw journal, look for the new identity line:
   `"isolated session"` in the system prompt build (check via
   `audit.log` or by raising agent log level).
3. Inspect `{workspace}/memory/_sessions/` — there should be a fresh
   per-session directory after the delegate runs.
4. Confirm `{workspace}/memory/YYYYMM/YYYYMMDD.md` did **not** grow.
5. Re-run the smolswarm smoke a second time with a different task; the
   smoke's Outline should be about its own task, not the prior one.

---

## Disabling isolation in an emergency

If isolation is somehow at fault for an outage (very unlikely given the
defaults are conservative), disable it without rebuilding:

```sh
SMOLCLAW_CHANNELS_WEB_ISOLATION_PATTERN="" systemctl --user restart smolclaw-agent@<name>
```

Effective immediately on next inbound message. To re-enable, restart
without the env override.
