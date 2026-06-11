# Future tasks — patterns to borrow from lazyagent

Source: 2026-05-12 cross-repo analysis of https://github.com/illegalstudio/lazyagent vs the smol* fleet. lazyagent is a Go-based passive session monitor for third-party agent CLIs (Claude Code, Codex, Cursor, OpenCode, pi, Amp). Zero direct overlap with smolclaw's role; these are pattern lifts only. None are urgent.

## High-leverage

### 1. Incremental JSONL parsing for session.c

**Pattern:** lazyagent's `SessionCache` (internal/model/types.go) stores `(session, mtime, byte_offset)` per file. On file growth it deep-clones the cached session and resumes parsing from `offset` instead of re-reading the whole JSONL. Mtime+size guards against truncate/replace.

**Apply where:** `src/session.c` — whenever the cached linear path is rebuilt after appending a node. If we already incrementally append in-process this is a no-op, but for any code path that re-loads from disk (e.g. host-refresh, gateway restart, multi-process reads) this is a free perf win on long sessions.

**Pitfalls:** Sessions are a JSONL *tree* with `parent_id`, not a flat log — the cache must be keyed on the linearized leaf, not the file. Validate by mtime AND size, not mtime alone (ext4 mtime granularity bit us in similar contexts before).

### 2. `smolclaw session compact` subcommand

**Pattern:** lazyagent's `internal/compact` rewrites JSONL in place, truncating bulky tool-output fields while preserving resumability. Atomic rewrite via temp file + rename, writes `.bak`, validates the rewrite parses cleanly before swap.

**Apply where:** New subcommand under `smolclaw` (or via gateway maintenance endpoint). Truncate large tool stdout / web_fetch bodies past N bytes, keep the head + tail + a `...[truncated NNN bytes]...` marker. Audit-log entry per file processed.

**Pairing:** Existing audit log (`{workspace}/audit.log`) already captures full tool outputs, so trimming the session file is non-lossy from an observability standpoint. State this in the help text.

**Pitfalls:** Don't compact the currently-active session unless we hold the session lock. Refuse to compact while gateway is running unless `--force`.

## Medium-leverage

### 3. `smolclaw session prune` subcommand

**Pattern:** lazyagent's `internal/prune` — filter by age / orphan status, soft-delete to trash optional.

**Apply where:** Useful for fleet hygiene on long-running deployments. Less urgent than `compact` since sessions are smaller than transcripts.

## Skip — already covered or out-of-scope

- **FTS5 search** — smolclaw memory_index.c already does this.
- **Cost estimation from token counts** — `cost.c` is ahead of lazyagent here (provider-reported actuals, not just estimates). Do not regress to estimate-only.
- **Multi-provider session reading** — lazyagent reads 6 third-party formats; smolclaw only writes its own. No need.
- **macOS menu bar / Wails GUI** — out of scope for a C11 framework.

## Open question

Should smolclaw expose its `sessions/{key}.json` in a format lazyagent could optionally tail? Probably not — adds a stable-API obligation for a tiny audience. Revisit only if there's a real reason to view smolclaw sessions in lazyagent's TUI.
