# Phase 4: Larger Investments

**Status**: In progress (4.8 audit mediums landed)  
**Master plan**: [`../master-plan.md`](../master-plan.md)  
**Prerequisite**: [Phase 3](phase-3-optional-surface-area.md) complete (or parallel if demand-driven)  
**Goal**: Optional subsystems and architectural improvements with higher complexity.  
**LOC budget**: ~2,100–3,200 (each item independently shippable)  
**Binary target**: Each feature Kconfig-gated; measure per flag

---

## 1. Scope

- **4.1** — Task: Arena allocator per turn — **allocator shipped + per-turn wired; only
  provider-parse conversion remains**; Source: zed-patterns T1; LOC: 80–150; Binary: ~0; Gate: always
- **4.2** — Task: MCP capability-based sandbox; Source: zed-patterns T3; LOC: 300–500; Binary:
  +10–20 KB; Gate: per-server config
- **4.3** — Task: Anthropic prompt caching; Source: claude-code P1 #4; LOC: 60–100; Binary: ~5 KB;
  Gate: Anthropic only
- **4.4** — Task: Old tool result compression transform; Source: claude-code P1 #6; LOC: 80–120;
  Binary: ~5 KB; Gate: config
- **4.5** — Task: Project memory + repo_search; Source: smallharness §6 task 7; LOC: 800–1,200;
  Binary: +50–100 KB; Gate: `SC_ENABLE_PROJECT_MEMORY` **default n**
- **4.6** — Task: `smolclaw doctor --local`; Source: smallharness §6 task 8; LOC: 200–350; Binary:
  ~10 KB; Gate: CLI
- **4.7** — Task: Prompt budget command; Source: smallharness §6 task 9; LOC: 80–120; Binary: ~5 KB;
  Gate: CLI
- **4.8** — Task: Remaining audit medium fixes; Source: code-analysis M-*; LOC: 150–300; Binary: ~0;
  Gate: always
- **4.9** — Task: Microsandbox exec backend; Source: todo.md; LOC: 400–600; Binary: +15–30 KB; Gate:
  `SC_ENABLE_MICROSANDBOX` + external daemon
- **4.10** — Task: Updater binary split evaluation; Source: todo.md; LOC: 200–400; Binary: variable;
  Gate: research spike
- **4.11** — Task: Global `session_search` tool; Source: Hermes-gap; Tier: **T1**; LOC: 300–500;
  Binary: +15–25 KB; Gate: `SC_ENABLE_SESSION_SEARCH` **default n**
- **4.12** — Task: Agent-initiated compact tool; Source: progress-2026-04-06; Tier: **T1**; LOC:
  100–150; Binary: ~5 KB; Gate: config
- **4.13** — Task: Post-turn memory review; Source: Hermes-gap; Tier: **T4**; LOC: 200–350; Binary:
  +10 KB; Gate: config **default off**
- **4.14** — Task: Staged memory writes + capacity headers; Source: Hermes-gap; Tier: **T4**; LOC:
  150–250; Binary: ~5 KB; Gate: config

Each task is a **separate milestone** — do not batch into one PR.

**Prerequisite for 4.13–4.14:** Phase 1 compaction stable and Phase 2 OAuth shipped (optional
auxiliary model path uses same provider factory).

---

## 2. Task Details

### 4.1 Arena allocator

**Source:** zed-patterns Task 1

> **Status (2026-06-26):** `src/util/arena.c` + `arena.h` already exist
> (`sc_arena_new/alloc/reset/free`) and the arena is already created, reset
> per turn, and threaded into the transform/context path in `src/agent.c`
> (see `agent->arena`, `sc_arena_reset` at turn start, `snap->arena`).
> **Remaining work:** convert provider SSE/response parsing
> (`src/providers/http.c`, `src/providers/provider_common.c`) to allocate from
> the arena so the unchecked-alloc class collapses to one OOM check point.

**Files:** `src/providers/http.c`, `src/providers/provider_common.c` (arena adoption)

- [x] Bump allocator with reset per turn *(shipped)*
- [ ] Provider SSE parsing uses arena *(remaining)*
- [ ] Single OOM check point per turn *(remaining — depends on above)*
- [x] Long-lived data stays on heap *(by design)*

### 4.2 MCP capability sandbox

**Source:** zed-patterns Task 3

**Files:** `src/mcp/bridge.c`, `src/config.c`, `src/util/sandbox.c`

- [ ] Config `capabilities` per MCP server (network, fs_read, fs_write, process)
- [ ] Translate to per-server Landlock + seccomp rules
- [ ] Missing capabilities → current blanket sandbox (backward compatible)

### 4.3 Anthropic prompt caching

**Source:** claude-code P1 #4

**Files:** `src/providers/claude.c`, `src/context.c`, `src/providers/types.h`

- [ ] Split system prompt static vs dynamic
- [ ] `cache_control: ephemeral` on static block
- [ ] Only when provider is Anthropic and config enabled

### 4.4 Context transform: compress old tool results

**Source:** claude-code P1 #6

**Files:** `src/agent.c` (transform hook), `src/config.{c,h}`

> **Recon (2026-06-27):** the core was **already shipped** — `mask_old_observations`
> (agent.c) runs via `sc_agent_add_transform()` before every LLM call and
> replaces old (older than last 6), large (>200 B) tool results with a one-line
> metadata placeholder. That already meets 4.4's goal (and is more aggressive
> than the spec's 500-char target). The only unmet deliverable was **"Gate:
> config"** — the behavior was hardcoded.

- [x] Before LLM call: compress old large tool results to a metadata placeholder
  *(already shipped via `mask_old_observations`)*
- [x] Uses existing `sc_agent_add_transform()` mechanism *(already shipped)*
- [x] **Config gate (this slice):** `compress_tool_results` (default true),
  `compress_keep_recent` (default 6), `compress_min_bytes` (default 200) under
  `agents.defaults`; defaults preserve prior behavior. Decision extracted to pure
  `sc_mask_should_compress()` (unit-tested); transform reads the values via the
  agent and honors hot-reload.

**Status (2026-06-27):** ✅ done. Owner chose "config gate" scope (the core
compression was already shipped). Pure `sc_mask_should_compress` + config
plumbing + `test_agent.c` test; default behavior unchanged.

### 4.5 Project memory index

**Source:** smallharness-integration task 7

**Files:** new `src/tools/project_memory.c`, `src/tools/repo_search.c`

> **Decisions (2026-06-26):** Q2 — store the index at
> **`{SMOLCLAW_HOME}/indexes/{workspace-hash}.json`** (`workspace-hash` = first 16
> hex of `sha256(realpath(workspace_root))`), **not** inside the user's repo.
> Q7 — v1 ships its **own lightweight extraction** with a `TODO(shared-symbols)`
> marker; the shared `sc_symbols` helper with `code_graph` lands in v2. See
> `autonomy-readiness.md` §3.

- [ ] Index: path, language, size, mtime, SHA-256, symbols, imports, terms
- [ ] Storage: `{SMOLCLAW_HOME}/indexes/{workspace-hash}.json` (Q2 resolved)
- [ ] `/index` equivalent via CLI or tool actions: build, refresh, status
- [ ] `repo_search` tool for ranked hits
- [ ] Optional system prompt injection for code questions (local providers only by default)
- [ ] v1 own extraction (`TODO(shared-symbols)`); share with `code_graph` in v2 (Q7)
- [ ] Kconfig **default n**

### 4.6 Local provider doctor

**Source:** smallharness-integration task 8

- [ ] `smolclaw doctor` or `smolclaw agent doctor --local`
- [ ] Probe: models list, streaming, tool calls, inline JSON fallback
- [ ] Cache under `.smolclaw/capabilities/`
- [ ] Explicit invocation only (no startup probe)

### 4.7 Prompt budget CLI

**Source:** smallharness-integration task 9

- [ ] `smolclaw context` — byte/token breakdown: system, history, tools, tool results
- [ ] Warn threshold configurable

### 4.8 Remaining audit mediums

Recon (2026-06-27) against `code-analysis-report.md` found most of these mediums
were already closed by prior hardening; two were genuinely open.

- [x] **M-2: Web pipe partial read** — **fixed.** Added
  `_Static_assert(sizeof(web_response_t) <= PIPE_BUF)` in `web.c`. POSIX
  guarantees a pipe write ≤ PIPE_BUF is atomic, so the reader can never see a
  torn message and lose (leak) the `text` pointer; the assert enforces the
  invariant at compile time.
- [x] **M-4: Session unbounded growth guard** — **fixed.** Async summarization
  can fail repeatedly (provider down), leaving the soft threshold permanently
  exceeded and history growing every turn. Added pure decision
  `sc_session_force_prune_due(count, threshold)` (hard ceiling = threshold ×
  `SC_SESSION_FORCE_PRUNE_MULT`); `sc_maybe_summarize` force-prunes to
  `keep_last` via the existing `sc_session_truncate` when it fires, logged
  loudly. Test in `test_session.c`.
- [x] **M-5: Config reload atomicity** — **verified already mitigated.**
  `sc_config_load` parses into a *new* `sc_config_t`; the SIGHUP path applies it
  only when non-NULL (`main.c` ~1794), so a failed parse leaves the live config
  untouched (no partial state). No code change.
- [x] **M-6: MCP client timeouts** — **verified already fixed.** MCP requests use
  finite `SC_MCP_INIT_TIMEOUT_MS` / `SC_MCP_CALL_TIMEOUT_MS` and `mcp_read_line`
  blocks on `poll()` with a deadline. No code change.
- [x] **M-7: Tool confirm bypass review** — **verified not exploitable** +
  regression test. The same `name` drives the allowlist check, the exact-match
  `strcmp` lookup, and the confirm callback, so an encoded/case/whitespace
  variant of a confirm-required tool's name fails the lookup ("tool not found")
  rather than bypassing confirmation. Locked by `test_tool_name_no_confirm_bypass`
  in `test_subagent_caps.c`.
- [~] **M-9: libevent thread safety** — **deferred (no reproduction).** The
  finding is non-specific; the web/mock event loops already call
  `evthread_use_pthreads`, and cross-thread wakeups go through the pipe (M-2) and
  the bus, not raw libevent calls. Revisit only with a concrete repro.
- [x] **M-10: IRC reconnect state** — **verified ok.** The reconnect loop resets
  `backoff`, `ping_pending`, and `last_recv`, and `irc_connect` re-runs the full
  NICK/USER/JOIN handshake, so no stale protocol state survives a reconnect. No
  code change.

**Status (2026-06-27):** ✅ done. Two real fixes (M-2 compile-verified, M-4 with
pure decision + test); M-5/M-6/M-7/M-10 verified already-closed (M-7 gets a
regression test); M-9 deferred with rationale.

### 4.9 Microsandbox exec (optional)

**Source:** todo.md

**Prerequisite:** KVM host + microsandbox-server operational acceptance

- [ ] `exec_mode: microsandbox` config value
- [ ] `src/tools/msb_client.c` JSON-RPC to localhost:5555
- [ ] Route `exec` / `exec_background` through microVM when enabled
- [ ] Deny patterns still run first; fallback to Landlock with loud warning
- [ ] Kconfig **default n**

**Smol note:** Strong security story but **external dependency** — not core smol.

### 4.10 Updater split spike

**Source:** todo.md

> **Decision (Q4, 2026-06-26): DO NOT SPLIT.** curl/cJSON are linked
> unconditionally and OpenSSL is already conditional, so a separate binary saves
> little while adding atomic-replace + version-sync complexity. This task reduces
> to **measurement only**: record updater code size with section-GC (task 0.4)
> on/off. See `autonomy-readiness.md` §3.

- [ ] Measure updater code size with/without `--gc-sections` (task 0.4)
- [ ] Revisit a split **only** if >50 KB savings is proven *and* the deps are not otherwise linked

### 4.11 Global session search

**Source:** Hermes `session_search` tool — FTS over all stored sessions.

**Files:** new `src/tools/session_search.c`, `src/session_index.c` (or extend `memory_index.c`),
`tests/test_session_search.c`

- [ ] Kconfig `SC_ENABLE_SESSION_SEARCH` (default **n**)
- [ ] Index session JSON files under `{SMOLCLAW_HOME}/sessions/` with FTS5 (reuse SQLite amalgamation)
- [ ] Tool actions: `search` (query → matching turns/snippets), `list` (recent sessions)
- [ ] On-demand indexing — defer full rebuild until first search (align with 0.8 deferred init)
- [ ] Does not replace `memory_search` (long-term facts vs conversation recall)
- [ ] Cap result payload size (reuse `output_filter` patterns)

**Hermes parity:** "did we discuss X last week?" without loading full session into context.

### 4.12 Agent-initiated compact tool

**Source:** [`docs/progress-2026-04-06.md`](../../progress-2026-04-06.md) — designed, not implemented.

**Files:** `src/tools/` (new `compact_tool.c` or extend session tool), `src/agent_session.c`

- [ ] Register `compact` tool (or `session_compact`) callable by agent mid-workflow
- [ ] Triggers same summarization path as `/compress` slash command (2.10)
- [ ] Cooldown guard: min interval between compactions (config, default 5 min)
- [ ] Budget guard: refuse if session below threshold (avoid pointless compaction)
- [ ] Scratchpad + action log reinjection preserved (existing compaction resilience)

**Complements:** Phase 1 auto-compaction (proactive) vs agent-initiated (explicit).

### 4.13 Post-turn memory review (Tier 4)

**Source:** Hermes background self-improvement review (subset — memory only, no `skill_manage`).

**Files:** `src/agent_session.c`, `src/memory.c`, `src/sc_task_t` (from 0.7)

- [ ] Config: `memory.background_review.enabled` (default **false**)
- [ ] After successful turn: async task (reuse summarization thread pattern) with compact turn digest
- [ ] Propose 0–2 memory entries via existing `memory_write` paths
- [ ] Optional: run on cheaper/auxiliary provider (`memory.background_review.provider` / `model`)
- [ ] Optional gateway notification: `memory_notifications`: `off` | `on` | `verbose` (config)
- [ ] **Out of scope:** autonomous skill creation, `/learn`, Skills Hub, Honcho (use MCP Tier 2)

**Smol contract:** opt-in; no extra runtime deps; uses existing memory + sc_task_t infrastructure.

### 4.14 Staged memory writes + capacity headers (Tier 4)

**Source:** Hermes `memory.write_approval` and bounded MEMORY.md capacity display.

**Files:** `src/memory.c`, `src/tools/memory_tools.c`, `src/context.c`, `src/main.c`

- [ ] Config: `memory.write_approval`: `false` (default) | `true`
- [ ] When `true`: foreground and background review writes stage to `{SMOLCLAW_HOME}/pending/memory/`
- [ ] CLI: `smolclaw memory pending|approve|reject` (mirror Hermes `/memory pending`)
- [ ] Web API: optional `GET/POST /api/memory/pending` (if `SC_ENABLE_WEB`)
- [ ] System prompt: show memory capacity usage % and char counts in memory block header
- [ ] Duplicate detection on add (existing entries rejected with success/no-op message)

**Explicitly not in 4.14:** `skill_manage`, skill write approval, external memory providers.

---

## 3. Exit Criteria

- [ ] Each shipped item has tests + Kconfig gate where applicable
- [ ] Project memory and microsandbox **not** in default release profile
- [ ] No Phase 4 item required for core agent operation
- [ ] `session_search` and Tier 4 learning loop **default off** in config and Kconfig
- [ ] Background review does not run when `memory.background_review.enabled` is false

---

## 4. Recommended order within Phase 4

1. **4.8** audit mediums (stability)
2. **4.1** arena (provider reliability)
3. **4.4** old result compression (quick win)
4. **4.3** prompt caching (Anthropic users)
5. **4.2** MCP capabilities (security)
6. **4.7** prompt budget CLI
7. **4.6** doctor CLI
8. **4.5** project memory (largest)
9. **4.12** agent compact tool (quick win after 2.10 slash `/compress`)
10. **4.11** session search (Kconfig off by default)
11. **4.13** post-turn memory review (Tier 4, opt-in)
12. **4.14** staged memory writes (Tier 4, pairs with 4.13)
13. **4.10** updater spike
14. **4.9** microsandbox (ops-heavy)

---

## 5. Risks

| Risk                          | Mitigation                                              |
|-------------------------------|---------------------------------------------------------|
| Context pipeline scope creep  | **Not in Phase 4** — see Phase 5                        |
| Project memory secret leakage | Skip `.env`, credentials paths (SmallHarness skip list) |
| Arena double-free             | Arena owns turn-scoped only; document ownership         |
| Microsandbox ops burden       | Document as advanced; default off                       |

---

## 6. Slice log

- **Slice 1 — `task/4.8-audit-mediums` (task 4.8)** — 2026-06-27. Closed the
  remaining audit Medium subset. Two real fixes: **M-2** web pipe partial-read
  leak (`_Static_assert(sizeof(web_response_t) <= PIPE_BUF)` enforcing atomic
  pipe writes) and **M-4** session unbounded-growth backstop (pure
  `sc_session_force_prune_due` + force-prune via `sc_session_truncate` in
  `sc_maybe_summarize`). Verified-already-closed: M-5 (atomic config load), M-6
  (finite MCP timeouts), M-10 (IRC reconnect resets state); M-7 verified
  not-exploitable + regression test (`test_tool_name_no_confirm_bypass`). M-9
  deferred (no concrete repro). New tests in `test_session.c` +
  `test_subagent_caps.c`.
  **Verification gates:** Release `-DSC_ENABLE_WEB=ON` build clean (KC-2
  `implicit`=0); `ctest` 49/49; `check_size_budget.sh` minimal-dynamic 273 KB ≤
  1024 KB; `check_claude_md.sh` clean; no new Kconfig flag (KC-1 N/A).
- **Slice 2 — `task/4.4-compress-old-results` (task 4.4)** — 2026-06-27. Recon
  found the core (compress old tool results via the transform hook) already
  shipped as `mask_old_observations`; this slice adds the unmet "Gate: config"
  deliverable. New `agents.defaults` fields `compress_tool_results` /
  `compress_keep_recent` / `compress_min_bytes` (defaults preserve prior
  behavior), pure decision `sc_mask_should_compress()`, transform reads them via
  the agent + honors hot-reload. Test in `test_agent.c`; CONFIGURATION.md
  documents the keys.
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest` 49/49;
  `check_size_budget.sh` minimal-dynamic 273 KB ≤ 1024 KB; `check_claude_md.sh`
  clean; no new Kconfig flag (KC-1 N/A).

---

**Next phase:** [Phase 5 — Defer / Reject](phase-5-defer-reject.md)
