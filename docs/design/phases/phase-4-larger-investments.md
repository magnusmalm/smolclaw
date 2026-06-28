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

- [x] Config `capabilities` per MCP server (network, fs_read, fs_write, process)
  — fs_read/fs_write/process pre-existed; **network added this slice**
- [x] Translate to per-server Landlock + seccomp rules — fs caps via Landlock
  (pre-existing); **seccomp rewritten to be capability-aware** so `process` and
  `network` are actually enforced
- [x] Missing capabilities → current blanket sandbox (backward compatible) —
  the runtime-built filter is equivalent in effect to the prior static denylist
  when no caps are set

**Recon (2026-06-27):** fs caps were already wired via Landlock, but
`no_process` was **parsed-but-dead** (the seccomp filter was a static array that
ignored `opts`) and `network` did not exist. This slice made the seccomp filter
capability-aware (fixing the dead `no_process`) and added the `network` cap.

**Status (2026-06-27):** ✅ done. `apply_seccomp(opts)` now builds the BPF
denylist at runtime: base list (unchanged) + `execve/fork/clone` set when
`process: []`, + `socket/connect` set when `network: []`/`false`.
`sc_mcp_capabilities_t.no_network` + `sc_sandbox_opts_t.cap_no_network` + config
parse + bridge/client wiring. Fork-based `test_sandbox` probes verify each cap
blocks and that defaults still allow (×4).

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

- [x] `smolclaw context [session_key]` — byte/token breakdown: system prompt,
  tool schemas, conversation history, tool results, total, and % of the model
  context window. Read-only (no provider call).
- [x] Warn threshold configurable — `agents.defaults.context_warn_pct` (default
  80; 0 = never), overridable per-invocation with `--warn-pct N`.

**Status (2026-06-27):** ✅ done. New `cmd_context` (main.c) + pure helpers
`sc_context_estimate_tokens` / `sc_context_budget_warn` (context.c, unit-tested
in `test_context_isolation.c`) + `context_warn_pct` config. Token counts are the
~4-chars/token estimate, not a tokenizer.

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

- [x] Measure updater code size with/without `--gc-sections` (task 0.4)
- [x] Revisit a split **only** if >50 KB savings is proven *and* the deps are not
  otherwise linked — **neither condition holds; no split.**

**Measurement (2026-06-27, MinSizeRel = LTO + `--gc-sections`, stripped,
dynamic build):**

| Configuration | Stripped size | Updater delta |
|---------------|---------------|---------------|
| minimal baseline (updater off) | 282,872 B | — |
| minimal + updater (sole OpenSSL user) | 291,128 B | **+8,256 B (8.0 KB)** |
| minimal + vault (OpenSSL already linked) | 295,320 B | — |
| minimal + vault + updater | 303,536 B | **+8,216 B (8.0 KB)** |

The two updater deltas are within ~40 bytes of each other, confirming the
updater's cost is **purely its own ~8 KB of code**: OpenSSL (its only notable
dependency) is **dynamically linked** in the default dynamic build, so it adds
no static binary weight, and curl/cJSON are linked unconditionally regardless.

**Conclusion: DO NOT SPLIT (confirms Q4).** A separate updater binary would save
at most ~8 KB — and only in builds that enable `SC_ENABLE_UPDATER` — while adding
atomic-replace and version-sync complexity. The 50 KB bar is not met (8 KB), and
the deps are otherwise linked / shared. Revisit only if a future change pushes
the updater's *own* code past 50 KB.

**Status (2026-06-27):** ✅ done (measurement spike; no code change).

### 4.11 Global session search

**Source:** Hermes `session_search` tool — FTS over all stored sessions.

**Files:** new `src/tools/session_search.c`, `src/session_index.c` (or extend `memory_index.c`),
`tests/test_session_search.c`

- [x] Kconfig `SC_ENABLE_SESSION_SEARCH` (default **n**, `depends on
  SC_ENABLE_MEMORY_SEARCH` for the FTS5 build); KC-1 wired
- [x] Index session `.jsonl`/`.json` files under `{workspace}/sessions/` with
  FTS5 via the existing `sc_memory_index_rebuild_dir` (source prefix `session:`)
- [x] Tool actions: `search` (query → matching sessions + snippets), `list`
  (recent sessions by mtime)
- [x] On-demand indexing — the tool builds its index lazily on the first
  `search` (own mutex-guarded lazy init; `list` needs no index)
- [x] Does not replace `memory_search` (separate tool + separate index DB at
  `sessions/.session_search.db`)
- [x] Cap result payload size — `max_results` clamped to 50; FTS5 snippets bounded

**Status (2026-06-27):** ✅ done. New `src/tools/session_search.{c,h}` reusing
`memory_index` FTS5; registered behind `#if SC_ENABLE_SESSION_SEARCH`. Tests in
`test_session_search.c` (construct/list/match/no-match/requires-query).

**Hermes parity:** "did we discuss X last week?" without loading full session into context.

### 4.12 Agent-initiated compact tool

**Source:** [`docs/progress-2026-04-06.md`](../../progress-2026-04-06.md) — designed, not implemented.

**Files:** `src/tools/` (new `compact_tool.c` or extend session tool), `src/agent_session.c`

- [x] Register `compact` tool callable by agent mid-workflow (`src/tools/compact.c`,
  registered next to spawn; always available)
- [x] Triggers same summarization path as `/compress` — both now route through
  the shared `sc_agent_compact_session()` (slash.c refactored to reuse it)
- [x] Cooldown guard: `compact_cooldown_secs` (config, default 300); pure
  decision `sc_compact_cooldown_ok()` (unit-tested). The slash command is
  deliberately NOT rate-limited (human intent)
- [x] Budget guard: refuses when session is at/below `keep_last` (returns a
  "already compact" message)
- [x] Scratchpad + action log reinjection preserved (reuses the existing
  `sc_maybe_summarize` compaction path unchanged)
- [x] Tool reaches the in-flight session via a new borrowed `agent->active_session_key`
  set per-turn in `run_agent_loop` (save/restore handles spawn reentrancy)

**Complements:** Phase 1 auto-compaction (proactive) vs agent-initiated (explicit).

**Status (2026-06-27):** ✅ done. `compact` tool + shared
`sc_agent_compact_session` + cooldown/budget guards + `compact_cooldown_secs`
config. Pure `sc_compact_cooldown_ok` tested in `test_agent.c`.

### 4.13 Post-turn memory review (Tier 4)

**Source:** Hermes background self-improvement review (subset — memory only, no `skill_manage`).

**Files:** `src/agent_session.c`, `src/memory.c`, `src/sc_task_t` (from 0.7)

- [x] Config: `memory_background_review` (default **false**, flat under
  `agents.defaults`)
- [x] After successful turn: async `sc_task_t` (reuses the summarization task
  pattern) with a compact turn digest (user msg + final response, bounded)
- [x] Propose 0–2 memory entries → written via `sc_memory_write_long_term`
- [x] Optional cheaper model: `memory_review_model` (provider override deferred;
  model override on the same provider covers the "cheaper aux" intent)
- [~] `memory_notifications` (`off`|`on`|`verbose`) — implemented as **log
  verbosity** for now; cross-thread gateway *publish* deferred (the background
  task has no channel/chat context)
- [x] **Out of scope:** skill creation / `/learn` / Honcho — not built

**Status (2026-06-27):** ✅ done (mock-accepted). New `src/memory_review.{c,h}`:
pure `sc_memory_review_should_run` + `sc_memory_review_parse` (tested) + async
worker mirroring consolidation. Isolated turns skipped (no shared-memory leak).
🟠 **Live LLM acceptance is a human gate** (needs a provider).

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
- **Slice 3 — `task/4.7-prompt-budget-cli` (task 4.7)** — 2026-06-27. New
  `smolclaw context [session_key] [--warn-pct N]` CLI: byte/token breakdown of
  system prompt, tool schemas, conversation history, and tool results, with
  context-window % and a configurable warn threshold
  (`agents.defaults.context_warn_pct`, default 80). Pure helpers
  `sc_context_estimate_tokens` / `sc_context_budget_warn` (context.c) unit-tested
  in `test_context_isolation.c`; read-only (no provider call). CONFIGURATION.md +
  README updated.
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest` 49/49;
  `check_size_budget.sh` minimal-dynamic 273 KB ≤ 1024 KB; `check_claude_md.sh`
  clean; no new Kconfig flag (KC-1 N/A).
- **Slice 4 — `task/4.12-compact-tool` (task 4.12)** — 2026-06-27.
  Agent-initiated `compact` tool (`src/tools/compact.{c,h}`) that summarizes the
  current session mid-workflow. New shared `sc_agent_compact_session()` (slash
  `/compress` refactored to reuse it), cooldown guard
  (`compact_cooldown_secs`/`sc_compact_cooldown_ok`, default 300s) + budget
  guard, and a per-turn borrowed `agent->active_session_key` (save/restore for
  spawn reentrancy) so the tool can target the in-flight session. Test in
  `test_agent.c`; CONFIGURATION.md updated.
  **Verification gates:** Release build clean (KC-2 `implicit`=0 after adding the
  `util/json_helpers.h` include); `ctest` 49/49; `check_size_budget.sh`
  minimal-dynamic 277 KB ≤ 1024 KB (+4 KB for the tool); `check_claude_md.sh`
  clean; no new Kconfig flag (KC-1 N/A).
- **Slice 5 — `task/4.2-mcp-capabilities` (task 4.2)** — 2026-06-27. Made the MCP
  per-server capability sandbox actually enforce process/network. Recon found fs
  caps already wired (Landlock) but `no_process` parsed-but-dead and `network`
  missing. Rewrote `apply_seccomp` to build the BPF denylist at runtime
  (capability-aware): base list unchanged + `execve/execveat/fork/vfork/clone/
  clone3` when `process: []`, + `socket/connect` (+`socketcall` on 32-bit) when
  `network: []`/`false`. Added `no_network` to caps + sandbox opts + config parse
  + bridge/client wiring. New fork-based `test_sandbox` probes (×4: each cap
  blocks; defaults allow). CONFIGURATION.md updated.
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest` 49/49
  incl. `test_sandbox` 30/30 (seccomp probes pass — caps block, defaults allow);
  `check_size_budget.sh` minimal-dynamic 277 KB ≤ 1024 KB; `check_claude_md.sh`
  clean; no new Kconfig flag (KC-1 N/A).
- **Slice 6 — `task/4.11-session-search` (task 4.11)** — 2026-06-27. New
  `session_search` tool (FTS5 over stored transcripts), gated by
  `SC_ENABLE_SESSION_SEARCH` (default n, `depends on SC_ENABLE_MEMORY_SEARCH`).
  Reuses `sc_memory_index_rebuild_dir` (prefix `session:`) over `.jsonl`/`.json`
  under `sessions/`; index built lazily on first search (own mutex). Actions
  `search` + `list`. New `src/tools/session_search.{c,h}`, agent registration,
  KC-1 wiring, `test_session_search.c` (5 cases). README + phase doc updated.
  **Verification gates:** Release `-DSC_ENABLE_SESSION_SEARCH=ON` build clean
  (KC-2 `implicit`=0); `ctest` 50/50 incl. `test_session_search`; minimal
  (flag off) 277 KB ≤ 1024 KB; KC-1 satisfied (genconfig disables it in minimal);
  `check_claude_md.sh` clean.
- **Slice 7 — `task/4.10-updater-spike` (task 4.10)** — 2026-06-27. Measurement
  spike (no code change). Measured the updater's binary-size contribution under
  section-GC: **8.0 KB stripped**, near-identical whether or not OpenSSL is
  otherwise linked (OpenSSL is dynamic → no static weight). 8 KB ≪ the 50 KB
  split bar → **confirmed Q4: do not split.** Findings recorded in §2 task 4.10.
  **Verification gates:** N/A (no source change); four MinSizeRel builds compiled
  clean for the measurement.
- **Slice 8 — `task/4.13-memory-review` (task 4.13)** — 2026-06-27. Opt-in
  post-turn memory review (default off). New `src/memory_review.{c,h}`: pure
  `sc_memory_review_should_run` + `sc_memory_review_parse` (JSON array, fence
  strip, cap, blank-skip) and an async `sc_task_t` worker mirroring the
  consolidation LLM call → writes 0–2 entries via `sc_memory_write_long_term`.
  Config `memory_background_review`/`memory_review_model`/`memory_notifications`;
  run_agent_loop hook (skips isolated turns); agent-destroy drains the task.
  `test_memory_review.c` (7 cases). **Live LLM acceptance = human gate.**
  **Verification gates:** Release + minimal builds clean (KC-2 `implicit`=0 after
  moving the include out of the `#if SC_ENABLE_MEMORY_SEARCH` guard); `ctest`
  50/50 incl. `test_memory_review`; `check_size_budget.sh` minimal-dynamic 281 KB
  ≤ 1024 KB (+4 KB always-compiled); `check_claude_md.sh` clean; no Kconfig flag.

---

**Next phase:** [Phase 5 — Defer / Reject](phase-5-defer-reject.md)
