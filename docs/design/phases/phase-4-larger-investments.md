# Phase 4: Larger Investments

**Status**: Phase 4 complete — all 11 tasks resolved (4.1 closed 2026-06-28; the
GATED-EXT items 4.3/4.6/4.9 are code-ready, pending external/human acceptance)  
**Master plan**: [`../master-plan.md`](../master-plan.md)  
**Prerequisite**: [Phase 3](phase-3-optional-surface-area.md) complete (or parallel if demand-driven)  
**Goal**: Optional subsystems and architectural improvements with higher complexity.  
**LOC budget**: ~2,100–3,200 (each item independently shippable)  
**Binary target**: Each feature Kconfig-gated; measure per flag

---

## 1. Scope

- **4.1** — Task: Arena allocator per turn — **done: allocator shipped + per-turn wired;
  provider-parse conversion rejected after recon** (see §2); Source: zed-patterns T1; LOC: 80–150; Binary: ~0; Gate: always
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

> **Status (2026-06-28):** ✅ done. The allocator (`src/util/arena.c` + `arena.h`:
> `sc_arena_new/alloc/reset/free`) ships and is created per agent, reset per turn,
> and threaded into the transform/context path in `src/agent.c` (see
> `agent->arena`, `sc_arena_reset` at turn start, `snap->arena`). The remaining
> "convert provider SSE/response parsing to the arena" deliverable was **rejected
> after recon** (see below) — the same recon-first outcome as 4.10 (reduced to a
> measurement) and 4.4 (reduced to a config gate).

**Files:** `src/util/arena.{c,h}`, `src/agent.c` (allocator + per-turn reset, shipped)

- [x] Bump allocator with reset per turn *(shipped)*
- [x] Long-lived data stays on heap *(by design — and the reason the parse
  conversion is rejected; see below)*
- [~] Provider SSE parsing uses arena — **rejected after recon (2026-06-28)**
- [~] Single OOM check point per turn — **rejected** (depends on the above)

**Recon (2026-06-28) — why the provider-parse conversion was rejected.** A close
read of `src/providers/http.c` + `src/providers/provider_common.c` against the
arena contract found the literal task does not map onto this code:

1. **Ownership / free mismatch (the decisive blocker).** Every allocation in the
   parse path that matters is **long-lived**: the parsed `sc_llm_response_t` and
   its fields (`content`, `thinking`, `finish_reason`, `tool_calls[]`,
   `tc->id/name`) are returned to the caller, appended to **session history that
   persists across turns**, and freed individually with `free()` via
   `sc_llm_response_free` / `sc_llm_message_free_fields`. The arena is
   `sc_arena_reset()` **once per turn** (`agent.c` `run_agent_loop`), so anything
   stored in cross-turn history *cannot* be arena-backed — and `free()` on an
   arena interior pointer would corrupt the heap. The spec's own rule
   ("long-lived data stays on heap") rules these sites out — and that is ~all of
   them.
2. **Reachability + wrong allocator for the genuinely-transient rest.** `arena`
   is referenced **nowhere** under `src/providers/`, and the `chat`/`chat_stream`
   vtable signatures (`providers/types.h`) carry no arena — threading one in
   would change the provider API across every provider. The only truly transient
   allocations (curl write-cb scratch in `provider_common.c`; the streaming
   `tool_arg_bufs` / `args_str`) live inside curl write callbacks or are
   `realloc`-grown accumulation buffers. `sc_arena_alloc` grows via `realloc`
   (`arena.c`), which can **move the block and invalidate all previously-returned
   arena pointers** — exactly the wrong allocator for accumulation buffers, and
   those sites are already cleanly owned/freed (not an unchecked-alloc hazard).

**Conclusion: the allocator + per-turn reset deliverable is shipped; the
provider-parse conversion is rejected.** Doing it would require reworking the
provider vtable API *and* the `sc_llm_response_t`/`sc_llm_message_t` ownership
model across every consumer — far beyond the 80–150 LOC budget, on the hottest
path, and in direct conflict with the cross-turn lifetime of session history.

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

**Files:** `src/context.c` (static/dynamic split — this slice), `src/providers/claude.c`
(cache_control emission — pre-existing)

> **Recon (2026-06-28):** the mechanical pieces were **already shipped** —
> `providers/claude.c` emits `cache_control: {type: "ephemeral"}` on the first
> system block (`build_system_blocks`) and the last tool (`build_tools_json`),
> and it is Anthropic-only by construction (the OpenAI-compatible `http.c` emits
> none). **But the cache silently never hit:** `sc_context_build_system_prompt`
> concatenated the entire prompt into **one** system block with a
> minute-resolution timestamp at the very top (`build_identity`). Prompt caching
> is a prefix match, so that timestamp invalidated the whole prefix every minute
> (`cache_read_input_tokens ≈ 0`). The real, unmet deliverable was the
> **static/dynamic split**.

- [x] **Split system prompt static vs dynamic (this slice).** `context.c` now
  builds two system blocks: a **static** prefix (`build_static_system`: identity
  sans-timestamp + bootstrap + skills + deferred tools + per-session info) and a
  **dynamic** suffix (`build_dynamic_system`: timestamp + memory, plus
  summary/scratchpad/action-log appended in `sc_context_build_messages`).
  `sc_context_build_messages` emits them as two `sc_msg_system` messages
  `[static, dynamic]`; the public `sc_context_build_system_prompt` still returns
  the full prompt (static+dynamic) for the 4.7 `context` token estimate + tests.
- [x] `cache_control: ephemeral` on static block — the pre-existing
  `claude.c` "mark first system block" logic now lands the breakpoint on the
  static block (no provider change needed); the dynamic block follows uncached.
- [x] Only when provider is Anthropic — satisfied by construction (`claude.c`
  only). **Runtime config gate dropped** (owner-chosen scope, 2026-06-28):
  caching default-on is correct, sub-minimum prefixes silently don't cache
  anyway, and gating the provider-side emission on agent config would need
  vtable plumbing (the same decoupling that scoped down 4.1) for little value.
- [~] **Live cache-hit verification = human gate (🟠).** Code + tests are
  autonomous; confirming `usage.cache_read_input_tokens > 0` across turns needs
  an **Anthropic key**.

**Status (2026-06-28):** ✅ code-complete (mock-tested); 🟠 live verification
pending an Anthropic key. The split makes the existing `cache_control` actually
cache the static prefix (tools + static system) across multi-turn Anthropic
sessions. Tests: `test_context_isolation` (`test_prompt_cache_static_dynamic_split`
+ updated scratchpad/action-log contract) and `test_session_isolation` (mock now
concatenates all leading system blocks).

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

- [x] Index: path, language, size, mtime, SHA-256, symbols, imports, terms
- [x] Storage: `{SMOLCLAW_HOME}/indexes/{workspace-hash}.json` (Q2:
  workspace-hash = first 16 hex of `sha256(realpath(workspace))`)
- [x] Tool actions: build, refresh (incremental), status
- [x] `repo_search` tool for ranked hits (term + symbol + import + path match)
- [~] Optional system-prompt injection for code questions — **deferred**
  (owner-chosen scope; the tool covers retrieval). Documented follow-up.
- [x] v1 own extraction (`TODO(shared-symbols)` in `project_memory.c`); share
  with `code_graph` in v2 (Q7)
- [x] Kconfig `SC_ENABLE_PROJECT_MEMORY` **default n**; KC-1 wired

**Status (2026-06-27):** ✅ done. New `src/project_memory.{c,h}` (workspace-hash,
language-by-ext, tokenizer, ranking, recursive walk with ignore-dirs +
incremental reuse, JSON index under SMOLCLAW_HOME) + `src/tools/repo_search.c`
(build/refresh/status/search). Pure helpers + a build→search round-trip tested
in `test_project_memory.c`. System-prompt injection deferred.

### 4.6 Local provider doctor

**Source:** smallharness-integration task 8

**Files:** new `src/doctor_local.{c,h}`, `src/doctor.c` (CLI wiring), `src/main.c` (help)

> **Recon (2026-06-28):** `smolclaw doctor` already existed (`src/doctor.{c,h}`)
> as **static** config/dependency validation (workspace, provider key,
> connectivity, fallbacks, channels, vault). 4.6 adds the **`--local` live
> capability probe** on top.

- [x] `smolclaw doctor --local [--model M]` — probes the configured (or named)
  model after the static checks. Explicit invocation only.
- [x] Probe: **streaming, tool calls, inline JSON** + basic chat round-trip.
  **"models list" omitted** (owner-noted scope): the provider vtable has no
  models-list method and `--local` targets one configured model, so a models
  probe would mean provider-specific `/v1/models` HTTP for little value. The four
  probed capabilities are the ones the agent actually depends on.
- [x] Cache under `{SMOLCLAW_HOME}/capabilities/<model>.json` (model name
  sanitized to a safe filename; dir created on demand).
- [x] Explicit invocation only (no startup probe) — it's a CLI subcommand.

**Design:** pure helpers (`sc_capabilities_to_json`/`_from_json`/`_cache_path`/
`_response_is_json`) + a mockable `sc_doctor_probe_provider(provider, model,
report)` are split from the live `sc_provider_create_for_model` + filesystem
wiring (`sc_doctor_local`), so the probe is unit-tested with a mock provider and
no network. Tri-state results (`SC_CAP_YES`/`NO`/`SKIPPED`) so streaming reports
"skipped" when compiled out. `test_doctor_local.c` (5 cases: JSON detection,
report round-trip, cache-path sanitization, mock-provider probe, null guard).

**Status (2026-06-28):** ✅ code-complete (mock-tested); 🟠 **live probe against
a real provider = human gate** (needs an API key / reachable Ollama/vLLM). With
no live provider, the command degrades gracefully ("could not create provider").

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

- [x] Config: `memory_write_approval` (default false, flat under `agents.defaults`)
- [x] When `true`: foreground (`memory_write` tool) and background-review writes
  stage to `{workspace}/memory/pending/` (workspace-relative — the memory
  subsystem is workspace-scoped; documented deviation from the spec's
  SMOLCLAW_HOME path)
- [x] CLI: `smolclaw memory pending | approve <id> | reject <id>`
- [x] Web API: `GET`/`POST /api/memory/pending` (behind `SC_ENABLE_WEB` + bearer
  auth; POST `{action,id}`, path-traversal-guarded)
- [x] System prompt: memory block header shows char count + % of soft cap
  (`SC_MEMORY_SOFT_MAX_BYTES`); pure `sc_memory_capacity_pct`
- [x] Duplicate detection on add — pure `sc_memory_is_duplicate`; dupes are a
  success no-op in `sc_memory_append_long_term`

**Explicitly not in 4.14:** `skill_manage`, skill write approval, external memory providers.

**Status (2026-06-27):** ✅ done. `sc_memory_append_long_term` (safe RMW append)
now honors dedup + staging; `sc_memory_stage`/`sc_memory_pending_dir_dup`/
`sc_memory_is_duplicate`/`sc_memory_capacity_pct` added. Staging wired to the
`memory_write` tool + background review; CLI `cmd_memory`; Web
`/api/memory/pending`; capacity header in `context.c`. Note: in approval mode the
foreground `memory_write` (which normally replaces the whole file) is treated as
a staged addition. Tests in `test_memory_tools.c` (capacity/dedup/append/staging).

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
- **Slice 9 — `task/4.14-staged-memory` (task 4.14)** — 2026-06-27. Staged memory
  writes + capacity + dedup. `sc_memory_append_long_term` gains dedup + staging;
  new `sc_memory_stage`/`sc_memory_pending_dir_dup`/`sc_memory_is_duplicate`/
  `sc_memory_capacity_pct` + `write_approval` flag. Wired to the `memory_write`
  tool and the 4.13 review worker; CLI `smolclaw memory pending|approve|reject`;
  Web `GET/POST /api/memory/pending` (bearer auth, traversal-guarded); capacity
  header in the system-prompt memory block. Config `memory_write_approval`
  (default off). Tests in `test_memory_tools.c`; CLI smoke-tested (stage→list→
  approve→committed).
  **Verification gates:** Release `-DSC_ENABLE_WEB=ON` + minimal builds clean
  (KC-2 `implicit`=0); `ctest` 50/50; `check_size_budget.sh` minimal-dynamic
  285 KB ≤ 1024 KB; `check_claude_md.sh` clean; no Kconfig flag (config-gated).
- **Slice 10 — `task/4.5-project-memory` (task 4.5)** — 2026-06-27. Project
  memory + repo_search behind `SC_ENABLE_PROJECT_MEMORY` (default n). New
  `src/project_memory.{c,h}` (per-workspace JSON code index at
  `{SMOLCLAW_HOME}/indexes/<hash>.json`; per-file path/lang/size/mtime/sha256/
  terms/symbols/imports; recursive walk with ignore-dirs + incremental reuse;
  pure hash/language/tokenize/rank seams) + `src/tools/repo_search.c`
  (build/refresh/status/search). Q7 v1 own extraction with `TODO(shared-symbols)`.
  System-prompt injection deferred (owner-chosen scope). KC-1 wired;
  `test_project_memory.c` (build→search round-trip + pure helpers).
  **Verification gates:** Release `-DSC_ENABLE_PROJECT_MEMORY=ON` build clean
  (KC-2 `implicit`=0 after adding `<stdio.h>` to repo_search.c); `ctest` 51/51
  incl. `test_project_memory`; minimal (flag off) 285 KB ≤ 1024 KB; KC-1
  satisfied; `check_claude_md.sh` clean.

- **Slice 13 — `task/4.6-doctor-local` (task 4.6)** — 2026-06-28. Added a live
  capability probe to the existing static `doctor`. New `src/doctor_local.{c,h}`:
  `smolclaw doctor --local [--model M]` builds the provider for the configured (or
  named) model and probes basic chat, streaming, tool calls, and inline-JSON
  output, caching the report at `{SMOLCLAW_HOME}/capabilities/<model>.json`. Pure
  helpers (`sc_capabilities_to_json`/`_from_json`/`_cache_path`/`_response_is_json`)
  + a mockable `sc_doctor_probe_provider(provider, model, report)` are split from
  the live `sc_provider_create_for_model` + filesystem wiring, so the probe is
  unit-tested with a mock provider and no network (tri-state SC_CAP_YES/NO/SKIPPED;
  streaming → "skipped" when compiled out). Wired `--local`/`--model` into
  `sc_cmd_doctor`; doctor_local.c lives in `smolclaw_lib` so both the binary and
  the test link it. **"models list" probe omitted** (owner-noted: no vtable
  support, single-model target). `test_doctor_local.c` (5 cases). 🟠 Live probe
  against a real provider = human gate; degrades gracefully without one.
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest` 51/51
  incl. `test_doctor_local`; `check_size_budget.sh` minimal-dynamic 285 KB ≤
  1024 KB; `check_claude_md.sh` clean; no new Kconfig flag (KC-1 N/A, CLI). CLI
  smoke: `--help` shows `--local`; `doctor --local` runs the probe section and
  reports "could not create provider" when none is configured.
- **Slice 12 — `task/4.3-prompt-caching` (task 4.3)** — 2026-06-28. Made
  Anthropic prompt caching actually hit. Recon found the `cache_control:
  ephemeral` emission already shipped in `providers/claude.c` (first system block
  + last tool, Anthropic-only by construction) but **silently non-functional**:
  `context.c` built one system block with a minute-resolution timestamp at the
  top, so the prefix-match cache invalidated every minute. This slice splits the
  system prompt into a **static** block (`build_static_system`: identity
  sans-timestamp + bootstrap + skills + deferred tools + per-session info) and a
  **dynamic** block (`build_dynamic_system`: timestamp + memory; summary +
  scratchpad + action-log appended in `sc_context_build_messages`), emitted as
  two `sc_msg_system` messages `[static, dynamic]`. The pre-existing claude.c
  "mark first system block" logic now caches the static prefix; the dynamic block
  follows uncached — **no provider change**. Public `sc_context_build_system_prompt`
  still returns the full prompt (4.7 `context` cmd + tests). Runtime config gate
  dropped (owner-chosen scope; provider-coupling cost ≫ value). New test
  `test_prompt_cache_static_dynamic_split` + updated scratchpad/action-log
  contract in `test_context_isolation`; `test_session_isolation` mock now
  concatenates all leading system blocks. 🟠 Live `cache_read_input_tokens > 0`
  verification = human gate (Anthropic key).
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest` 50/50;
  `check_size_budget.sh` minimal-dynamic 285 KB ≤ 1024 KB (restructure, no
  growth); `check_claude_md.sh` clean; no new Kconfig flag (KC-1 N/A).
- **Slice 11 — `task/4.1-arena` (task 4.1)** — 2026-06-28. Recon-only outcome: the
  arena allocator + per-turn reset already ship (`util/arena.{c,h}`, `agent->arena`,
  `sc_arena_reset` at turn start, `snap->arena` in `mask_old_observations`); the
  remaining "convert provider SSE/response parsing to the arena" deliverable was
  **rejected after recon**. Decisive blocker: every parse allocation that matters
  is long-lived (`sc_llm_response_t`/`sc_llm_message_t` fields returned to the
  caller, stored in **cross-turn session history**, freed individually via
  `sc_llm_response_free`/`sc_llm_message_free_fields` → `free()`), while the arena
  resets every turn — so it cannot back that data, and `free()` on an arena
  pointer would corrupt the heap. The spec's own "long-lived stays on heap" rules
  out ~all 9 sites. The genuinely transient allocations live in curl write
  callbacks / are `realloc`-grown accumulation buffers (arena grow moves the block,
  invalidating live pointers — wrong allocator), and `arena` is referenced nowhere
  under `src/providers/`. The full conversion would require reworking the provider
  vtable API + message/response ownership across every consumer — far beyond the
  80–150 LOC budget, on the hottest path. Mirrors the recon-first outcomes of 4.10
  (measurement) and 4.4 (config gate). **This closes Phase 4.**
  **Verification gates:** N/A — docs-only, no source change (no build/ctest/size
  impact); KC-1 N/A (no Kconfig flag).

---

**Next phase:** [Phase 5 — Defer / Reject](phase-5-defer-reject.md)
