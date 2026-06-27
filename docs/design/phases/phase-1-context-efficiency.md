# Phase 1: Context Efficiency

**Status**: Not started  
**Master plan**: [`../master-plan.md`](../master-plan.md)  
**Prerequisite**: [Phase 0](phase-0-safety-and-stability.md) complete  
**Goal**: Reduce token waste and improve local-model behavior without new channels.  
**LOC budget**: ~700–1,200  
**Binary target**: +≤40 KB with new config defaults unchanged (all new behavior opt-in)

---

## 1. Scope

- **1.1** — Task: Tool result spill-to-disk; Source: claude-code P0 #1; LOC: 80–120; Binary: +5 KB;
  Default: config threshold
- **1.2** — Task: Per-turn aggregate tool output cap; Source: claude-code P0 #1; LOC: 30–50; Binary:
  ~0; Default: config
- **1.3** — Task: Token-aware auto-compaction; Source: claude-code P0 #2; LOC: 80–120; Binary: ~0;
  Default: uses existing summarization
- **1.4** — Task: Reactive compaction on context error; Source: claude-code P0 #2; LOC: 40–60;
  Binary: ~0; Default: always safe
- **1.5** — Task: Adaptive tool selection (`auto`); Source: smallharness §6.1; LOC: 150–250; Binary:
  +5 KB; Default: **`fixed`** (current)
- **1.6** — Task: Streaming inline tool-call buffer; Source: smallharness §6.3; LOC: 80–120; Binary:
  ~0; Default: always
- **1.7** — Task: JSON-aware tool result compaction; Source: smallharness §6.4; LOC: 60–100; Binary:
  ~0; Default: always
- **1.8** — Task: Prompt prefix warmup (local providers); Source: smallharness §6.2; LOC: 80–120;
  Binary: +5 KB; Default: **`false`**

**Out of scope:** project memory, operator modes, OAuth, Signal.

---

## 2. Task Details

### 1.1–1.2 Tool result size management

**Source:** [`docs/claude-code-improvements.md`](../../claude-code-improvements.md) P0 #1

**Files:** `src/tools/registry.c`, `src/config.c`, `src/config.h`, `src/agent.c`, `tests/test_tools.c`

> **Status (2026-06-27):** the spill-to-disk core (1.1) and the per-turn
> cumulative cap (1.2) were **already shipped** — spill in
> `sc_tool_registry_execute`, the cap via `agents.defaults.max_output_total`
> (default 500 KB; stop-loop at `agent_turn.c`). This slice made the spill
> thresholds **configurable** (were hardcoded 50000/2000) and added a test.

- [x] Config: `max_tool_result_chars` (default 50000), `tool_result_preview_chars` (2000) — runtime
  config, env overrides, validation (preview clamped below threshold); wired via
  `sc_tool_registry_set_result_limits()`
- [x] Oversized `for_llm` → write `{workspace}/tool_outputs/{tool}_{ts}.txt` *(already shipped)*
- [x] Replace with preview + path hint for model *(already shipped)*
- [x] Per-turn cumulative cap → existing `max_output_total` (default 500 KB), stop-loop message *(verified)*
- [x] Full output remains in audit log / tee if enabled *(unchanged)*

**Acceptance:** `exec cat large_file` → preview in context, file on disk, `file_read` can recover.

**Verification gates (2026-06-27):** KC-2 clean (0 implicit); `ctest --test-dir build` **39/39**
(`configs/defconfig`); new `test_registry_result_spill_configurable` (spill + no-spill paths) and
`test_config` round-trip pass; minimal-dynamic size **245 KB ≤ 1024 KB**. No new Kconfig flag
(runtime config only).

### 1.3–1.4 Token-aware compaction

**Source:** claude-code P0 #2

**Files:** `src/agent_turn.c`, `src/agent_internal.h`, `tests/test_agent.c`

> **Status (2026-06-27):** 1.3 was **already shipped** (proactive token-aware
> trigger at `agent_turn.c`: when `last_prompt_tokens > 85% of context_window`
> → `sc_maybe_summarize`, with a 3-failure circuit breaker). 1.4 was
> **implemented but dead-wired** — `call_llm_with_fallback` collapses every
> non-200 (incl. 400) to `NULL`, so the `if (!resp) break;` fired before the
> `resp->http_status == 400` reactive block, which was unreachable. **Fixed**
> this slice: the helper now sets `tc.context_overflow` on a 400 context error
> before freeing the response, and the turn loop reacts on that flag.

- [x] Track `last_prompt_tokens` from provider usage *(shipped)*
- [x] Pre-call: if >85% of `context_window`, trigger sync summarization *(shipped, with breaker)*
- [x] Reactive: on HTTP 400 context-length errors, drop oldest message group and retry (×3)
  *(was unreachable; **fixed + regression test** `test_reactive_compaction_on_context_error`)*
- [x] Keep `session_summary_threshold` as fallback when usage unavailable *(unchanged)*

**Verification gates (2026-06-27):** KC-2 clean; `ctest --test-dir build` **39/39**;
`test_agent` 177/0 (incl. new reactive test); minimal-dynamic **245 KB ≤ 1024 KB**.

### 1.5 Adaptive tool selection

**Source:** [`smallharness-integration.md`](../smallharness-integration.md) task 1, SmallHarness `tools/mod.rs`

**Files:** new `src/tools/tool_selection.{c,h}`, `src/agent_turn.c`, `src/config.{c,h}`,
`src/agent.{c,h}`, `CMakeLists.txt`, new `tests/test_tool_selection.c`

> **Decision (Q1, 2026-06-26):** runtime config only — **no Kconfig flag**
> (+~8 KB is below the gating threshold and the default is no-op). See
> `autonomy-readiness.md` §3.

> **Status (2026-06-27): done.** New `tool_selection` module classifies the
> user message and compacts the tool-def array in place per turn when
> `tool_selection: auto`. Default `fixed` = unchanged behavior.

- [x] Config: `tool_selection`: `"fixed"` | `"auto"` (default **`fixed`**) — JSON, env override,
  serialization; wired to the agent and applied at `agent_turn.c` after `to_defs`
- [x] Keyword heuristics: greeting → only unknown tools; fileish → read/search/memory; editish →
  +write/edit; shellish → +exec; webish → web; ambiguous → keep all (never starve the model)
- [x] Ceiling = enabled tool pool (runs on the already-filtered `to_defs` output); **unknown/MCP/skill
  tools always kept** (except pure greetings)
- [x] Log selected tools at DEBUG (`SC_LOG_DEBUG`)

**Verification gates (2026-06-27):** KC-2 clean; `ctest --test-dir build` **40/40**;
new `test_tool_selection` 25/0 (greeting / fileish / editish / shellish / ambiguous / fixed paths),
`test_config` 102/0, `test_agent` 177/0; minimal-dynamic **253 KB ≤ 1024 KB**. No new Kconfig flag.

**Acceptance:** Ollama turn with "hello" sends zero tool schemas; "grep for config in src" sends read/search subset.

### 1.6 Streaming inline tool-call buffer

**Source:** smallharness-integration task 3

**Files:** new `src/providers/stream_buffer.{c,h}`, `src/agent_turn.c`
(`call_provider_with_retry`), new `tests/test_stream_buffer.c`

> **Status (2026-06-27): done.** A buffering wrapper sits between the provider
> and the channel callback: when streamed text starts with `{`, it withholds it
> until end-of-stream, then **suppresses** it if it looks like a tool call (the
> post-hoc extractor still parses it) or **flushes** it otherwise. Prose passes
> through immediately. Wrapped once in `call_provider_with_retry` (covers
> primary + fallback), fresh per attempt.

- [x] Detect start of inline JSON tool call during stream (`{"name":...`)
- [x] Buffer instead of emitting to channel until stream end
- [x] Parse with `arguments` / `parameters` / `args` aliases (`sc_stream_looks_like_tool_call`)
- [x] Tests: suppress tool call / pass prose / flush non-tool JSON / idempotent finish

### 1.7 JSON-aware compaction

**Source:** smallharness-integration task 4

**Files:** new `src/util/json_compact.{c,h}` (always compiled — **not**
`output_filter.c`, which is `SC_ENABLE_OUTPUT_FILTER`-gated), `src/agent_turn.c`
(`wrap_tool_output`), new `tests/test_json_compact.c`

> **Status (2026-06-27): done.** `sc_json_compact_for_llm` parses the tool
> result and, if JSON, truncates long string fields and caps big arrays,
> marking the object `compacted: true`. Applied in `wrap_tool_output` before the
> result enters history; **errors are never compacted**.

- [x] After tool execute, before session insert: compact JSON results
- [x] Cap string fields (`content`, `output`, `diff`, …) at ~4 KB with `...[truncated N chars]`
- [x] Cap arrays (`matches`, `entries`, …) at 50 items with `compacted: true` + `<key>_total`
- [x] Do not compact error payloads (`result->is_error` skipped)

**Verification gates (2026-06-27):** KC-2 clean; `ctest --test-dir build` **42/42**;
`test_json_compact` 13/0, `test_stream_buffer` 14/0, `test_agent` 177/0; minimal-dynamic
**257 KB ≤ 1024 KB**. No new Kconfig flags. 1.6's "no raw JSON flashes on a live Ollama stream"
is a manual 🟠 check; the buffer logic is unit-tested.

### 1.8 Prompt prefix warmup

**Source:** smallharness-integration task 2

**Files:** new `src/providers/warmup.c`, `src/providers/http.c`, `src/agent.c`

- [ ] Config: `local_optimizations.warmup` (default **false**)
- [ ] Provider allowlist: ollama, vllm (configurable)
- [ ] Non-streaming request, `max_tokens: 1`, full system + tools
- [ ] Fingerprint: backend + model + system prompt + tool set; skip if unchanged
- [ ] Once per agent session on fingerprint change (not every message)

---

## 3. Configuration additions

```json
{
  "agents": {
    "defaults": {
      "tool_selection": "fixed",
      "max_tool_result_chars": 50000,
      "tool_result_preview_chars": 2000,
      "max_tool_output_per_turn_chars": 200000,
      "local_optimizations": {
        "warmup": false,
        "warmup_providers": ["ollama", "vllm"]
      }
    }
  }
}
```

Env overrides: `SMOLCLAW_AGENTS_DEFAULTS_TOOL_SELECTION`, etc.

---

## 4. Exit Criteria

- [ ] All tasks 1.1–1.8 complete or explicitly deferred with reason
- [ ] Default config behavior unchanged from pre-Phase-1 (fixed tools, no warmup)
- [ ] `tool_selection: auto` documented in README config section
- [ ] New tests: tool_selection, inline buffer, compaction, spill-to-disk
- [ ] ctest green; binary delta documented vs Phase 0 baseline

---

## 5. Risks

| Risk                                       | Mitigation                                      |
|--------------------------------------------|-------------------------------------------------|
| Adaptive tools hide needed tool from model | `fixed` escape hatch; log selection             |
| Warmup adds startup latency                | Opt-in; skip on fingerprint match               |
| Spill-to-disk fills workspace              | Prune old `tool_outputs/` optionally in Phase 2 |
| Compaction loses debugging info            | Audit log retains full output                   |

---

## 6. Suggested PR order

1. `feat: tool result spill-to-disk and per-turn cap`
2. `feat: token-aware session compaction`
3. `feat: adaptive tool selection (default fixed)`
4. `feat: streaming inline tool-call buffer + JSON compaction`
5. `feat: optional local provider prompt warmup`

---

**Next phase:** [Phase 2 — Operator & Provider UX](phase-2-operator-provider-ux.md)
