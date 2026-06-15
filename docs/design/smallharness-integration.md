# Design: SmallHarness Integration — Local-Model Patterns for smolclaw

**Status**: Design Complete — Implementation Not Started  
**Author**: Cross-repo analysis (2026-05-21)  
**Last Updated**: 2026-05-21  
**Source**: https://github.com/GetSmallAI/SmallHarness (v0.2.2, cloned for analysis)  
**Related**: `lazyagent_borrow_tasks.md`, `docs/tools/code_graph.md`, `src/agent_turn.c`, `src/providers/http.c`

---

## 1. Summary

[SmallHarness](https://github.com/GetSmallAI/SmallHarness) is a Rust TUI agent harness optimized for **small open-weight models** (7B–14B) running locally via Ollama, LM Studio, MLX, or llama.cpp. It is not a multi-channel framework — it is a single-process operator console with sharp focus on prompt-eval cost, tool-call reliability, and local-repo navigation.

smolclaw already supports Ollama and local HTTP providers, text-based tool-call extraction, output filtering, and a much stronger security model. The integration goal is **not** to port SmallHarness's TUI or Mac packaging, but to borrow patterns that make smolclaw materially better when the active provider is a constrained local model.

This document lists concrete, prioritized tasks. None are urgent; all are pattern lifts.

---

## 2. Motivation

Local models differ from cloud frontier models in predictable ways:

- **Large tool schemas in every turn** — Slow prompt-eval, high latency, context waste
- **Weak tool-call templates** — Tool calls emitted as plain JSON text
- **Prefix-cache engines (llama.cpp, Ollama)** — First real prompt pays full system+tools eval
- **Limited context window** — Tool outputs blow the window quickly
- **Operator uncertainty** — Users don't know which local model/backend actually supports tools

SmallHarness treats these as first-class design problems. smolclaw treats local providers as one of many backends — correctly, but without the local-model-specific optimizations SmallHarness has validated in production use.

---

## 3. Goals

- Improve smolclaw agent quality and latency when `provider` is Ollama, vLLM, or other local OpenAI-compatible endpoints.
- Keep changes behind config flags with safe defaults (no behavior change for cloud-only deployments).
- Reuse existing smolclaw infrastructure where possible (`code_graph`, audit log, tool registry, `output_filter.c`).
- Maintain smolclaw's security posture — never weaken Landlock, exec deny patterns, or vault in pursuit of convenience.

### Non-Goals

- Port SmallHarness's TUI (bordered input, banner, spinner, slash-command REPL).
- Replace smolclaw channels/gateway with a standalone harness binary.
- Mac-specific hardware profiles (`mac-mini-16gb`, MLX defaults) — generalize as optional RAM-tier presets if needed later.
- OpenRouter `/compare` A/B as a built-in feature (smolclaw already has multi-provider fallback).
- Drop Rust dependency or embed SmallHarness — all lifts are reimplemented in C11.

---

## 4. Architecture Comparison

```text
SmallHarness                         smolclaw (today)
─────────────────                    ─────────────────
main.rs input loop                   channels → bus → agent loop
agent.rs tool loop                   agent_turn.c tool loop
tools/mod.rs adaptive selection      all enabled tools every turn
warmup.rs prefix priming             none
project_memory.rs repo index         code_graph + memory FTS5
approval.rs diff + tiered policy     registry confirm + auto_confirm
session.rs flat JSONL                session.c tree JSON + summarization
capabilities.rs doctor/autotune      none
path_policy.rs workspace root        sandbox + path validation (stronger)
```

**Overlap already in smolclaw** (do not regress):

- Text tool-call extraction (`extract_text_tool_calls` in `agent_turn.c`) — SmallHarness adds streaming buffer; smolclaw does not yet.
- Tool output size limits (`output_filter.c`, 32 KB cap).
- Ollama provider + `num_ctx` passthrough (`providers/http.c`).
- Long-term memory search (FTS5) — different purpose from project index.
- Session summarization/compaction in `agent_session.c` — different mechanism from SmallHarness `/compact`.

---

## 5. Configuration Sketch

Proposed additions under `agents.defaults` (names provisional):

```json
{
  "tool_selection": "fixed",
  "operator_mode": "custom",
  "local_optimizations": {
    "warmup": false,
    "warmup_providers": ["ollama", "vllm"],
    "prompt_budget_warn_bytes": 196608
  },
  "approval_policy": "always",
  "project_memory": {
    "enabled": false,
    "auto_inject": true,
    "auto_index": false,
    "max_injected_bytes": 8192
  }
}
```

- `tool_selection`: `"fixed"` (default, current behavior) | `"auto"` (SmallHarness-style heuristic).
- `operator_mode`: `"explore"` | `"edit"` | `"ship"` | `"review"` | `"custom"` — preset bundles; `"custom"` leaves explicit tool list untouched.
- `approval_policy`: `"always"` | `"never"` | `"dangerous-only"` — extends confirm behavior beyond boolean `auto_confirm`.
- `local_optimizations.warmup`: opt-in prefix priming for listed providers.

Env overrides follow existing `SMOLCLAW_AGENTS_DEFAULTS_*` convention.

---

## 6. Implementation Tasks

Tasks are grouped by priority. Each item cites the SmallHarness source pattern and the smolclaw target.

---

### Tier 1 — High leverage (core agent loop)

#### 1. Adaptive tool selection (`tool_selection: auto`)

**Pattern:** SmallHarness `select_tool_names()` in `src/tools/mod.rs`. Keyword heuristics on the user message decide which tool schemas to send:

- Chat/greetings → no tools
- File/repo questions → read/search tools
- Edit language → add write/edit/patch tools
- Shell/build language → add exec if enabled

**Apply where:**

- New `src/tools/tool_selection.c` (or section in `registry.c`).
- `src/agent_turn.c` — filter `sc_tool_definition_t` array before each LLM call when `tool_selection == auto`.
- `src/config.c` / `config.h` — new enum + JSON field.
- `tests/test_tool_selection.c`.

**Pairing:** Works best with operator modes (task 5). In `auto` mode, the enabled tool pool (`tools.allow` or registry subset) is the ceiling; heuristics pick a subset per turn.

**Pitfalls:**

- Heuristics are brittle — log selected tools at DEBUG; allow `tool_selection: fixed` as escape hatch.
- Gateway/multi-channel: selection must be per-turn from user message text, not global state.
- Do not hide tools from the model that are required by active skills/MCP without explicit policy.

**Acceptance:** With Ollama 7B, a "hello" turn sends zero tool schemas; "find the config loader in src/" sends read/search tools only; token count in provider request drops measurably.

---

#### 2. Prompt prefix warmup

**Pattern:** SmallHarness `warmup.rs` — non-streaming `max_tokens: 1` request with full system prompt + active tool defs to prime llama.cpp/Ollama prefix cache. Re-run when backend/model/system-prompt/tools fingerprint changes (`main.rs` `prompt_fingerprint()`).

**Apply where:**

- New `src/providers/warmup.c` or hook in `providers/http.c`.
- `src/agent.c` / `agent_turn.c` — call after system prompt or tool set changes; skip for cloud providers unless explicitly enabled.
- Config: `local_optimizations.warmup`, `warmup_providers[]`.

**Pitfalls:**

- Adds latency at session start — must be opt-in (`warmup: false` default).
- Wasted request if backend doesn't cache prefixes — gate on provider type.
- Don't warmup on every channel message in gateway mode; warmup once per agent session or on fingerprint change only.

**Acceptance:** With `warmup: true` and Ollama qwen 7B, second user prompt in same tool fingerprint shows reduced time-to-first-token vs cold first prompt (manual benchmark; document in help text).

---

#### 3. Streaming inline tool-call buffer

**Pattern:** SmallHarness `agent.rs` — during SSE streaming, if assistant text starts like `{"name":...`, buffer deltas instead of emitting to user/channel; parse at end of stream; synthesize structured tool call. Accepts `arguments`, `parameters`, `args` aliases.

**Apply where:**

- `src/agent_turn.c` — extend streaming path (alongside existing post-hoc `extract_text_tool_calls`).
- Channel streaming callbacks in `src/channels/*.c` — suppress buffered JSON-shaped text.

**Pairing:** Complements existing `<tool_call>...</tool_call>` and bare-JSON post-parse. Merge into one code path eventually.

**Pitfalls:**

- False positives on assistant prose containing `{` — SmallHarness uses anchored regex at stream start; replicate conservatively.
- Partial JSON at stream abort — fall back to emitting buffered text.

**Acceptance:** Unit tests mirroring SmallHarness `agent.rs` tests (`looks_like_tool_call_positives/negatives`, alias fields). Integration: Ollama model that emits inline JSON does not flash raw JSON to CLI/Web UI.

---

#### 4. JSON-aware tool result compaction

**Pattern:** SmallHarness `compact_tool_output()` in `agent.rs` — 4 KB char cap; for JSON tool results, truncate `content`/`output`/`diff` string fields or cap `matches`/`entries` arrays at 50 with `compacted: true` metadata.

**Apply where:**

- New helper in `src/tools/output_filter.c` or `src/agent_turn.c` (`wrap_tool_output` path).
- Apply before message enters session/history; full output remains in audit log if `SC_ENABLE_TEE` or audit captures it.

**Pairing:** Existing 32 KB hard cap and CLI-specific filters (`sc_filter_detect`) — compaction is semantic, filters are syntactic. Run compaction first, then byte cap.

**Pitfalls:**

- Don't compact error payloads — preserve full error strings.
- Structured tools (code_graph, memory_search) may need per-tool overrides.

**Acceptance:** Tests for large grep result JSON and file_read content field; model context receives compacted payload with summary marker.

---

### Tier 2 — Medium leverage (operator experience)

#### 5. Operator mode presets

**Pattern:** SmallHarness `AgentConfig::apply_operator_mode()` in `config.rs`:

| Mode    | Tool pool (ceiling) | Approval       | Steps |
|---------|---------------------|----------------|-------|
| explore | read/search         | dangerous-only | 6–12  |
| edit    | read + edit + patch | always         | ≥12   |
| ship    | full + shell        | dangerous-only | ≥20   |
| review  | read + shell        | dangerous-only | 8–16  |

**Apply where:**

- `src/config.c` — `operator_mode` enum; apply on load and on `smolclaw config set`.
- Map to existing `max_tool_iterations`, tool allowlist, confirm policy.

**Pitfalls:**

- `custom` must not clobber user tool lists on config reload.
- Gateway agents may need per-agent mode in multi-agent setups later.

---

#### 6. Enhanced tool confirmation

**Pattern:** SmallHarness `approval.rs` + tool `preview()` (e.g. `file_edit.rs` unified diff).

**Apply where:**

- `src/tools/registry.c` — extend confirm callback signature to include optional diff preview string.
- `src/channels/cli.c` — show diff on confirm; Web channel could show truncated diff.
- `approval_policy: dangerous-only` for exec — port regex from SmallHarness `shell.rs` (`rm`, `sudo`, `chmod`, etc.) as supplement to existing `exec_common.c` deny patterns.

**Session allow cache:**

- `[a]lways for tool` → in-memory set for agent lifetime (like SmallHarness `always_allow`).
- `[s]ession-allow this exact call` → cache key `tool:path_or_command` (SmallHarness pattern).

**Pairing:** Distinct from `auto_confirm` (headless). Precedence: `auto_confirm` > explicit policy > interactive.

**Pitfalls:**

- Diff preview for large files — cap display at 80 lines (SmallHarness limit).
- Non-interactive channels (Telegram) cannot show diff — fall back to summary text or deny writes.

---

#### 7. Project memory index + `repo_search` tool

**Pattern:** SmallHarness `project_memory.rs` — workspace walk with `.gitignore`, per-file metadata (path, language, size, mtime, SHA-256, symbols, headings, imports, terms), stored at `{workspace}/.smolclaw/project-index.json` (path TBD). Powers:

- `repo_search` tool (ranked hits)
- Optional compact repo map injection into system prompt for code-related user messages
- Incremental refresh on mtime/SHA; refresh after successful writes

**Apply where:**

- New `src/tools/project_memory.c` + `src/tools/repo_search.c` (or single tool with actions).
- Behind `SC_ENABLE_PROJECT_MEMORY` Kconfig flag (default off initially).
- `src/context.c` — optional auto-inject block (like SmallHarness `render_system_prompt_with_memory`).

**Pairing with existing tools:**

- **`code_graph` (imports, C symbols)** — Cross-language metadata, keyword/heading search, ranked
  snippets
- **`memory_search` (FTS5 notes)** — Codebase structure, not user notes
- **`context_search`** — Session-scoped, not repo index

**Pitfalls:**

- Index storage location must not collide with session files or `.git`.
- Cloud providers: default `allow_cloud_context: false` (SmallHarness pattern) — inject index only for local providers unless opted in.
- Secret file skip list (`.env`, credentials) — copy SmallHarness skip patterns.

---

#### 8. Local provider doctor + capability cache

**Pattern:** SmallHarness `capabilities.rs` + `/doctor --deep` in `commands.rs` — probe `/v1/models`, streaming, usage chunks, native tool calls, inline JSON fallback; persist JSON under `.sessions/capabilities/`.

**Apply where:**

- New `smolclaw doctor` subcommand (or `smolclaw agent doctor`).
- `src/providers/http.c` — probe helpers.
- Cache file under `{workspace}/.smolclaw/capabilities/` or config dir.

**Scope for v1:** Probe active configured provider only; `--all` later.

**Pitfalls:**

- Probes cost time and tokens — require explicit invocation, not startup default.
- Store results locally; no telemetry.

---

#### 9. Prompt budget visibility

**Pattern:** SmallHarness `budget.rs` + `/context` — byte breakdown: system, transcript, tool schemas, tool results; warn at 75% of limit.

**Apply where:**

- New `smolclaw context` subcommand or gateway status endpoint.
- Reuse token estimates from `cost.c` where available; byte estimate as fallback (bytes/4).

**Pitfalls:**

- Estimates are approximate — label clearly in output.

---

### Tier 3 — Lower priority (CLI hygiene & workflows)

#### 10. Session maintenance subcommands

**Pattern:** SmallHarness `session.rs` + slash commands — list, search, resume, delete, prune (keep N), export markdown/json.

**Apply where:**

- `src/main.c` — `smolclaw session list|search|export|prune|compact` subcommands.
- Aligns with lazyagent borrow task #2 (`session compact`) and #3 (`session prune`) in `lazyagent_borrow_tasks.md`.

**Pairing:** smolclaw session format is a JSON tree, not flat JSONL — export/compact must preserve `parent_id` resumability.

**Pitfalls:** See lazyagent doc — don't compact active session without lock; audit log retains full tool output.

---

#### 11. Shipcheck / handoff maintenance commands

**Pattern:** SmallHarness `shipcheck.rs`, `handoff.rs` — git-aware release preflight and handoff markdown (commit message, changelog bullets, test notes).

**Apply where:**

- Optional `smolclaw shipcheck` and `smolclaw handoff` subcommands using existing `git` tool internals.
- No agent loop required — pure local git + project-index freshness.

**Pitfalls:**

- Keep offline-only; no cloud LLM call unless user explicitly runs agent with a prompt.

---

#### 12. RAM-tier model presets (generalized hardware profiles)

**Pattern:** SmallHarness `backends.rs` + `hardware.rs` — profile maps backend → default model by RAM tier.

**Apply where:**

- Optional config snippet in docs/examples, not hardcoded Mac names.
- Could integrate with doctor/autotune (task 8) later.

**Defer** until tasks 1–2 prove local-model path is actively used.

---

## 7. Skip — Already Covered or Out of Scope

- **TUI / bordered input / banner** — Web UI + CLI channels — skip
- **Flat JSONL sessions** — Tree sessions in `session.c` — different model; borrow commands only
- **`memory_search` equivalent** — FTS5 in `memory_index.c` — keep
- **Landlock / seccomp sandbox** — smolclaw ahead — do not weaken for parity
- **MCP tools** — smolclaw ahead
- **Multi-agent spawn/delegate** — smolclaw ahead
- **`/batch` multi-file editor** — Lower priority vs spawn/worktree; defer
- **`/test` smart test runner** — Useful but orthogonal; defer
- **`/prompt` template library** — Skills system partially overlaps; defer
- **OpenRouter `/compare`** — Multi-provider fallback sufficient
- **Mac MLX / LM Studio defaults** — Document in user guide; don't encode in binary

---

## 8. Suggested Implementation Order

```text
Phase A (local model quick wins)
  1 → 3 → 4 → 2
  adaptive tools, streaming buffer, compaction, warmup

Phase B (operator trust)
  5 → 6
  operator modes, enhanced confirmation

Phase C (repo navigation)
  7
  project memory + repo_search

Phase D (observability)
  8 → 9 → 10
  doctor, context budget, session CLI

Phase E (optional)
  11 → 12
  shipcheck/handoff, RAM presets
```

Phase A is the minimum viable "SmallHarness learnings" release.

---

## 9. Testing Strategy

- **Adaptive tool selection** — Unit tests with fixed prompts; assert tool count in mock provider
  request
- **Warmup** — Mock HTTP server; assert single-token request shape; skip on fingerprint match
- **Streaming buffer** — Unit tests ported from SmallHarness `agent.rs` tests
- **Compaction** — Unit tests for JSON truncation paths
- **Project memory** — Temp dir fixture repo; index build, search ranking, incremental refresh
- **Doctor** — Mock provider returning/withholding tool_calls; cache read/write
- **Session CLI** — Integration tests on temp session tree

All new code: C11, zero warnings, `ctest` coverage for pure logic.

---

## 10. Open Questions

1. **Kconfig vs runtime-only:** Should `tool_selection: auto` and project memory be compile-time flags, runtime config, or both? Recommendation: runtime config for selection; Kconfig gate for project memory (new code volume).

2. **Index path:** `{workspace}/.smolclaw/project-index.json` vs `{SMOLCLAW_HOME}/indexes/{workspace-hash}.json` for multi-workspace gateway?

3. **Warmup in gateway:** One warmup per agent instance at first turn, or per channel session? Recommendation: per agent instance, fingerprint-keyed.

4. **Confirm UX on async channels:** Telegram/Discord cannot show unified diff — block write tools, summary-only confirm, or link to Web UI?

5. **Merge with code_graph:** Long-term, should `repo_search` call into `code_graph` for symbol data instead of duplicating regex extraction? Recommendation: shared symbol helper in v2 of task 7.

---

## 11. Cross-References

- `lazyagent_borrow_tasks.md` — session compact/prune (tasks 10 overlaps)
- `docs/tools/code_graph.md` — existing static analysis; complement not replace
- `docs/implementation-notes/phase3-code-graph-landing-2026-05-18.md` — symbol lookup direction
- SmallHarness source map (cloned for analysis):
  - `src/agent.rs` — tool loop, inline JSON, compaction
  - `src/tools/mod.rs` — adaptive selection
  - `src/warmup.rs` — prefix priming
  - `src/project_memory.rs` — repo index
  - `src/approval.rs` — confirm UX
  - `src/config.rs` — operator modes
  - `src/capabilities.rs` — doctor/autotune
  - `src/session.rs` — session CLI patterns

---

## 12. Success Criteria (Overall)

When Phase A–B are complete, a user running smolclaw with Ollama 7B should observe:

1. Casual chat turns do not pay tool-schema prompt-eval cost.
2. Inline JSON tool calls do not leak to channel output during streaming.
3. Large grep/read results are semantically compacted before entering history.
4. Optional warmup reduces first-turn latency after startup or tool-set change.
5. Operator can switch explore/edit/ship presets without hand-editing tool lists.
6. Write/exec confirmation can show diffs and remember per-session allowances.

No regression for cloud-provider deployments with default config.
