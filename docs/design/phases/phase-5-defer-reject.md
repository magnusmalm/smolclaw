# Phase 5: Defer / Reject

**Status**: Parking lot — do not schedule until demand proven  
**Master plan**: [`../master-plan.md`](../master-plan.md)  
**Goal**: Document items explicitly out of near-term scope with promotion criteria

---

## 1. Rejected (anti-smol or wrong fit)

- **Rich TUI (ncurses/React-style)** — Source: grok-cli-vs-smolclaw; Reason: +100 KB+, large UX
  surface; Web UI + CLI sufficient
- **OpenRouter `/compare` A/B** — Source: smallharness; Reason: Niche; multi-provider fallback
  covers need
- **SmallHarness batch multi-file editor** — Source: smallharness; Reason: spawn/worktree/delegate
  patterns suffice
- **lazyagent multi-format session reading** — Source: lazyagent; Reason: smolclaw owns its session
  format
- **Embed signal-cli / libsignal** — Source: signal-channel; Reason: JVM/protocol bloat; external
  daemon only
- **macOS MLX hardware profiles** — Source: smallharness; Reason: Too platform-specific; generalize
  as RAM tiers if ever needed

---

## 2. Deferred — architectural (high refactor risk)

### 2.1 Layered context pipeline

**Source:** zed-patterns Task 4  
**LOC:** ~800–1,200  
**Binary:** neutral to +

Composable stages (system → memory → history → tools → trim). Replaces flat `context.c` builder.

**Promote when:** Context budget bugs recur after Phase 1 compaction; MCP tool count >30; per-stage trimming needed in production.

### 2.2 Session index with aggregate summaries

**Source:** zed-patterns Task 5  
**LOC:** ~600–900  
**Binary:** +20–40 KB

B-tree-like index over session tree for O(log n) branch/truncate/token queries.

**Promote when:** Sessions regularly exceed 500 messages; linear session scans show in profiling.

---

## 3. Deferred — feature follow-ups

### 3.1 Signal Phase 2 (SSE, typing, health)

**Source:** signal-channel.md Phase 2  
**Effort:** 4–6 days  
**After:** Phase 3 Signal MVP stable in production

### 3.2 Signal Phase 3 (attachments, voice, reactions)

**Source:** signal-channel.md Phase 3  
**Effort:** 6–8 days  
**Risk:** Media handling bloat; transcribe integration

### 3.3 SmallHarness Phase D–E

**Source:** smallharness-integration

| Item                        | Notes                                   |
|-----------------------------|-----------------------------------------|
| `shipcheck` / `handoff` CLI | Release workflow helpers; no agent loop |
| `/test` smart runner        | Overlaps exec + output_filter           |
| `/prompt` template library  | Overlaps skills system                  |
| `/autotune` / `/recommend`  | Needs capability cache (4.6) first      |
| RAM-tier presets            | Docs-only until doctor/autotune exist   |

### 3.4 Claude-code P2 items

**Source:** claude-code-improvements

| Item                                           | Promote when                        |
|------------------------------------------------|-------------------------------------|
| Deferred MCP tool loading (ToolSearch)         | Total MCP tools >30                 |
| Correlation IDs across the orchestration stack | Multi-agent debugging pain reported |

### 3.5 xAI OAuth Phase 2–3

**Source:** xai-grok-oauth.md

- Image/video/TTS tools using OAuth token
- Read-only `~/.grok/auth.json` interoperability
- Multi-account credential pool

**After:** Phase 2 OAuth MVP stable.

### 3.6 grok-cli borrow: media generation tools

**Source:** grok-cli-vs-smolclaw  
**LOC:** ~200–400 API wrappers  
**Gate:** Kconfig + provider with billing clarity

### 3.7 Notify post-tool hook auto-ping

**Source:** todo.md  
**After:** Pre/post hook chain stable; headless fleet demand

---

## 4. Deferred — low priority polish

| Item                                                 | Source                                    |
|------------------------------------------------------|-------------------------------------------|
| Port conflict logging                                | Moved to Phase 2 — if skipped, stays here |
| Post-tool notify on session end                      | todo.md                                   |
| Open question: smolclaw session format for lazyagent | lazyagent_borrow_tasks                    |

---

## 5. Promotion criteria (when to pull from Phase 5)

Use this checklist before scheduling a deferred item:

1. **User or fleet demand** — issue raised 3+ times or blocking deployment
2. **Measured pain** — profiling, binary size report, or session size data
3. **Dependencies met** — e.g. autotune after doctor CLI
4. **Smol review** — Kconfig gate + LOC/binary budget approved
5. **Phase 0–3 stable** — no open HIGH audit items in related code paths

---

## 6. Review schedule

Revisit Phase 5 items:

- After each major release (tag)
- When local-model / Ollama usage grows (SmallHarness items)
- When MCP server count per deployment exceeds 3

Update this doc with date + decision when promoting or permanently rejecting an item.

---

**Active work:** Return to [Phase 0](phase-0-safety-and-stability.md) or current in-progress phase.
