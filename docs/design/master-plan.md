# Master Plan: smolclaw Feature & Improvement Roadmap

**Status**: Planning — Not yet executing  
**Author**: Consolidated from cross-repo analyses (2026-03 through 2026-05)  
**Last Updated**: 2026-05-21  
**Related**: Individual phase plans in `docs/design/phases/`, source design docs listed below

---

## 1. Purpose

This document is the **single index** for all planned smolclaw improvements gathered from design docs, comparative analyses, audit reports, and backlog items. It captures:

- What each plan proposes
- Rough code and binary size impact
- Alignment with the **smol** philosophy (small binaries, Kconfig modularity, lean codebase)
- Recommended execution order from a **risk-minimization** perspective

Detailed task breakdowns live in **phase plans** (`docs/design/phases/phase-*.md`). Source design documents remain authoritative for individual features.

---

## 2. Guiding Principles ("smol" contract)

Every item in this roadmap must satisfy:

1. **Optional by default where size matters** — Kconfig `default n` or runtime config off for features adding >~50 KB.
2. **No new runtime dependencies** — reuse curl, libevent, cJSON, SQLite, existing util code.
3. **Reuse infrastructure** — channels use `base.c`, tools use registry/sandbox, auth follows `x_api.c` / vault patterns.
4. **Ship in slices** — MVP first; Phase 2/3 items stay out of early PRs.
5. **Security never regresses** — Landlock, seccomp, pairing, audit log, path validation stay intact.

**Binary budget rule:** treat **+50 KB per optional feature** as a warning threshold; require Kconfig gating above that.

**LOC budget rule:** aim for **≤2,000 LOC net** across Phase 0–2 before starting Phase 3 optional surface area.

---

## 3. Source Documents Index

| Document | Status | Phase(s) | Notes |
|----------|--------|----------|-------|
| [`code-analysis-report.md`](../../code-analysis-report.md) | Audit remediation | 0 | 35 findings; 11 high |
| [`todo.md`](../../todo.md) | Backlog | 0, 3, 4, 5 | Size opts, microsandbox, small fixes |
| [`docs/plan-checkpoint-rewind.md`](../plan-checkpoint-rewind.md) | Ready | 0 | ~100 LOC agent loop |
| [`docs/claude-code-improvements.md`](../claude-code-improvements.md) | Recommendations | 1, 4, 5 | ~380–800 LOC |
| [`docs/design/smallharness-integration.md`](smallharness-integration.md) | Design complete | 1, 3, 4, 5 | Local-model patterns |
| [`docs/design/xai-grok-oauth.md`](xai-grok-oauth.md) | Design complete | 2 | <650 LOC cap |
| [`lazyagent_borrow_tasks.md`](../../lazyagent_borrow_tasks.md) | Pattern lifts | 2 | Session CLI |
| [`docs/zed-patterns-actionable.md`](../zed-patterns-actionable.md) | Recommendations | 0, 2, 4, 5 | 6 architectural tasks |
| [`docs/design/signal-channel.md`](signal-channel.md) | Design complete | 3, 5 | Kconfig `default n` |
| [`docs/channels/signal.md`](../channels/signal.md) | User doc (planned) | 3 | Mirror of Signal design |
| [`grok-cli-vs-smolclaw.md`](../../grok-cli-vs-smolclaw.md) | Comparative | 5 | Mostly skip TUI |
| [`docs/development/using-grok-implement-skill.md`](../development/using-grok-implement-skill.md) | Process | — | How to implement designs |

**Not in roadmap** (implemented or out of scope):

- `docs/tools/code_graph.md`, `docs/implementation-notes/phase3-code-graph-landing-2026-05-18.md` — shipped
- Progress reports (`docs/progress-*.md`) — historical
- `README.md`, `SECURITY.md`, `RELEASING.md` — operational docs

---

## 4. Consolidated Inventory

### 4.1 By theme

| Theme | Items | Primary sources |
|-------|-------|-----------------|
| **Reliability & safety** | Audit fixes, arena allocator, sc_task_t, checkpoint rewind | code-analysis, zed-patterns |
| **Binary lean** | LTO/gc-sections, optional FTS5, updater split eval | todo.md |
| **Context & tokens** | Spill-to-disk, token compaction, old-result compression, adaptive tools, warmup | claude-code, smallharness |
| **Local models** | Adaptive tools, warmup, stream buffer, compaction, project memory, doctor | smallharness |
| **Auth & providers** | xAI Grok OAuth, provider health, prompt caching, backoff | xai-grok-oauth, zed, claude-code |
| **Channels & tools** | Signal MVP, notify extras, X note_tweet | signal-channel, todo |
| **Session ops** | compact, prune, incremental reload | lazyagent |
| **Architecture (large)** | Context pipeline, session index, MCP capability sandbox | zed-patterns |
| **Security depth** | Microsandbox exec backend | todo.md |
| **Explicitly deferred** | Rich TUI, Signal media/SSE, shipcheck/handoff, batch editor | grok-cli, smallharness, signal |

### 4.2 Size impact summary

| Item | LOC (rough) | Binary Δ (rough) | Kconfig / config gate |
|------|-------------|------------------|------------------------|
| Audit high/medium fixes | 300–600 | +0–5 KB | always |
| Binary size optimizations | 50–200 (CMake) | **−10–25%** | build profile |
| Optional FTS5 | 20–50 (CMake) | **−50–200 KB** on minimal | `SC_ENABLE_MEMORY_SEARCH` |
| Checkpoint rewind | 100–150 | ~0 | always |
| Arena allocator (Zed T1) | 250–400 | +5–15 KB | always |
| sc_task_t (Zed T2) | 150–250 | ~5 KB | always |
| Tool spill + token compaction (P0) | 200–350 | +10–20 KB | config |
| SmallHarness Phase A | 400–700 | +15–40 KB | `tool_selection`, `warmup` flags |
| xAI Grok OAuth | <650 | +40–60 KB | `SC_ENABLE_XAI_OAUTH` |
| Session compact/prune CLI | 200–450 | ~5–15 KB | CLI only |
| Provider health (Zed T6) | 80–150 | ~5 KB | always |
| Signal channel MVP | 800–1,000 | +40–80 KB | `SC_ENABLE_SIGNAL` default **n** |
| SmallHarness Phase B (modes, confirm) | 300–500 | +10–20 KB | config |
| MCP capability sandbox (Zed T3) | 300–500 | +10–20 KB | config per server |
| Anthropic prompt caching | 60–100 | ~5 KB | provider flag |
| Project memory + repo_search | 800–1,200 | +50–100 KB | `SC_ENABLE_PROJECT_MEMORY` default **n** |
| Context pipeline (Zed T4) | 800–1,200 | neutral/+ | refactor |
| Session index (Zed T5) | 600–900 | +20–40 KB | optional |
| Microsandbox exec | 400–600 | +15–30 KB | `SC_ENABLE_MICROSANDBOX` + external daemon |
| Rich TUI (grok-cli borrow) | 2,000+ | +100 KB+ | **reject** |

Estimates are order-of-magnitude for stripped release builds on x86_64; measure after each phase.

---

## 5. Smol-Theme Scorecard

| Rating | Items |
|--------|-------|
| **Strong smol** | Audit fixes, binary size opts, optional FTS5, checkpoint rewind, sc_task_t, provider health, port logging, X note_tweet, xAI OAuth (bounded), Signal MVP (Kconfig off) |
| **Good if gated** | SmallHarness Phase A–B, claude-code P0/P1, MCP capabilities, session compact/prune, notify extras |
| **Bloat risk** | Project memory, shipcheck/handoff, Zed context pipeline, session index, microsandbox ops, Signal Phase 2–3, Rich TUI |
| **Skip / defer** | grok-cli TUI, OpenRouter compare, SmallHarness batch editor, lazyagent multi-format reading |

---

## 6. Master Execution Order

Phases are ordered to **minimize regression risk**: foundations first, agent-loop wins before new channels, architectural refactors last.

```text
Phase 0 — Safety & stability          docs/design/phases/phase-0-safety-and-stability.md
Phase 1 — Context efficiency          docs/design/phases/phase-1-context-efficiency.md
Phase 2 — Operator & provider UX      docs/design/phases/phase-2-operator-provider-ux.md
Phase 3 — Optional surface area       docs/design/phases/phase-3-optional-surface-area.md
Phase 4 — Larger investments          docs/design/phases/phase-4-larger-investments.md
Phase 5 — Defer / reject              docs/design/phases/phase-5-defer-reject.md
```

### Phase summary

| Phase | Goal | LOC budget | Binary target | Exit criteria |
|-------|------|------------|---------------|---------------|
| **0** | Fix known bugs; shrink binary; checkpoint rewind | ~500–900 | Net **smaller** or flat | Audit highs closed; ctest green; size baseline recorded |
| **1** | Context/token efficiency + local-model quick wins | ~700–1,200 | +≤40 KB default config | Spill/compaction + SmallHarness Phase A behind flags |
| **2** | Auth, session CLI, provider health | ~900–1,400 | +≤80 KB with OAuth on | xAI OAuth shippable; session compact works |
| **3** | Kconfig-gated channels & modes | ~1,200–1,800 | +≤80 KB per flag enabled | Signal MVP; operator modes; no default-on bloat |
| **4** | Memory index, arena, MCP caps, caching | ~1,500–2,500 | gated | Each item independently shippable |
| **5** | Parking lot | — | — | Revisit only with demand |

### Dependency graph (simplified)

```mermaid
flowchart TD
    P0[Phase 0: Safety + size]
    P1[Phase 1: Context + local model]
    P2[Phase 2: OAuth + session CLI]
    P3[Phase 3: Signal + modes]
    P4[Phase 4: Project memory + architecture]
    P5[Phase 5: Deferred]

    P0 --> P1
    P1 --> P2
    P2 --> P3
    P1 --> P3
    P3 --> P4
    P4 --> P5
```

---

## 7. Measurement Baseline

Before Phase 0 work, record:

```bash
# Dynamic release build (current default)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
ls -la build/smolclaw
# Minimal profile
cp configs/defconfig.minimal .config
cmake -B build-minimal && cmake --build build-minimal -j$(nproc)
ls -la build-minimal/smolclaw
ctest --test-dir build
```

Track in phase-0 doc: binary bytes, peak RSS (optional), test count.

---

## 8. How to Use This Roadmap

1. **Pick a phase** — read the corresponding `docs/design/phases/phase-*.md`.
2. **Implement one slice** — single PR per task group within a phase when possible.
3. **Update status** — mark tasks done in the phase doc; link commits.
4. **Source doc wins on detail** — e.g. Signal behavior = `signal-channel.md`; OAuth security = `xai-grok-oauth.md`.
5. **Implement via skill** — for large features, use prompts from `docs/development/using-grok-implement-skill.md`.

---

## 9. Open Questions (cross-phase)

1. Should Phase 1 adaptive tools be runtime-only or also Kconfig-gated?
2. Project memory index path: per-workspace vs hashed under `SMOLCLAW_HOME`?
3. Confirm UX on async channels (Telegram/Discord) for diff previews — block, summary-only, or Web UI link?
4. Updater split: separate binary vs rely on LTO+gc-sections only?
5. When to promote Phase 5 items — what metrics trigger (session size, MCP tool count, user demand)?

---

## 10. Document Map

```
docs/design/
  master-plan.md                          ← this file
  phases/
    phase-0-safety-and-stability.md
    phase-1-context-efficiency.md
    phase-2-operator-provider-ux.md
    phase-3-optional-surface-area.md
    phase-4-larger-investments.md
    phase-5-defer-reject.md
  signal-channel.md                       ← authoritative for Signal
  xai-grok-oauth.md                       ← authoritative for OAuth
  smallharness-integration.md             ← authoritative for local-model lifts
```

---

**Next step:** Execute [Phase 0](phases/phase-0-safety-and-stability.md) — audit fixes and binary size baseline.
