# Autonomy Readiness — Handoff Matrix for master-plan.md

**Status**: Living handoff doc  
**Purpose**: Assess whether each task in [`master-plan.md`](master-plan.md) and the
phase plans can be implemented by an autonomous Opus-4.8-class agent, and what
must be resolved or provisioned *before* handing the plan off.  
**Last verified against code**: 2026-06-26 (commit at time of writing)  
**Related**: [`master-plan.md`](master-plan.md), `docs/design/phases/phase-*.md`

---

## 1. Verdict

The plan is **not** a fire-and-forget "implement all phases" button — but it is a
strong substrate for **supervised, slice-by-slice autonomous execution**: one
task → one branch/PR → gated by `ctest` + `scripts/check_size_budget.sh`.

Two structural caveats:

- **Phase 5 is an explicit do-not-build parking lot.** "Implement all phases"
  excludes Phase 5 by design.
- **Several acceptance criteria require a live external system or a human**
  (real OAuth consent, a Signal daemon, a KVM host, a running Ollama). The agent
  can write the code + mock tests, but cannot *accept* those tasks alone.

The open questions are **now decided** (§3, 2026-06-26). With the external
prerequisites provisioned or scoped to mock-acceptance (§4), roughly **70–80% of
concrete tasks are autonomous-ready today**; the remainder are
autonomous-to-implement but human-to-accept.

---

## 2. Readiness matrix

**Legend**

| Tag | Meaning |
|-----|---------|
| ✅ **READY** | Autonomously implementable *and* verifiable via `ctest` / mocks / build checks. No human, no unresolved decision. |
| 🟡 **GATED-DEC** | Logic implementable, but blocked on an unresolved **design decision** (resolve in §3 first). |
| 🟠 **GATED-EXT** | Code + mock tests autonomous, but **final acceptance needs a live external system or human**. |
| 🔵 **SHIPPED** | Already implemented in HEAD — **verify-only** (add/confirm a regression test). |
| ⛔ **DO-NOT-BUILD** | Parking lot; build only after promotion criteria met. |

### Phase 0 — Safety & stability

**Status (2026-06-27):** Complete on branch `task/0.8-deferred-init` — see
[`phase-0-safety-and-stability.md`](phases/phase-0-safety-and-stability.md).

| Task | Tag | Note / acceptance gate |
|------|-----|------------------------|
| 0.1 size & test baseline | 🔵 SHIPPED | Baseline recorded; KC-2 fix + 1 MB budget (owner) |
| 0.2 audit highs H-1–H-11 | 🔵 SHIPPED | H-11 guards + provider regression tests |
| 0.3 audit mediums (subset) | 🔵 SHIPPED | M-1/M-3 verified under `security_mutex` |
| 0.4 size build profile | 🔵 SHIPPED | MinSizeRel + LTO + gc-sections (−42.6% release) |
| 0.5 FTS5 gate | 🔵 SHIPPED | FTS5 only when `SC_ENABLE_MEMORY_SEARCH=y` |
| 0.6 checkpoint & rewind | 🔵 SHIPPED | Verify-only; `test_checkpoint_rewind_*` |
| 0.7 `sc_task_t` | 🔵 SHIPPED | Summarization cancel on shutdown (M-8) |
| 0.8 deferred init | 🔵 SHIPPED | Deferred rebuild + lazy deny-regex; web/main defer |

### Phase 1 — Context efficiency

| Task | Tag | Note / acceptance gate |
|------|-----|------------------------|
| 1.1 tool-result spill-to-disk | ✅ READY | Mock-testable |
| 1.2 per-turn aggregate cap | ✅ READY | |
| 1.3 token-aware compaction | ✅ READY | Uses provider usage; mockable |
| 1.4 reactive compaction on ctx error | ✅ READY | |
| 1.5 adaptive tool selection (`auto`) | ✅/🟠 | Q1 resolved: runtime config, default `fixed`. Logic READY; acceptance benchmark wants live Ollama |
| 1.6 streaming inline tool-call buffer | ✅ READY | Port SmallHarness `agent.rs` tests |
| 1.7 JSON-aware compaction | ✅ READY | |
| 1.8 prompt-prefix warmup | 🟠 GATED-EXT | Logic READY; TTFT benchmark needs live Ollama/vLLM |

### Phase 2 — Operator & provider UX

| Task | Tag | Note / acceptance gate |
|------|-----|------------------------|
| 2.1 xAI Grok OAuth | 🟠 GATED-EXT | Code + mock_http READY; **real login needs SuperGrok sub + current client_id/endpoints** |
| 2.2 `auth` subcommand | 🟠 GATED-EXT | Part of 2.1 |
| 2.3 `session compact` | ✅ READY | Tree-format tests |
| 2.4 `session prune` | ✅ READY | |
| 2.5 incremental reload | 🟡 GATED-DEC | Implement only "if measured bottleneck" — needs a measurement decision |
| 2.6 provider health | 🔵 SHIPPED | Tracker exists in `agent_turn.c`; verify fallback consults it + surface in analytics |
| 2.7 port conflict logging | ✅ READY | |
| 2.8 backoff verification | ✅ READY | Audit + add tests if gaps |
| 2.9 cron expression parser | ✅ READY | Premise verified (`"cron"` kind disabled); unit tests |
| 2.10 gateway slash MVP | ✅ READY | Mock-channel tests cover acceptance |
| 2.11 skills format docs | ✅ READY | Docs only |
| 2.12 MCP cookbook | 🟠 GATED-EXT | Needs ≥1 real MCP server for the smoke-test recipe |

### Phase 3 — Optional surface area

| Task | Tag | Note / acceptance gate |
|------|-----|------------------------|
| 3.1 Signal channel MVP | 🟠 GATED-EXT | Code + mock_http READY; **real `signal-cli` daemon + test number** for smoke test |
| 3.2 operator mode presets | ✅ READY | |
| 3.3 enhanced tool confirmation | ✅ READY | Q3 resolved: summary-only async confirm, fail-closed; full diff CLI/Web only |
| 3.4 X `note_tweet` | ✅ READY | Premise verified (`format_tweet` already handles it) |
| 3.5 notify Slack/ntfy | ✅ READY | "Ship only if trivial" |
| 3.6 subagent deny matrices | ✅ READY | |
| 3.7 session reset policies | ✅ READY | |
| 3.8 busy-input queue mode | ✅ READY | `steer` mode is Phase 5 |
| 3.9 silent delivery tokens | ✅ READY | |

### Phase 4 — Larger investments

| Task | Tag | Note / acceptance gate |
|------|-----|------------------------|
| 4.1 arena allocator | 🔵/✅ | Allocator shipped + per-turn wired; finish provider-parse adoption |
| 4.2 MCP capability sandbox | ✅ READY | Landlock/seccomp tests on Linux |
| 4.3 Anthropic prompt caching | 🟠 GATED-EXT | Logic READY; real verification needs an Anthropic key |
| 4.4 old result compression | ✅ READY | Uses existing transform hook |
| 4.5 project memory + repo_search | ✅ READY | Q2 resolved: `{SMOLCLAW_HOME}/indexes/<hash>.json`; Q7: v1 own extraction. Large (800–1,200 LOC) |
| 4.6 `doctor --local` | 🟠 GATED-EXT | Probes need a live provider |
| 4.7 prompt budget CLI | ✅ READY | |
| 4.8 remaining audit mediums | ✅ READY | M-2,4,5,6,7,9,10 |
| 4.9 microsandbox exec | 🟠 GATED-EXT | **KVM host + microsandbox-server**; ops-heavy |
| 4.10 updater split spike | ✅ READY | Q4 resolved: no split; measure under section-GC (0.4), revisit only if >50 KB proven |
| 4.11 global `session_search` | ✅ READY | Kconfig default n |
| 4.12 agent-initiated compact tool | ✅ READY | After 2.10 slash `/compress` |
| 4.13 post-turn memory review | ✅ READY | Opt-in; acceptance mockable (aux provider optional) |
| 4.14 staged memory writes | ✅ READY | Pairs with 4.13 |

### Phase 5 — Defer / reject

⛔ **DO-NOT-BUILD.** Every item is a parking-lot entry. Build only after its
written promotion criteria are met (`phase-5-defer-reject.md` §5). An autonomous
run must **skip** Phase 5.

---

## 3. Open-question resolutions (decided 2026-06-26)

All seven are **resolved**. Decisions apply the smol contract (Kconfig
`default n` above ~50 KB, no new deps, reuse infra) and the mantra
(work > right > fast). The owner may override any — update here *and* the
cited phase task. Q3 and Q6 were reviewed and **confirmed by the owner
on 2026-06-26**.

- [x] **Q1 — adaptive tools gating (1.5): RUNTIME CONFIG ONLY; no Kconfig flag; default `fixed`.**
  150–250 LOC / ~+5 KB is far below the +50 KB gating threshold and defaults to
  current behavior, so a compile-time flag is not justified. Field
  `agents.defaults.tool_selection: "fixed" | "auto"`. (Matches spec rec.)

- [x] **Q2 — project-memory index path (4.5): `{SMOLCLAW_HOME}/indexes/{workspace-hash}.json`.**
  Keep all smolclaw state together (sessions, memory, vault, `auth.json` already
  live under `~/.smolclaw/`); never write an index into the user's repo (no VCS
  noise, no per-workspace `.gitignore` burden); multi-workspace-gateway-safe.
  `workspace-hash` = first 16 hex of `sha256(realpath(workspace_root))`.

- [x] **Q3 — async confirm UX (3.3; shapes 3.1, 2.10): SUMMARY-ONLY confirm; fail-closed.**
  Async channels (Telegram/Discord) get a capped text summary (tool, path,
  change size — **no raw diff**) routed through the existing tool-confirm reply
  flow. Full unified diff only on interactive CLI + Web. If a channel offers no
  confirm path and `auto_confirm` is off, **deny** dangerous ops (fail-closed) —
  never silently allow. **[owner-confirmed 2026-06-26 — fail-closed stands]**

- [x] **Q4 — updater split (4.10): DO NOT SPLIT; rely on LTO + `--gc-sections` (task 0.4).**
  curl/cJSON are linked unconditionally and OpenSSL is already conditional, so a
  separate binary saves little while adding atomic-replace + version-sync
  complexity. 4.10 reduces to a **measurement task**: record updater code size
  with section-GC on/off; only revisit a split if >50 KB is proven *and* those
  deps are not otherwise linked.

- [x] **Q5 — Phase 5 promotion metrics: parked until ALL of (a) + (b) + (c).**
  (a) **demand** — same item requested 3+ times OR blocking a deployment; AND
  (b) **measured breach** — MCP tool count >30 (→ context pipeline / deferred
  tool loading), sessions regularly >500 messages (→ session index), OR a
  context-budget bug recurring ≥2× after Phase 1 (→ context pipeline); AND
  (c) Phases 0–3 stable with no open HIGH audit item in the related path.
  Rich TUI stays **permanently rejected** regardless.

- [x] **Q6 — xAI OAuth Kconfig (2.1): `SC_ENABLE_XAI_OAUTH default n`, `depends on SC_ENABLE_XAI`.**
  +40–60 KB sits at the smol gating threshold, so default-off keeps minimal
  builds lean; only offered when the xai provider is compiled. **This overrides
  the spec's tentative `default y`** — the spec itself invokes the smol contract,
  and the ≤1 MB minimal budget wins. `~/.grok/auth.json` interop stays **out of
  MVP** (Phase 2, read-only fallback). **[owner-confirmed 2026-06-26 — default n stands]**

- [x] **Q7 — repo_search ↔ code_graph (4.5): v1 DUPLICATES extraction; share in v2.**
  Don't couple two subsystems before repo_search's ranking needs are known (work
  before right). v1 ships lightweight term/symbol extraction with a
  `TODO(shared-symbols)` marker; a shared `sc_symbols` helper lands in v2 once
  validated. (Matches spec rec.)

---

## 4. External prerequisites checklist (provision OR scope to mock-acceptance)

Tasks tagged 🟠 GATED-EXT cannot be *accepted* without these. Either stand them
up before the run, or instruct the agent to deliver "code + mock tests only" and
hold final acceptance for a human:

- [ ] **Ollama / vLLM** reachable — for 1.5, 1.8, 4.6 acceptance benchmarks
- [ ] **`signal-cli` daemon + dedicated test phone number** — for 3.1 smoke test
- [ ] **SuperGrok subscription + verified-current xAI client_id/endpoints** — for
  2.1 real login
- [ ] **Anthropic API key** — for 4.3 cache-hit verification
- [ ] **KVM host + `microsandbox-server` on :5555** — for 4.9
- [ ] **≥1 real MCP server** (e.g. Playwright, Home Assistant) — for 2.12 recipe
- [ ] **Note**: `code-analysis-report.md` is **gitignored** (absent on fresh
  clone). Phase 0 is self-sufficient because the H-table is inlined in
  `phase-0-safety-and-stability.md`, but do not rely on the external report.

---

## 5. Recommended execution protocol

1. **Decision pass** — resolve §3; write answers back into the relevant phase
   docs. *(Human, one sitting.)*
2. **Provision pass** — satisfy §4, or mark each GATED-EXT task "mock-acceptance,
   human final". *(Human/ops.)*
3. **Per-task loop** (agent): pick next task in phase order (0→1→2→3→4, skip 5) →
   branch → implement against the **authoritative spec** named in the phase doc →
   `cmake --build build` clean (grep for `implicit` per KC-2) →
   `ctest --test-dir build` green → `scripts/check_size_budget.sh` pass →
   new Kconfig flags added to `FEATURE_SYMS` (KC-1) → open PR.
4. **Human gates**: each §3 decision, each 🟠 GATED-EXT acceptance, and any task
   that would breach the LOC or ≤1 MB size budget.

---

## 6. Verification gates the agent can self-serve

- `ctest --test-dir build` (33 tests in the full build; per-module)
- `scripts/check_size_budget.sh` (CI-enforced minimal ≤ 1 MB stripped)
- `scripts/check_claude_md.sh` (CLAUDE.md fact drift)
- Build hygiene: KC-1 (new flags → `FEATURE_SYMS`), KC-2 (grep build output for
  `implicit`)
- Mock infrastructure: `tests/mock_http.h` (channels, providers, OAuth callback)

---

## 7. Maintenance

Update the §2 tags as tasks land. When a task moves to 🔵 SHIPPED, record the
commit. Re-run the code spot-checks (the ones behind the 2026-06-26 column)
before trusting a tag older than a release.
