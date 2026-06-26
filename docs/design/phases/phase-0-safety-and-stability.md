# Phase 0: Safety & Stability

**Status**: Not started  
**Master plan**: [`../master-plan.md`](../master-plan.md)  
**Goal**: Close known high-severity bugs, improve shutdown/thread safety, establish binary size baseline, add checkpoint rewind.  
**LOC budget**: ~650–1,150  
**Binary target**: Net **smaller or flat** (size optimizations offset small fixes; RSS win from 0.8)

---

## 1. Scope

Phase 0 fixes foundations before any feature work touches `agent_turn.c`, providers, or channels.

> **Re-verified 2026-06-26:** Most audit Highs (H-1–H-10) and M-1 are **already
> fixed in HEAD** — see the remediation status table in `code-analysis-report.md`.
> 0.2 collapses to verifying H-11 and adding any missing regression tests, not
> re-fixing. 0.6 (checkpoint/rewind) has **already shipped** — it is verify-only.

- **0.1** — Task: Record size & test baseline; Source: master-plan §7; LOC: —; Binary: —; Smol: ✓
- **0.2** — Task: Audit high-severity fixes (H-1–H-11) — **mostly done; verify H-11 + tests**;
  Source: code-analysis-report; LOC: 0–80; Binary: ~0; Smol: ✓
- **0.3** — Task: Audit medium fixes (priority subset; M-1 done, M-3 verify); Source:
  code-analysis-report; LOC: 50–150; Binary: ~0; Smol: ✓
- **0.4** — Task: Binary size build profile; Source: todo.md; LOC: 50–100 CMake; Binary:
  **−10–25%**; Smol: ✓✓
- **0.5** — Task: Optional SQLite FTS5 gate; Source: todo.md; LOC: 20–50 CMake; Binary: **−50–200
  KB** minimal; Smol: ✓✓
- **0.6** — Task: Checkpoint & rewind — **already shipped; verify-only**; Source:
  plan-checkpoint-rewind; LOC: 0 (+test); Binary: ~0; Smol: ✓
- **0.7** — Task: sc_task_t + summarization join (M-8); Source: zed-patterns T2; LOC: 150–250;
  Binary: ~5 KB; Smol: ✓
- **0.8** — Task: Deferred runtime init (FTS5, deny-regex); Source: deferred-initialization.md;
  Tier: **T1**; LOC: 150–250; Binary: ~0 (RSS/startup win); Smol: ✓✓

**Out of scope for Phase 0:** arena allocator (Phase 4 or early if provider fixes proliferate), new features, new channels.

---

## 2. Task Details

### 0.1 Measurement baseline

Recorded **2026-06-26** at git `45b74441df0b0be437655ce283f4b4981ba836db`.

**Build profiles**

| Profile | Command | Binary | Stripped |
|---------|---------|--------|----------|
| Release (full) | `cp configs/defconfig .config && cmake -B build -DCMAKE_BUILD_TYPE=Release` | `build/smolclaw` | **2,180,864 B** (2,320,824 unstripped) |
| Minimal (master-plan §7) | `cp configs/defconfig.minimal .config && cmake -B build-minimal` | `build-minimal/smolclaw` | **415,328 B** (925,176 unstripped) |
| CI minimal-dynamic | `cp configs/defconfig.minimal .config && cmake -B build-size -DCMAKE_BUILD_TYPE=MinSizeRel` (LTO + gc-sections via `cmake/size_optimize.cmake`) | `build-size/smolclaw` | **262,640 B** (§0.1 pre-LTO) → **250,880 B** / **245 KB** post-0.4 |

- [x] Record `build/smolclaw` and `build-minimal/smolclaw` byte sizes (see table)
- [x] Record `ctest` pass count
  - `ctest --test-dir build` (full/defconfig): **42/42 passed** (two consecutive
    runs, 0 failures)
- [x] Note git SHA in this doc
  - `45b74441df0b0be437655ce283f4b4981ba836db`

**Verification gates (2026-06-26):** KC-2 clean (`grep -i implicit` on fresh
release `build-full.log`: 0 matches; fixed pre-existing `asprintf` implicit
declarations in `scratchpad.c` / `main.c`). Size budget passes on CI profile:
`scripts/check_size_budget.sh build-size/smolclaw 1024 minimal-dynamic` → OK
(257 KB, headroom 767 KB at 1 MB budget). Unoptimized `build-minimal` (406 KB)
also within budget; task 0.4 still targets MinSizeRel + gc-sections for lean
release builds.

### 0.2 Audit high-severity fixes

> **Status (2026-06-26):** Verified in HEAD. H-11 stragglers fixed (`parse_response`,
> streaming finalize, `sc_provider_http_new` calloc guards). Regression tests added
> in `tests/test_providers.c` (H-1 write/header callbacks, H-2/H-3 clone, H-11
> malformed/empty JSON parse paths). H-4–H-10 covered by existing channel/tool
> tests — no re-fix applied.

**Files:** `src/providers/provider_common.c`, `src/providers/http.c`, `src/channels/discord.c`, `src/channels/telegram.c`, `src/tools/filesystem.c`, `src/logger.c`

| ID       | Fix                                           | Regression test |
|----------|-----------------------------------------------|-----------------|
| H-1      | NULL check after malloc in `sc_curl_write_cb` | `test_sc_curl_write_cb` |
| H-2, H-3 | NULL check after calloc for tool_calls        | `test_message_with_tool_calls`, `test_message_clone_with_tool_calls` |
| H-4      | Bounds check after SSE realloc failure        | existing SSE/stream tests |
| H-5, H-6 | Validate author/user id before use            | `test_discord`, `test_telegram` |
| H-7      | Block `.git/hooks/` in write paths            | `test_tools` / filesystem tests |
| H-8      | Mutex around logger writes                    | concurrent logger usage (shipped) |
| H-9      | Serialize Discord SSL access                  | `test_discord` |
| H-10     | Atomic write (temp + rename) for edit_file    | `test_tools` |
| H-11     | Remaining unchecked allocs in http provider   | `test_http_provider_malformed_json`, `test_http_provider_empty_choices` |

- [x] H-11: no unguarded `calloc`/`malloc` in `http.c` (manual audit + fixes)
- [x] Each H fix has a test or documented existing coverage (see table)
- [x] `ctest --test-dir build` green after changes

**Acceptance:** Each fix has a test or is covered by existing tests; no new HIGH findings in touched files.

### 0.3 Audit medium fixes (subset)

> **Status (2026-06-26):** M-1 verified (`sc_header_cb` overflow guard in
> `test_sc_header_cb_overflow_guard`). M-3 verified: `reload_allow_list()` assigns
> `dm_policy` under `security_mutex`; `sc_channel_handle_message()` reads policy
> under the same lock; regression tests in `tests/test_channel_manager.c`.

Prioritize items on the agent/provider hot path:

- [x] M-1: Integer overflow in `sc_header_cb` — `test_sc_header_cb_overflow_guard`
- [x] M-3: `dm_policy` write under `security_mutex` — `test_reload_dm_policy_*`,
  `test_reload_allow_list_assigns_dm_policy_under_lock`
- [ ] M-8: Covered by 0.7

Defer M-2, M-4–M-7, M-9–M-10 to Phase 4 unless blocking.

### 0.4 Size-optimized release build

**Files:** `cmake/size_optimize.cmake`, `CMakeLists.txt`, `.gitea/workflows/ci.yml`,
`scripts/release-build.sh`, `README.md`

> **Status (2026-06-26):** `cmake/size_optimize.cmake` applies thin LTO +
> section GC whenever `CMAKE_BUILD_TYPE=MinSizeRel`. Release tags build with
> `MinSizeRel` via `scripts/release-build.sh`; CI `size-budget` job uses the same
> profile (flags no longer duplicated on the cmake command line).

- [x] `MinSizeRel` release profile (`cmake/size_optimize.cmake`)
- [x] `-flto=thin`, `-ffunction-sections`, `-fdata-sections`, `-Wl,--gc-sections`
- [x] CI release job uses size profile (`release-build.sh` → `MinSizeRel`)
- [x] Document in README building section

**Acceptance:** ≥10% size reduction on x86_64 release vs pre-change baseline.

| Profile | Stripped (B) | vs §0.1 Release baseline (2,180,864 B) |
|---------|--------------|----------------------------------------|
| Release (pre-0.4, §0.1) | 2,180,864 | — |
| MinSizeRel + LTO + gc (full defconfig, post-0.4) | **1,251,696** | **−42.6%** |
| CI minimal-dynamic (post-0.4 LTO) | **250,880** → **245 KB** | was 262,640 B (§0.1) |

**Verification gates (2026-06-26):** `ctest --test-dir build-verify` **43/43** passed.
KC-2 clean (0 `implicit` in build log). `check_size_budget.sh build-size/smolclaw
1024` → OK (245 KB). Toolchain used full `-flto` (Debian gcc 12.2 lacks `-flto=thin`;
`cmake/size_optimize.cmake` prefers thin when supported).

### 0.5 Gate SQLite FTS5

**Files:** `CMakeLists.txt`, `Kconfig`, `configs/defconfig.minimal`

> **Status (2026-06-26):** `SQLITE_ENABLE_FTS5` is set only when
> `SC_ENABLE_MEMORY_SEARCH=y`. Minimal and analytics-only (memory search off)
> builds have zero `fts5` symbols in `smolclaw` and `libsqlite3.a`.

- [x] `SQLITE_ENABLE_FTS5` only when `SC_ENABLE_MEMORY_SEARCH=y`
- [x] Minimal build verifies no FTS5 symbols (`nm build-minimal/smolclaw`: 0)
- [x] Full build + `test_memory_tools` / `test_memory_search` pass

**Verification gates (2026-06-26):** `ctest --test-dir build-full` **43/43** passed.
Analytics-only (`MEMORY_SEARCH` off, `ANALYTICS` on): 0 FTS5 symbols in binary and
`libsqlite3.a`. KC-2 clean; size budget unchanged (minimal has no SQLite link).

### 0.6 Checkpoint & rewind — ALREADY SHIPPED (verify-only)

**Source:** [`docs/plan-checkpoint-rewind.md`](../../plan-checkpoint-rewind.md)

**Files:** `src/agent_internal.h`, `src/agent_turn.c`, `tests/test_agent.c`

> **Status (2026-06-26):** Verified in HEAD. `sc_checkpoint_t`,
> `SC_MAX_CHECKPOINTS` (2-slot ring buffer), `rewind_count` cap (max 2), and
> restore-on-3-errors / pre-escalation rewind paths confirmed via source audit
> and `test_checkpoint_rewind_on_tool_errors` in `tests/test_agent.c`.

- [x] Ring buffer of 2 checkpoints after successful tool execution (`checkpoint_save`)
- [x] Rewind on error budget threshold (`tool_error_count == 3` → `checkpoint_rewind`)
- [x] Rewind before model escalation (`checkpoint_rewind` before fallback model)
- [x] Max 2 rewinds per turn (`tc->rewind_count >= 2` guard)
- [x] Inject rewind hint user message (post-rewind hint in `postprocess_result`)

**Acceptance:** Unit or integration test simulating repeated tool errors → rewind → success path.

**Verification gates (2026-06-26):** `test_checkpoint_rewind_on_tool_errors` and
`test_checkpoint_rewind_structural` pass; full `ctest --test-dir build-full` green.

### 0.7 Structured tasks (sc_task_t)

**Source:** zed-patterns Task 2

> **Status (2026-06-26):** `src/util/task.{c,h}` already exist with the full
> `sc_task_spawn` / `poll` / `join(timeout_ms)` / `cancel` / `free` API.
> **Remaining work:** confirm `agent_session.c` summarization runs on
> `sc_task_t` and that agent shutdown cancels+joins it (the actual M-8 fix),
> rather than the standalone worker-thread path. Verify, then add a test.

**Files:** `src/util/task.{c,h}` *(exist)*, `src/agent_session.c`, `src/agent.c`

- [x] `sc_task_spawn` / `poll` / `join` / `cancel` / `free` *(shipped)*
- [ ] Summarization uses sc_task_t; joined on agent shutdown
- [ ] Cancel flag checked in summarization loop

**Acceptance:** Rapid shutdown during summarization does not leak threads (M-8).

### 0.8 Deferred runtime initialization

**Authoritative spec:** [`../deferred-initialization.md`](../deferred-initialization.md)  
**Hermes gap (Tier 1):** Pattern lift from Hermes PRs #28864, #28957 — lazy init without
memoization bloat.

**Files:** `src/memory_index.c`, `src/util/sandbox.c` (or deny-pattern module), `src/agent.c`

**Targets (priority order):**

- [ ] **FTS5 memory index rebuild** — defer until first `memory_search` / `memory_read` that needs index
- [ ] **Exec deny-regex table** — compile on first `exec` tool use; deduplicate if compiled twice today
- [ ] **TLS context (IRC/Web/WSS)** — verify already lazy; document invariant in code comment
- [ ] **Vault unlock probe** — verify already lazy; document invariant in code comment

**Smol invariants (from spec):**

- Subtraction beats addition — cold path should not allocate unused subsystems
- No new globals — use sentinels in existing structs where possible
- No memoization caches that add RSS without reducing it

**Acceptance:**

- [ ] `smolclaw agent -m "hi"` with memory search disabled does not rebuild FTS5 index
- [ ] `smolclaw agent -m "hi"` with no exec does not compile deny-regex table
- [ ] Record peak RSS before/after on minimal musl-static smoke run (note in this doc)
- [ ] ctest green; no regression in `test_memory_tools`, `test_security`

---

## 3. Exit Criteria

- [ ] All Phase 0 checkboxes complete
- [ ] `ctest --test-dir build` passes
- [ ] Binary size ≤ baseline or documented reduction from 0.4/0.5
- [ ] RSS/startup improvement from 0.8 recorded (or N/A with justification)
- [ ] No open HIGH audit items in provider/channel/tool hot paths
- [ ] Update master-plan status line for Phase 0

---

## 4. Risks & Mitigations

| Risk                                   | Mitigation                                    |
|----------------------------------------|-----------------------------------------------|
| Discord SSL mutex changes behavior     | Test gateway reconnect                        |
| LTO breaks obscure platform            | CI matrix glibc + musl                        |
| Checkpoint rewind loses valid progress | Only rewind on stuck detection; cap at 2/turn |
| FTS5 gate breaks accidental FTS use    | Grep for FTS5 API usage                       |

---

## 5. Suggested PR order

1. `fix: audit high-severity NULL and concurrency issues`
2. `build: size-optimized release profile + optional FTS5`
3. `perf: deferred runtime init for FTS5 and deny-regex`
4. `feat: agent turn checkpoint rewind` (verify if already shipped)
5. `feat: sc_task_t for summarization lifecycle`

---

**Next phase:** [Phase 1 — Context Efficiency](phase-1-context-efficiency.md)
