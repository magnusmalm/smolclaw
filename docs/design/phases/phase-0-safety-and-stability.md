# Phase 0: Safety & Stability

**Status**: Not started  
**Master plan**: [`../master-plan.md`](../master-plan.md)  
**Goal**: Close known high-severity bugs, improve shutdown/thread safety, establish binary size baseline, add checkpoint rewind.  
**LOC budget**: ~500–900  
**Binary target**: Net **smaller or flat** (size optimizations offset small fixes)

---

## 1. Scope

Phase 0 fixes foundations before any feature work touches `agent_turn.c`, providers, or channels.

- **0.1** — Task: Record size & test baseline; Source: master-plan §7; LOC: —; Binary: —; Smol: ✓
- **0.2** — Task: Audit high-severity fixes (H-1–H-11); Source: code-analysis-report; LOC: 250–400;
  Binary: +0–5 KB; Smol: ✓
- **0.3** — Task: Audit medium fixes (priority subset); Source: code-analysis-report; LOC: 100–200;
  Binary: ~0; Smol: ✓
- **0.4** — Task: Binary size build profile; Source: todo.md; LOC: 50–100 CMake; Binary:
  **−10–25%**; Smol: ✓✓
- **0.5** — Task: Optional SQLite FTS5 gate; Source: todo.md; LOC: 20–50 CMake; Binary: **−50–200
  KB** minimal; Smol: ✓✓
- **0.6** — Task: Checkpoint & rewind; Source: plan-checkpoint-rewind; LOC: 100–150; Binary: ~0;
  Smol: ✓
- **0.7** — Task: sc_task_t + summarization join (M-8); Source: zed-patterns T2; LOC: 150–250;
  Binary: ~5 KB; Smol: ✓

**Out of scope for Phase 0:** arena allocator (Phase 4 or early if provider fixes proliferate), new features, new channels.

---

## 2. Task Details

### 0.1 Measurement baseline

- [ ] Record `build/smolclaw` and `build-minimal/smolclaw` byte sizes
- [ ] Record `ctest` pass count
- [ ] Note git SHA in this doc

### 0.2 Audit high-severity fixes

**Files:** `src/providers/provider_common.c`, `src/providers/http.c`, `src/channels/discord.c`, `src/channels/telegram.c`, `src/tools/file_tools.c`, `src/logger.c`

| ID       | Fix                                           |
|----------|-----------------------------------------------|
| H-1      | NULL check after malloc in `sc_curl_write_cb` |
| H-2, H-3 | NULL check after calloc for tool_calls        |
| H-4      | Bounds check after SSE realloc failure        |
| H-5, H-6 | Validate author/user id before use            |
| H-7      | Block `.git/hooks/` in write paths            |
| H-8      | Mutex around logger writes                    |
| H-9      | Serialize Discord SSL access                  |
| H-10     | Atomic write (temp + rename) for edit_file    |
| H-11     | Remaining unchecked allocs in http provider   |

**Acceptance:** Each fix has a test or is covered by existing tests; no new HIGH findings in touched files.

### 0.3 Audit medium fixes (subset)

Prioritize items on the agent/provider hot path:

- [ ] M-1: Integer overflow in `sc_header_cb`
- [ ] M-3: `dm_policy` write under `security_mutex`
- [ ] M-8: Covered by 0.7

Defer M-2, M-4–M-7, M-9–M-10 to Phase 4 unless blocking.

### 0.4 Size-optimized release build

**Files:** `CMakeLists.txt`, `.github/workflows/release.yml`

- [ ] `MinSizeRel` or explicit `-Os`/`-Oz` release profile
- [ ] `-flto=thin`, `-ffunction-sections`, `-fdata-sections`, `-Wl,--gc-sections`
- [ ] CI release job uses size profile
- [ ] Document in README building section

**Acceptance:** ≥10% size reduction on x86_64 release vs pre-change baseline.

### 0.5 Gate SQLite FTS5

**Files:** `CMakeLists.txt`, `Kconfig`, `configs/defconfig.minimal`

- [ ] `SQLITE_ENABLE_FTS5` only when `SC_ENABLE_MEMORY_SEARCH=y`
- [ ] Minimal build verifies no FTS5 symbols
- [ ] Full build + `test_memory_tools` pass

### 0.6 Checkpoint & rewind

**Source:** [`docs/plan-checkpoint-rewind.md`](../../plan-checkpoint-rewind.md)

**Files:** `src/agent_internal.h`, `src/agent_turn.c`

- [ ] Ring buffer of 2 checkpoints after successful tool execution
- [ ] Rewind on error budget threshold / per-tool-name stuck count
- [ ] Rewind before model escalation (clean context for fallback model)
- [ ] Max 2 rewinds per turn (prevent infinite loop)
- [ ] Inject rewind hint system/user message

**Acceptance:** Unit or integration test simulating repeated tool errors → rewind → success path.

### 0.7 Structured tasks (sc_task_t)

**Source:** zed-patterns Task 2

**Files:** new `src/util/task.c`, `src/agent_session.c`, `src/agent.c`

- [ ] `sc_task_spawn` / `poll` / `join` / `cancel` / `free`
- [ ] Summarization uses sc_task_t; joined on agent shutdown
- [ ] Cancel flag checked in summarization loop

**Acceptance:** Rapid shutdown during summarization does not leak threads (M-8).

---

## 3. Exit Criteria

- [ ] All Phase 0 checkboxes complete
- [ ] `ctest --test-dir build` passes
- [ ] Binary size ≤ baseline or documented reduction from 0.4/0.5
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
3. `feat: agent turn checkpoint rewind`
4. `feat: sc_task_t for summarization lifecycle`

---

**Next phase:** [Phase 1 — Context Efficiency](phase-1-context-efficiency.md)
