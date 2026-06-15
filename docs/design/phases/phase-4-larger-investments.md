# Phase 4: Larger Investments

**Status**: Not started  
**Master plan**: [`../master-plan.md`](../master-plan.md)  
**Prerequisite**: [Phase 3](phase-3-optional-surface-area.md) complete (or parallel if demand-driven)  
**Goal**: Optional subsystems and architectural improvements with higher complexity.  
**LOC budget**: ~1,500–2,500 (each item independently shippable)  
**Binary target**: Each feature Kconfig-gated; measure per flag

---

## 1. Scope

- **4.1** — Task: Arena allocator per turn; Source: zed-patterns T1; LOC: 250–400; Binary: +5–15 KB;
  Gate: always
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

Each task is a **separate milestone** — do not batch into one PR.

---

## 2. Task Details

### 4.1 Arena allocator

**Source:** zed-patterns Task 1; closes audit H-1–H-4 class

**Files:** new `src/util/arena.c`, `src/agent_turn.c`, `src/providers/http.c`

- [ ] Bump allocator with reset per turn
- [ ] Provider SSE parsing uses arena
- [ ] Single OOM check point per turn
- [ ] Long-lived data stays on heap

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

**Files:** `src/agent.c` (transform hook), optional `src/tools/context_compress.c`

- [ ] Before LLM call: truncate tool messages older than last 4 below 10K to 500-char summary
- [ ] Uses existing `sc_agent_add_transform()` mechanism

### 4.5 Project memory index

**Source:** smallharness-integration task 7

**Files:** new `src/tools/project_memory.c`, `src/tools/repo_search.c`

- [ ] Index: path, language, size, mtime, SHA-256, symbols, imports, terms
- [ ] Storage: `{workspace}/.smolclaw/project-index.json` (path TBD in open question)
- [ ] `/index` equivalent via CLI or tool actions: build, refresh, status
- [ ] `repo_search` tool for ranked hits
- [ ] Optional system prompt injection for code questions (local providers only by default)
- [ ] Complements `code_graph` — do not duplicate symbol extraction long-term (shared helper later)
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

- [ ] M-2: Web pipe partial read
- [ ] M-4: Session unbounded growth guard
- [ ] M-5: Config reload atomicity
- [ ] M-6: MCP client timeouts
- [ ] M-7: Tool confirm bypass review
- [ ] M-9, M-10: libevent thread safety, IRC reconnect

Prioritize by production impact.

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

- [ ] Time-boxed evaluation: separate `smolclaw-updater` binary vs LTO dead-code elimination
- [ ] Document recommendation; implement only if >50 KB savings proven

---

## 3. Exit Criteria

- [ ] Each shipped item has tests + Kconfig gate where applicable
- [ ] Project memory and microsandbox **not** in default release profile
- [ ] No Phase 4 item required for core agent operation

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
9. **4.10** updater spike
10. **4.9** microsandbox (ops-heavy)

---

## 5. Risks

| Risk                          | Mitigation                                              |
|-------------------------------|---------------------------------------------------------|
| Context pipeline scope creep  | **Not in Phase 4** — see Phase 5                        |
| Project memory secret leakage | Skip `.env`, credentials paths (SmallHarness skip list) |
| Arena double-free             | Arena owns turn-scoped only; document ownership         |
| Microsandbox ops burden       | Document as advanced; default off                       |

---

**Next phase:** [Phase 5 — Defer / Reject](phase-5-defer-reject.md)
