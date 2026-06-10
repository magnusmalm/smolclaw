# Phase 3: Optional Surface Area

**Status**: Not started  
**Master plan**: [`../master-plan.md`](../master-plan.md)  
**Prerequisite**: [Phase 2](phase-2-operator-provider-ux.md) complete  
**Goal**: Kconfig-gated channel and config presets; small backlog items.  
**LOC budget**: ~1,200–1,800  
**Binary target**: +≤80 KB **per enabled flag**; default build unchanged

---

## 1. Scope

| # | Task | Source | LOC | Binary | Gate |
|---|------|--------|-----|--------|------|
| 3.1 | Signal channel MVP (Phase 0+1) | signal-channel.md | 800–1,000 | +40–80 KB | `SC_ENABLE_SIGNAL` **default n** |
| 3.2 | Operator mode presets | smallharness §6 task 5 | 150–250 | ~5 KB | config |
| 3.3 | Enhanced tool confirmation | smallharness §6 task 6 | 200–350 | ~10 KB | config |
| 3.4 | X `note_tweet` field | todo.md | 10–20 | ~0 | always |
| 3.5 | Notify: Slack + ntfy backends | todo.md | 80–120 | ~5 KB | optional |
| 3.6 | Subagent tool deny matrices | claude-code P1 #3 | 40–60 | ~0 | always |

---

## 2. Task Details

### 3.1 Signal channel MVP

**Authoritative spec:** [`../signal-channel.md`](../signal-channel.md)  
**User doc:** [`../../channels/signal.md`](../../channels/signal.md)  
**Implement guide:** [`../../development/using-grok-implement-skill.md`](../../development/using-grok-implement-skill.md)

**Reference implementation:** `src/channels/x.c`, `tests/test_x.c`

**Deliverables:**

- [ ] Kconfig `SC_ENABLE_SIGNAL` (default **n**, `select NEED_PTHREADS`)
- [ ] `sc_signal_config_t` + JSON + env overrides
- [ ] `src/channels/signal.c` + `signal.h` (~550–700 LOC)
- [ ] JSON-RPC client: `receive`, `send`, `subscribeReceive`
- [ ] Polling thread; text-only DMs + groups
- [ ] Identifier normalization: prefer `uuid:...`, support `+phone`
- [ ] `group_trigger`, full pairing / `allow_from` / strict security
- [ ] Wire in `manager.c` with quarantine check
- [ ] `tests/test_signal.c` via `mock_http.h` (≥10 cases from design §8.2)
- [ ] Update `docs/channels/signal.md` for implemented MVP

**Explicitly NOT in 3.1:** SSE streaming, attachments, reactions (Phase 5).

**Effort:** design estimates 9–13 dev-days.

### 3.2 Operator mode presets

**Source:** smallharness-integration task 5

**Files:** `src/config.c`, `src/config.h`

Modes: `explore`, `edit`, `ship`, `review`, `custom`

Each mode sets:

- Tool allowlist ceiling
- `approval_policy` / confirm behavior
- `max_tool_iterations` clamp

- [ ] `operator_mode` config field; `"custom"` preserves explicit lists
- [ ] Apply on config load; document in README
- [ ] CLI: `smolclaw config set agents.defaults.operator_mode ship` (optional)

### 3.3 Enhanced tool confirmation

**Source:** smallharness-integration task 6

**Files:** `src/tools/registry.c`, `src/channels/cli.c`, `src/tools/file_tools.c`

- [ ] `approval_policy`: `always` | `never` | `dangerous-only`
- [ ] Diff preview on confirm for file edit/write (cap 80 lines display)
- [ ] Session allow cache: always-for-tool, session-allow-exact-call
- [ ] Precedence: `auto_confirm` > policy > interactive
- [ ] Async channels: summary-only confirm (document limitation)

### 3.4 X note_tweet

**Files:** `src/tools/x_tools.c` or `src/util/x_api.c`

- [ ] Add `note_tweet` to `tweet.fields` in `x_get_thread`, `x_search`
- [ ] `format_tweet()` already handles field

### 3.5 Notify backends

**Files:** `src/tools/notify.c`

- [ ] Slack incoming webhook URL scheme
- [ ] ntfy.sh / self-hosted ntfy topic scheme
- [ ] Low priority — ship only if trivial

### 3.6 Subagent tool matrices

**Source:** claude-code P1 #3

**Files:** `src/tools/spawn.c`, `src/tools/registry.c`

- [ ] Depth-based deny lists (depth≥1: no spawn/delegate/cron; depth≥2: stricter)
- [ ] MCP standalone mode: read-only tools only

---

## 3. Exit Criteria

- [ ] Signal MVP passes mock tests; manual smoke test documented
- [ ] Default build (`SC_ENABLE_SIGNAL=n`) binary size unchanged vs Phase 2
- [ ] Operator modes documented with preset table
- [ ] Spawn depth restrictions tested
- [ ] README feature table updated for Signal when enabled

---

## 4. Risks

| Risk | Mitigation |
|------|------------|
| Signal daemon API drift | Version note in docs; defensive JSON parsing |
| UUID vs phone pairing bugs | Explicit test cases from design §8.2 |
| Diff confirm on Telegram | Summary text fallback |
| Operator mode clobber custom config | `custom` mode no-op on reload |

---

## 5. Suggested PR order

1. `feat: subagent tool deny matrices by spawn depth`
2. `feat: operator mode presets and enhanced confirmation`
3. `fix: request note_tweet in X thread/search APIs`
4. `feat: Signal channel MVP (SC_ENABLE_SIGNAL, default off)` — large, isolated PR
5. `feat: notify slack/ntfy backends` (optional)

---

**Next phase:** [Phase 4 — Larger Investments](phase-4-larger-investments.md)
