# Phase 3: Optional Surface Area

**Status**: Not started  
**Master plan**: [`../master-plan.md`](../master-plan.md)  
**Prerequisite**: [Phase 2](phase-2-operator-provider-ux.md) complete  
**Goal**: Kconfig-gated channel and config presets; gateway behavior polish; small backlog items.  
**LOC budget**: ~1,500–2,100  
**Binary target**: +≤80 KB **per enabled flag**; default build unchanged

---

## 1. Scope

- **3.1** — Task: Signal channel MVP (Phase 0+1); Source: signal-channel.md; LOC: 800–1,000; Binary:
  +40–80 KB; Gate: `SC_ENABLE_SIGNAL` **default n**
- **3.2** — Task: Operator mode presets; Source: smallharness §6 task 5; LOC: 150–250; Binary: ~5
  KB; Gate: config
- **3.3** — Task: Enhanced tool confirmation; Source: smallharness §6 task 6; LOC: 200–350; Binary:
  ~10 KB; Gate: config
- **3.4** — Task: X `note_tweet` field; Source: todo.md; LOC: 10–20; Binary: ~0; Gate: always
- **3.5** — Task: Notify: Slack + ntfy backends; Source: todo.md; LOC: 80–120; Binary: ~5 KB; Gate:
  optional
- **3.6** — Task: Subagent tool deny matrices; Source: claude-code P1 #3; LOC: 40–60; Binary: ~0;
  Gate: always
- **3.7** — Task: Session reset policies (daily/idle); Source: Hermes-gap; Tier: **T1**; LOC:
  100–150; Binary: ~5 KB; Gate: config
- **3.8** — Task: Busy-input modes (interrupt/queue); Source: Hermes-gap; Tier: **T1**; LOC:
  150–250; Binary: ~5 KB; Gate: config
- **3.9** — Task: Silent delivery tokens; Source: Hermes-gap; Tier: **T1**; LOC: 40–60; Binary: ~0;
  Gate: config

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

**Files:** `src/tools/registry.c`, `src/channels/cli.c`, `src/tools/filesystem.c`

> **Decision (Q3, 2026-06-26):** async channels (Telegram/Discord) get a capped
> **summary-only** confirm (tool/path/size, no raw diff) via the existing
> tool-confirm reply flow; full unified diff only on interactive CLI + Web. If a
> channel has no confirm path and `auto_confirm` is off, **deny** dangerous ops
> (fail-closed). See `autonomy-readiness.md` §3.

- [ ] `approval_policy`: `always` | `never` | `dangerous-only`
- [ ] Diff preview on confirm for file edit/write (cap 80 lines display)
- [ ] Session allow cache: always-for-tool, session-allow-exact-call
- [ ] Precedence: `auto_confirm` > policy > interactive
- [ ] Async channels: summary-only confirm (document limitation)

### 3.4 X note_tweet

**Files:** `src/tools/x_tools.c` or `src/util/x_api.c`

- [x] Add `note_tweet` to `tweet.fields` in `x_get_thread` (both requests) and
  `x_search` (`x_get_tweet` already requested `note_tweet,article`)
- [x] `format_tweet()` already prefers article > note_tweet > text (verified)

**Status (2026-06-27):** ✅ done (request-param only; `format_tweet` already
consumed the field — its preference just had no data on thread/search). Gated by
`SC_ENABLE_X_TOOLS`; verified compiles with `-DSC_ENABLE_X_TOOLS=ON`.

### 3.5 Notify backends

**Files:** `src/tools/notify.c`

- [ ] Slack incoming webhook URL scheme
- [ ] ntfy.sh / self-hosted ntfy topic scheme
- [ ] Low priority — ship only if trivial

### 3.6 Subagent tool matrices

**Source:** claude-code P1 #3

**Files:** `src/tools/spawn.c`, `src/tools/registry.c`

- [x] Depth-based deny lists (depth≥1: no spawn/delegate/cron; depth≥2: also
  notify/converse/background) — was already wired in `spawn_depth_guard`;
  refactored the decision into testable `sc_spawn_tool_denied_at_depth()`
- [x] MCP standalone mode: read-only tools by default (`sc_tools_readonly_names`
  applied in `cmd_mcp_server`); `--all-tools` opt-out; explicit `allowed_tools`
  config still wins

**Status (2026-06-27):** ✅ done. The depth guard pre-existed; this slice made
it testable and added the MCP read-only default + `--all-tools`. New
`tests/test_subagent_caps.c` (deny matrix + read-only allowlist). README
documents the flag.

### 3.7 Session reset policies

**Source:** Hermes `reset_by_platform` in gateway config.

**Files:** `src/config.c`, `src/session.c`, `src/channels/manager.c`

- [ ] Config per channel: `reset_mode`: `none` | `daily` | `idle` | `both`
- [ ] `daily_reset_hour` (default 4:00 local) and `idle_minutes` (default 1440)
- [ ] On inbound message: check policy → start fresh session if triggered
- [ ] Per-platform overrides under `channels.<name>.reset` (optional)
- [ ] Document in `docs/CONFIGURATION.md`; no LLM call on reset

**Hermes parity:** automatic session hygiene without manual `/reset`.

### 3.8 Busy-input modes

**Source:** Hermes `display.busy_input_mode` — interrupt (default), queue, steer.

**Files:** `src/bus.c`, `src/agent_turn.c`, channel adapters

**Ship in 3.8:**

- [ ] `busy_input_mode`: `interrupt` (default, current behavior) | `queue`
- [ ] **Interrupt:** new message cancels in-flight turn (existing behavior; document)
- [ ] **Queue:** hold messages until current turn completes; combine into one follow-up prompt
- [ ] Optional `busy_ack_enabled` — short ack line (`⏳ queued`) on async channels
- [ ] Config under `agents.defaults` or `gateway.display`

**Defer to Phase 5:** `steer` mode (inject mid-turn without new session — higher complexity).

### 3.9 Silent delivery tokens

**Source:** Hermes intentional silence for group chats and automations.

**Files:** `src/channels/manager.c`, outbound delivery path

- [ ] If agent final response is exactly one token (after trim + case fold): `[SILENT]`, `SILENT`,
  `NO_REPLY`, `NO REPLY` — suppress outbound delivery
- [ ] Silence turn **stored** in session transcript (alternation preserved)
- [ ] Failed turns still surface errors (do not silence errors)
- [ ] Config: `gateway.silent_tokens_enabled` (default true)

---

## 3. Exit Criteria

- [ ] Signal MVP passes mock tests; manual smoke test documented
- [ ] Default build (`SC_ENABLE_SIGNAL=n`) binary size unchanged vs Phase 2
- [ ] Operator modes documented with preset table
- [ ] Spawn depth restrictions tested
- [ ] README feature table updated for Signal when enabled
- [ ] Session reset policy tested: idle timeout starts fresh session
- [ ] Queue mode delivers combined follow-up after busy turn
- [ ] Silent token suppresses outbound but retains transcript

---

## 4. Risks

| Risk                                | Mitigation                                   |
|-------------------------------------|----------------------------------------------|
| Signal daemon API drift             | Version note in docs; defensive JSON parsing |
| UUID vs phone pairing bugs          | Explicit test cases from design §8.2         |
| Diff confirm on Telegram            | Summary text fallback                        |
| Operator mode clobber custom config | `custom` mode no-op on reload                |

---

## 5. Suggested PR order

1. `feat: subagent tool deny matrices by spawn depth`
2. `feat: operator mode presets and enhanced confirmation`
3. `fix: request note_tweet in X thread/search APIs`
4. `feat: session reset policies and busy-input queue mode`
5. `feat: silent delivery tokens for gateway`
6. `feat: Signal channel MVP (SC_ENABLE_SIGNAL, default off)` — large, isolated PR
7. `feat: notify slack/ntfy backends` (optional)

---

## 6. Slice log

- **Slice 1 — `task/3.6-subagent-caps` (task 3.6)** — 2026-06-27. Refactored the
  spawn depth-deny decision into testable `sc_spawn_tool_denied_at_depth()`;
  added MCP-server read-only default (`sc_tools_readonly_names` +
  `cmd_mcp_server --all-tools` opt-out). New `tests/test_subagent_caps.c`.
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest` 48/48;
  `check_size_budget.sh` minimal-dynamic 269 KB ≤ 1024 KB; `check_claude_md.sh`
  clean; no new Kconfig flag (KC-1 N/A).
- **Slice 2 — `task/3.4-note-tweet` (task 3.4)** — 2026-06-27. Added `note_tweet`
  to `tweet.fields` in `x_get_thread` (×2) and `x_search` so `format_tweet`'s
  existing long-tweet preference has data. Request-param only; no test seam
  (static `format_tweet`, live-API field).
  **Verification gates:** Release `-DSC_ENABLE_X_TOOLS=ON` build clean (KC-2
  `implicit`=0); `ctest` 48/48; `check_size_budget.sh` minimal-dynamic 269 KB ≤
  1024 KB (X_TOOLS off in minimal); `check_claude_md.sh` clean.

---

**Next phase:** [Phase 4 — Larger Investments](phase-4-larger-investments.md)
