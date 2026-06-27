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

- [x] Kconfig `SC_ENABLE_SIGNAL` (default **n**, `select NEED_PTHREADS`); KC-1
  wired (FEATURE_SYMS + cmake override + defconfig.minimal)
- [x] `sc_signal_config_t` (`signal_` field — avoids shadowing libc `signal()`)
  + JSON + env overrides + serialize + free
- [x] `src/channels/signal.c` + `signal.h` + `signal_internal.h` (pure-helper seam)
- [x] JSON-RPC client `signal_rpc(method, params)` over `POST /api/v1/rpc`;
  `receive` + `send` (subscribeReceive deferred — polling-only MVP)
- [x] Polling thread with backoff; text-only DMs + groups
- [x] Identifier normalization: prefer `uuid:...`, support `+phone`
  (`sc_signal_normalize_sender`); group `chat_id` → `signal:group:<id>`
- [x] `group_trigger` filter; full pairing / `allow_from` / strict security
  via `channels/base.c` + manager quarantine check
- [x] Wire in `manager.c` with quarantine check
- [x] `tests/test_signal.c` via `mock_http.h` (18 cases: pure-helper truth
  tables + send/lifecycle; covers design §8.2 DM-phone/DM-uuid/group/allow_from/
  trigger/send/error)
- [x] Update `docs/channels/signal.md` for implemented MVP; README feature table

**Explicitly NOT in 3.1:** SSE streaming, attachments, reactions (Phase 5);
`subscribeReceive`/typing/health (Phase 2 of the Signal design).

**Status (2026-06-27):** ✅ code-complete (mock-accepted). 🟠 **Live smoke test
against a real `signal-cli` daemon + test number remains a human acceptance gate**
(GATED-EXT). The receive-loop's exact daemon JSON-RPC shape (`receive` polling
per design §6.2) should be reconciled during that smoke test.

### 3.2 Operator mode presets

**Source:** smallharness-integration task 5

**Files:** `src/config.c`, `src/config.h`

Modes: `explore`, `edit`, `ship`, `review`, `custom`

Each mode sets:

- Tool allowlist ceiling
- `approval_policy` / confirm behavior
- `max_tool_iterations` clamp

- [x] `operator_mode` config field (`agents.defaults`); `"custom"`/unknown/NULL = no-op
- [x] Apply on config load (`sc_config_apply_operator_mode`); documented in CONFIGURATION.md
- [~] Tool-allowlist ceiling per mode — **deferred** (entangled with read-only /
  per-channel / user lists); modes set approval_policy + iteration clamp
- [ ] CLI `config set` helper — optional, not shipped

**Status (2026-06-27):** ✅ done (presets: explore/edit/review/ship + custom).
Pure `sc_config_apply_operator_mode`; tests in `test_config.c`.

### 3.3 Enhanced tool confirmation

**Source:** smallharness-integration task 6

**Files:** `src/tools/registry.c`, `src/channels/cli.c`, `src/tools/filesystem.c`

> **Decision (Q3, 2026-06-26):** async channels (Telegram/Discord) get a capped
> **summary-only** confirm (tool/path/size, no raw diff) via the existing
> tool-confirm reply flow; full unified diff only on interactive CLI + Web. If a
> channel has no confirm path and `auto_confirm` is off, **deny** dangerous ops
> (fail-closed). See `autonomy-readiness.md` §3.

- [x] `approval_policy`: `always` | `never` | `dangerous-only` (pure
  `sc_approval_requires_confirm`, gates the registry confirm path)
- [~] Diff preview on confirm — **deferred** (interactive rendering; confirm_cb
  gets an args summary, not structured args)
- [x] Session allow cache: **always-for-tool** (confirm returns 2 → cached in
  registry, skips re-prompt). Exact-call cache deferred.
- [x] Precedence: `auto_confirm` (gateway auto-approve) > policy > interactive
- [~] Async summary-only confirm — **deferred** (needs a channel confirm-reply
  flow; gateway currently auto-approves, fail-closed per Q3 stands)

**Status (2026-06-27):** ✅ core done. `approval_policy` (registry-level) +
CLI `y/N/a` always-allow cache. Interactive diff-preview and async
summary-confirm are documented follow-ups. Tests in `test_subagent_caps.c`.

### 3.4 X note_tweet

**Files:** `src/tools/x_tools.c` or `src/util/x_api.c`

- [x] Add `note_tweet` to `tweet.fields` in `x_get_thread` (both requests) and
  `x_search` (`x_get_tweet` already requested `note_tweet,article`)
- [x] `format_tweet()` already prefers article > note_tweet > text (verified)

**Status (2026-06-27):** ✅ done (request-param only; `format_tweet` already
consumed the field — its preference just had no data on thread/search). Gated by
`SC_ENABLE_X_TOOLS`; verified compiles with `-DSC_ENABLE_X_TOOLS=ON`.

### 3.5 Notify backends

**Files:** `src/tools/notify.c`, `src/tools/notify_internal.h`, `src/tools/notify.h`

- [x] Slack incoming webhook URL scheme — `slack://<webhook-path>` →
  `https://hooks.slack.com/services/<path>`, `{"text":"*title*\nbody"}`
- [x] ntfy.sh / self-hosted ntfy topic scheme — `ntfy://topic` (ntfy.sh) and
  `ntfy://host/topic` (self-hosted, https) → JSON publish `{topic,title,message}`
- [x] Stayed trivial: both slot into the existing `parse_one_url` + `send_one`
  switch, reusing `http_post_json`/`json_escape_str`. Parser extracted to
  `notify_internal.h` and unit-tested (`test_notify.c`, also retro-covering the
  pre-existing discord/tg/json schemes).

**Status (2026-06-27):** ✅ done. Two new Apprise-compatible schemes; ~50 LOC
plus the test seam. No Kconfig flag (notify is a core tool).

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

- [x] Config `session_reset.mode`: `none` | `daily` | `idle` | `both` (top-level)
- [x] `daily_reset_hour` (default 4 local) and `idle_minutes` (default 1440)
- [x] On inbound gateway message: `sc_session_reset_due` → `sc_session_reset` if triggered
- [~] Per-platform overrides under `channels.<name>.reset` — **deferred** (global
  policy ships; per-channel override is the spec's "(optional)")
- [x] Documented in `docs/CONFIGURATION.md`; no LLM call on reset

**Status (2026-06-27):** ✅ done. Pure decision `sc_session_reset_due()` +
`sc_session_get_updated()` (session.c), config + agent fields, gateway hook.
Tests in `test_session.c` (idle/daily/both/none, getter).

**Hermes parity:** automatic session hygiene without manual `/reset`.

### 3.8 Busy-input modes

**Source:** Hermes `display.busy_input_mode` — interrupt (default), queue, steer.

**Files:** `src/bus.c`, `src/agent_turn.c`, channel adapters

**Ship in 3.8:**

- [x] `busy_input_mode`: `interrupt` (default) | `queue` (top-level config)
- [x] **Interrupt:** documented — smolclaw processes queued messages sequentially
  in arrival order (it does **not** cancel a turn mid-flight; the spec's
  "cancel in-flight" doesn't match the single-threaded gateway, so this is the
  honest description of current behavior)
- [x] **Queue:** coalesce all pending **same-chat** messages into one follow-up
  turn (`sc_bus_drain_inbound_matching` + combine in the gateway loop)
- [~] Optional `busy_ack_enabled` (`⏳ queued`) — **deferred**: needs a busy flag
  visible to the channel publish threads; out of MVP
- [x] Config top-level `busy_input_mode`

**Status (2026-06-27):** ✅ done. New `sc_bus_drain_inbound_matching()` (bus.c,
order-preserving, lock-held); gateway loop coalesces in queue mode; config +
agent field. Tests in `test_bus.c`.

**Defer to Phase 5:** `steer` mode (inject mid-turn without new session — higher complexity).

### 3.9 Silent delivery tokens

**Source:** Hermes intentional silence for group chats and automations.

**Files:** `src/gateway_route.h`, `src/main.c` (gateway delivery), `src/config.{c,h}`, `src/agent.{c,h}`

- [x] If agent final response is exactly one token (after trim + case fold): `[SILENT]`, `SILENT`,
  `NO_REPLY`, `NO REPLY` — suppress outbound delivery (pure `sc_gateway_is_silent_token`)
- [x] Silence turn **stored** in session transcript (alternation preserved) —
  free by construction: `run_agent_loop` stores the assistant message before
  returning; the gateway only suppresses the *delivery*
- [x] Failed turns still surface errors (do not silence errors) — free by
  construction: error strings begin with `Error: …` and can't equal a token
- [x] Config: `silent_tokens_enabled` (default true). **Top-level** key (not
  `gateway.…`) to match siblings 3.7 `session_reset` / 3.8 `busy_input_mode`,
  which are also top-level; deviation from the spec's dotted name documented in
  `docs/CONFIGURATION.md`.

**Status (2026-06-27):** ✅ done. Pure decision `sc_gateway_is_silent_token()`
(gateway_route.h, header-inline like `sc_gateway_should_isolate`); gateway hook
in `main.c` suppresses delivery when enabled + matched. Config/agent field
default-true. Tests in `test_gateway_routing.c` (exact/case/trim/substring/
error+empty truth table).

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
- **Slice 3 — `task/3.7-3.8-gateway-behavior` (tasks 3.7 + 3.8)** — 2026-06-27.
  Session reset policies (`sc_session_reset_due`/`sc_session_get_updated` +
  config/agent/gateway hook) and busy-input queue mode
  (`sc_bus_drain_inbound_matching` + gateway-loop coalesce). New
  `tests/test_bus.c`; reset tests in `test_session.c`. CONFIGURATION.md updated.
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest` 49/49;
  `check_size_budget.sh` minimal-dynamic 269 KB ≤ 1024 KB; `check_claude_md.sh`
  clean; no new Kconfig flag (KC-1 N/A).
- **Slice 4 — `task/3.2-3.3-operator-confirm` (tasks 3.2 + 3.3)** — 2026-06-27.
  Operator-mode presets (`sc_config_apply_operator_mode`: explore/edit/review/
  ship/custom → approval_policy + iteration clamp) and approval policy
  (`sc_approval_requires_confirm` gating the registry confirm path + session
  always-allow cache via CLI `y/N/a`). Config/agent/MCP wiring. Tests in
  `test_config.c` + `test_subagent_caps.c`. Diff-preview / async-summary /
  allowlist-ceiling deferred (documented).
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest` 49/49;
  `check_size_budget.sh` minimal-dynamic 269 KB ≤ 1024 KB; `check_claude_md.sh`
  clean; no new Kconfig flag (KC-1 N/A).
- **Slice 5 — `task/3.9-silent-tokens` (task 3.9)** — 2026-06-27. Silent
  delivery tokens: pure `sc_gateway_is_silent_token()` (gateway_route.h) matches
  `[SILENT]`/`SILENT`/`NO_REPLY`/`NO REPLY` on the whole trimmed+case-folded
  response; gateway delivery hook in `main.c` suppresses the send when
  `silent_tokens_enabled` (top-level config, default true). Transcript storage
  and error surfacing are free by construction (assistant message stored before
  return; error strings can't match). New truth-table cases in
  `test_gateway_routing.c`; CONFIGURATION.md documents the key.
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest` 49/49;
  `check_size_budget.sh` minimal-dynamic 269 KB ≤ 1024 KB; `check_claude_md.sh`
  clean; no new Kconfig flag (KC-1 N/A).
- **Slice 6 — `task/3.5-notify-backends` (task 3.5)** — 2026-06-27. Added Slack
  (`slack://<webhook-path>`) and ntfy (`ntfy://topic`, `ntfy://host/topic`)
  schemes to the notify tool, slotted into the existing `parse_one_url` +
  `send_one` switch. Extracted the pure parser to `tools/notify_internal.h` and
  added `tests/test_notify.c` (9 cases) — the module had no test before, so this
  also retro-covers discord/tg/json. CONFIGURATION.md gained a scheme table.
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest` 50/50;
  `check_size_budget.sh` minimal-dynamic 269 KB ≤ 1024 KB; `check_claude_md.sh`
  clean; no new Kconfig flag (KC-1 N/A; notify is a core tool).
- **Slice 7 — `task/3.1-signal` (task 3.1)** — 2026-06-27. Signal channel MVP
  behind `SC_ENABLE_SIGNAL` (default n). New `src/channels/signal.{c,h}` +
  `signal_internal.h` (pure seam: sender/group normalization, group-trigger,
  id validation, recipient decomposition, base-url, envelope extraction);
  JSON-RPC client over `POST /api/v1/rpc`; polling receive thread with backoff;
  DM + group send. `sc_signal_config_t` (always-compiled config plumbing, like
  the X channel) + KC-1 wiring + manager construction/quarantine. New
  `tests/test_signal.c` (18 cases via mock_http + pure helpers). Docs:
  `docs/channels/signal.md` flipped to Implemented (MVP), README updated.
  **Mock-accepted; live signal-cli smoke test is a remaining human gate.**
  **Verification gates:** Release `-DSC_ENABLE_SIGNAL=ON` build clean (KC-2
  `implicit`=0); `ctest` 50/50 incl. `test_signal` (#36); minimal (SIGNAL off)
  builds clean, `check_size_budget.sh` 273 KB ≤ 1024 KB (+4 KB from the
  always-compiled config section); `check_claude_md.sh` clean; KC-1 satisfied
  (new flag recognized by genconfig, disabled in minimal).

---

**Next phase:** [Phase 4 — Larger Investments](phase-4-larger-investments.md)
