# Phase 2: Operator & Provider UX

**Status**: Not started  
**Master plan**: [`../master-plan.md`](../master-plan.md)  
**Prerequisite**: [Phase 1](phase-1-context-efficiency.md) complete  
**Goal**: Auth for Grok subscribers, session maintenance CLI, provider reliability helpers,
gateway slash commands, Hermes-gap operator docs.  
**LOC budget**: ~1,200–2,000  
**Binary target**: +≤80 KB when xAI OAuth enabled; +~25 KB for session CLI + slash commands without OAuth

---

## 1. Scope

- **2.1** — Task: xAI Grok OAuth provider; Source: xai-grok-oauth.md; LOC: <650; Binary: +40–60 KB;
  Gate: `SC_ENABLE_XAI_OAUTH`
- **2.2** — Task: `smolclaw auth` subcommand; Source: xai-grok-oauth.md; LOC: (in 2.1); Binary: —;
  Gate: same
- **2.3** — Task: `smolclaw session compact`; Source: lazyagent #2; LOC: 150–250; Binary: ~5 KB;
  Gate: CLI
- **2.4** — Task: `smolclaw session prune`; Source: lazyagent #3; LOC: 80–150; Binary: ~5 KB; Gate:
  CLI
- **2.5** — Task: Incremental session reload (optional); Source: lazyagent #1; LOC: 100–200; Binary:
  ~5 KB; Gate: if needed
- **2.6** — Task: Provider health tracking; Source: zed-patterns T6; LOC: 80–150; Binary: ~5 KB;
  Gate: always
- **2.7** — Task: Port conflict diagnostics; Source: todo.md; LOC: 30–50; Binary: ~0; Gate: always
- **2.8** — Task: Verify exponential backoff + fallback; Source: claude-code P1 #5; LOC: 20–50;
  Binary: ~0; Gate: always
- **2.9** — Task: Cron expression parser; Source: Hermes-gap / `src/cron/service.c`; Tier: **T1**;
  LOC: 80–150; Binary: ~5 KB; Gate: `SC_ENABLE_CRON`
- **2.10** — Task: Gateway slash commands MVP; Source: Hermes-gap; Tier: **T1**; LOC: 200–350;
  Binary: +10 KB; Gate: config
- **2.11** — Task: Skills format documentation; Source: audit / agentskills.io; Tier: **T1**; LOC:
  docs only; Binary: 0; Gate: —
- **2.12** — Task: MCP integration cookbook; Source: Hermes-gap; Tier: **T2**; LOC: docs only;
  Binary: 0; Gate: —
- **2.13** — Task: Mixture of Agents (MoA-lite); Source: mixture-of-agents.md; Tier: **T1**;
  LOC: 350–550; Binary: +10–20 KB; Gate: `SC_ENABLE_MOA` default **n**

---

## 2. Task Details

### 2.1–2.2 xAI Grok OAuth

**Authoritative spec:** [`../xai-grok-oauth.md`](../xai-grok-oauth.md)

**New files:** `src/util/xai_oauth.c`, `tests/test_xai_oauth.c`

**Modified:** `src/providers/factory.c`, `src/main.c`, `src/config.c`, `src/util/base64.c`

Deliverables:

- [ ] PKCE login flow with loopback evhttp callback (127.0.0.1 only)
- [ ] Token storage in `~/.smolclaw/auth.json` (0600, atomic replace)
- [ ] JWT `exp` decode for refresh decision (no signature verify)
- [ ] `sc_xai_oauth_ensure_fresh_token()` called from factory for `xai-oauth` provider
- [ ] `smolclaw auth login|status|logout|refresh xai`
- [ ] `--no-browser` for SSH/VPS
- [ ] Provider aliases: `xai-oauth`, `grok-oauth`
- [ ] Kconfig `SC_ENABLE_XAI_OAUTH` — **default n, `depends on SC_ENABLE_XAI`** (Q6, 2026-06-26:
  +40–60 KB → keep minimal builds lean; overrides spec's tentative `default y`). `~/.grok/auth.json`
  interop stays out of MVP (Phase 2).
- [ ] ≥90% line coverage on `xai_oauth.c`; mock HTTP tests

**Smol contract:** <650 LOC, <60 KB binary, zero new deps.

### 2.3 Session compact

**Source:** [`lazyagent_borrow_tasks.md`](../../../lazyagent_borrow_tasks.md)

**Files:** `src/main.c`, `src/session.c`

- [x] Subcommand: `smolclaw session compact [--force] [--max-bytes N] [key...]`
- [x] Truncate large tool-result `content` (role `tool` — stdout / web_fetch)
- [x] Keep head + tail + `...[truncated N bytes]...` marker
- [x] Atomic rewrite via temp + rename; write `.bak`
- [x] Validate rewritten session parses before swap (`validate_session_file`)
- [x] Refuse during gateway unless `--force` — gateway holds a `flock` run-lock
  (`<workspace>/.gateway.lock`), `session compact` probes it
- [x] Audit log entry per file (`session_compact` event)
- [x] Help text: full output retained in the audit log

**Status (2026-06-27):** ✅ done. New module `src/session_maint.c`
(+`session_maint.h`); CLI `cmd_session` in `main.c`; gateway acquires the
run-lock. Note: the spec's `[path...]` is implemented as `[key...]` (session
keys are mapped to files via `sc_sanitize_filename`, matching the manager's
on-disk naming). Reads arbitrarily long lines (the manager's 64 KB `fgets` cap
would otherwise truncate the very tool outputs we compact).

### 2.4 Session prune

- [x] `smolclaw session prune [--keep N] [--yes]`
- [x] Delete sessions older than N newest by mtime (default keep 20),
  interactive `[y/N]` confirm unless `--yes`
- [ ] Optional soft-delete to trash dir — **deferred** (YAGNI; `.bak` from
  compact + audit log already cover recovery; revisit on demand)

**Status (2026-06-27):** ✅ done (`sc_session_prune_candidates` + `cmd_session`).

### 2.5 Incremental session reload (optional)

- [ ] Cache `(session, mtime, size, byte_offset)` for disk reload paths
- [ ] Resume JSONL parse from offset on append-only growth
- [ ] **Skip if** in-process append already covers all reload paths

Only implement if gateway restart / multi-process read is a measured bottleneck.

### 2.6 Provider health

**Source:** zed-patterns Task 6

> **Status (2026-06-26):** A provider-health tracker already exists in
> `src/agent_turn.c` (`provider_health_update`, `s_provider_health[]`, status
> enum `SC_PROVIDER_HEALTHY` / `RATE_LIMITED` / …). **Remaining work:** confirm
> the fallback chain consults it (skip-until-`retry_after`) and surface it in
> `smolclaw analytics` or logs. Likely verify-plus-glue, not net-new.

**Files:** `src/agent_turn.c` *(tracker exists)*, fallback selection, `src/analytics.c`

- [x] Per-provider status: HEALTHY, RATE_LIMITED, AUTH_EXPIRED, UNREACHABLE
  *(enum shipped; `AUTH_EXPIRED` was missing — **added this slice**)*
- [x] Update from HTTP responses (429/529 → RATE_LIMITED, 401 → AUTH_EXPIRED,
  timeout/0 → UNREACHABLE) *(401 mapping **added this slice**, 300 s cooldown)*
- [x] Fallback chain skips unhealthy until `retry_after` *(already wired at
  `agent_turn.c:834` via `provider_health_ok`; **locked with regression test**)*
- [x] Visible in logs — `SC_LOG_WARN` on every unhealthy transition
  *(**added this slice**)*. The in-memory tracker is process-local (gateway), so
  `smolclaw analytics` (separate process, DB-backed) cannot observe it; logs are
  the correct surface.

**Status (2026-06-27):** ✅ done. Tracker verified + `AUTH_EXPIRED`/401 mapping
and transition logging added; `sc_provider_health_reset()` exported for test
isolation. New test `test_provider_health_skips_auth_expired_fallback`
(`tests/test_agent.c`).

### 2.7 Port conflict logging

**Source:** todo.md

**Files:** `src/channels/web.c` (and shared bind helper if exists)

- [x] On bind failure, log the process holding the port — new
  `src/util/port_diag.c` (`sc_port_holder`) parses `/proc/net/tcp{,6}` for the
  LISTEN inode then scans `/proc/<pid>/fd` for the owner; falls back to an
  `ss -ltnp` hint when the PID is unresolvable
- [x] Documented `auto_port` (CONFIGURATION.md `channels.web`)

**Status (2026-06-27):** ✅ done. Wired into `web.c`'s bind-failure path; 3-case
`tests/test_port_diag.c` (binds a real ephemeral listener and asserts its own
pid is reported). Linux-only `/proc`; returns NULL elsewhere.

### 2.8 Backoff verification

**Source:** claude-code P1 #5

**Files:** `src/agent_turn.c`

- [x] Audit existing retry/fallback logic (`call_provider_with_retry`,
  `agent_turn.c`)
- [x] Exponential backoff on transient errors (0/429/502/503/529): ×2 from
  `SC_LLM_RETRY_INITIAL_MS=1000` capped at `SC_LLM_RETRY_MAX_MS=30000`,
  `SC_LLM_MAX_RETRIES=3` (`constants_network.h`). **No gap** — the spec's
  "1s/4s/16s" is illustrative; ×2 (1s/2s/4s) is correct exponential backoff.
- [x] Honor `retry_after_secs` from provider — used as the delay (capped 300 s);
  header parser caps the raw value at 3600 s (`provider_common.c`).
- [x] Test added: `test_transient_error_retries_then_succeeds` (503 → retry →
  200).

**Status (2026-06-27):** ✅ done (audit confirms correct; regression test added).

### 2.9 Cron expression parser

**Source:** `src/cron/service.c` — `"cron"` schedule kind currently logs a warning and is disabled.

**Files:** `src/cron/service.c`, `src/cron/jobs.c` (or new `src/cron/cron_parse.c`), `tests/test_cron.c`

- [x] Parse standard 5-field cron expressions (`min hour dom month dow`) —
  `*`, ranges, lists, `*/step`; dow `0-6`/`7`; Vixie dom/dow OR semantics
- [x] Compute `next_run` from expression + timezone (`sc_cron_next_after`,
  per-job `tz` via scoped `TZ`); reuses existing job storage
- [x] Re-enable `"kind": "cron"` in `compute_next_run`; documented in
  `docs/CONFIGURATION.md`; exposed via the `cron` tool (`schedule_type:"cron"`,
  `expr`, `tz`) so the agent can create them
- [x] Unit tests: daily, weekly, `*/15`, Sunday-as-7, invalid expressions,
  impossible date (Feb 31 → no run), and service-level enable check
- [x] `"every"` / `"at"` behavior unchanged

**Status (2026-06-27):** ✅ done. New `src/cron/cron_parse.c` (+`.h`); wired into
`src/cron/service.c` and `src/tools/cron.c`. Gated behind `SC_ENABLE_CRON`
(absent from the minimal profile, so no minimal-size impact).

**Hermes parity:** `cronjob` tool schedule formats (subset — no shell-only cron tasks).

### 2.10 Gateway slash commands (MVP)

**Source:** Hermes messaging gateway chat commands (subset).

**Files:** `src/channels/base.c` or shared `src/slash.c`, channel adapters, `src/agent_turn.c`

**MVP commands (ship in this task):**

| Command | Behavior |
|---------|----------|
| `/reset` or `/new` | Start fresh session for this chat |
| `/model [alias]` | Show or change model for this session |
| `/compress` | Trigger manual session summarization/compaction |
| `/status` | Session info: model, message count, token usage if available |
| `/help` | List available slash commands |

**Explicitly defer to Phase 5:** `/background`, `/voice`, `/insights`, `/reasoning`, `/rollback`,
`/approve`/`/deny` (use existing tool confirm flow).

- [x] Detect leading `/` in inbound gateway messages before agent turn
  (`gateway_process_message`) **and** in the interactive CLI REPL
- [x] Dispatch without LLM call; reply via same channel
- [ ] Per-channel allowlist config — **deferred to 3.7** (admin tier); MVP
  exposes the same five commands on every channel
- [x] Tests: `tests/test_slash.c` exercises `/help`, `/status`, `/reset`,
  `/new`, `/model` (show + alias + literal), `/compress`, and pass-through for
  non-/ and unknown-/ input

**Status (2026-06-27):** ✅ done. New `src/slash.c` (+`slash.h`):
`sc_slash_dispatch()` returns 1 (handled, with a malloc'd reply) or 0 (not a
recognized command → normal agent turn — so legitimate slash-prefixed content
like `/etc/hosts` still reaches the LLM). Added `sc_session_reset()` to
session.c for `/reset`. `/compress` force-summarizes by briefly lowering the
threshold (the model is strdup-copied into the summarize worker, so no race
with `/model`). `/model <alias>` resolves config aliases and swaps the
gateway's active model. Wired into both the gateway loop and the CLI REPL;
audit entry per command. **Note:** the model switch is gateway-global (not
per-session) and stays on the current provider — true per-session / cross-
provider switching is out of MVP scope. Live REPL/gateway smoke not run here
(offline env has no LLM credentials for agent startup); logic covered by unit
tests.

### 2.11 Skills format documentation

**Source:** audit finding — skills ship in code but README/CONFIGURATION lack operator docs.

**Files:** `README.md`, `docs/CONFIGURATION.md` (no code unless examples need fixtures)

- [x] Document `SKILL.md` frontmatter — verified against `src/skill.c`: `name`,
  `description`, `when-to-use`, `arguments`, `allowed-tools`, `model`,
  `context` (inline/fork), `user-invocable`, `disable-model-invocation`
- [x] Document search paths: `~/.smolclaw/skills/`, `{workspace}/.claude/skills/`
  (user precedence; `<name>/SKILL.md` or flat `<name>.md`)
- [x] Document slash-command (`/skill-name`) and `skill` tool invocation, incl.
  the gateway-reserved slash names that shadow skills
- [x] Note [agentskills.io](https://agentskills.io) compatibility (no Skills Hub)
- [x] Cross-link `docs/development/using-grok-implement-skill.md`

**Status (2026-06-27):** ✅ done (docs-only). Skills sections added to
`README.md` (### Skills) and `docs/CONFIGURATION.md`; README command list
updated with `session` (slice 2). All fields/paths verified against
`src/skill.c` + `src/agent.c` rather than assumed.

### 2.12 MCP integration cookbook (Tier 2 kickoff)

**Source:** Hermes "Use MCP with Hermes" — smolclaw closes browser/HA/media gaps via MCP, not in-process.

**Files:** new `docs/integrations/mcp-cookbook.md` (authoritative); link from README

- [ ] Document smolclaw MCP client config pattern (`mcp.servers` in config.json)
- [ ] **Browser automation** — example Playwright MCP server; Landlock binary path resolution
- [ ] **Home Assistant** — example MCP server or community reference
- [ ] **Media (image/TTS)** — delegate to MCP until xAI OAuth Phase 2 wrappers (Phase 4)
- [ ] Smoke-test recipe: one MCP server + `smolclaw gateway` end-to-end
- [ ] Tier 2 rule: zero smolclaw binary cost; optional thin native wrapper only after ≥3 fleet deployments

### 2.13 Mixture of Agents (MoA-lite)

**Authoritative spec:** [`../mixture-of-agents.md`](../mixture-of-agents.md)  
**Hermes reference:** [Mixture of Agents](https://hermes-agent.nousresearch.com/docs/user-guide/features/mixture-of-agents)

**New files:** `src/providers/moa.c`, `src/providers/moa.h`, `tests/test_moa.c`

**Modified:** `src/providers/factory.c`, `src/config.{c,h}`, `src/agent_turn.c`, `src/agent.c`,
`src/slash.c`, `CMakeLists.txt`, `Kconfig`, `docs/CONFIGURATION.md`, `README.md`

Deliverables:

- [x] Virtual `moa` provider with named presets in `config.json` (`reference_models` + `aggregator`)
- [x] Per-iteration loop: trimmed reference fan-out (no tools) → inject on user-tail → aggregator with tools
- [x] Parallel reference calls (cap 3, pthread per ref); reference failure injected as error text, turn continues
- [x] `local_only` preset policy — Ollama/vLLM/loopback+RFC1918 custom only; reject cloud slots at load
- [x] `enabled: false` on preset → aggregator alone (MoA off for that preset)
- [x] Block recursive MoA (aggregator provider `moa` → preset rejected)
- [~] Cost/audit — aggregator usage flows through the normal turn accounting; per-reference token
  sums **deferred** (references are fire-and-forget threads; v2 can aggregate their usage)
- [x] `/model <preset>` selects a preset (the moa provider resolves the preset by the turn's model
  arg — **no alias table needed**, since `use_model = agent->model`); gated hint in `slash.c`
- [x] Kconfig `SC_ENABLE_MOA` — **default n**; FEATURE_SYMS + cmake override + defconfig comment (KC-1)
- [x] `tests/test_moa.c` — 9 cases: reference_view, injection (+synthetic tail), fan-out, ref-failure,
  `enabled:false`, `local_only` reject, recursive reject, `is_local`

**Status (2026-06-27):** ✅ done. New `src/providers/moa.c` (+`moa.h`); config
parse in `config.{c,h}`; factory routes `provider:"moa"` / `model:"moa/<preset>"`.
**Deviation from spec:** preset switching uses the moa provider's own
preset-by-`model` lookup instead of registering `moa:<preset>` alias-table
entries (simpler, same `/model` UX — `use_model` is already `agent->model`).
Aggregator inherits the turn's options (preset `aggregator_temperature`/
`aggregator_max_tokens` override when set). Slots are resolved eagerly at
provider construction via `sc_provider_create_for_model` so the provider owns
its handles (no `cfg` lifetime dependency). Live integration (real
Ollama+cloud) is the manual 🟠 acceptance; mock tests cover the logic.

**Smol contract:** No dashboard UI; no `/moa` one-shot required for MVP; distinct from
fallback (failure) and Phase 5 OpenRouter `/compare` (rejected). Presets may mix local
(`ollama`, `vllm`) and cloud providers when `local_only` is false.

**Example presets (documented, not hard-coded):**

| Preset | References | Aggregator |
|--------|------------|------------|
| `hybrid` | `ollama/*` + `openrouter/*` | `anthropic/*` |
| `airgap` | `ollama/*` | `ollama/*` (`local_only: true`) |

---

## 3. Exit Criteria

- [ ] xAI OAuth: manual login + chat via `provider: xai-oauth` works
- [ ] Session compact/prune tested on tree-format sessions
- [ ] Provider health skips rate-limited backend in fallback test
- [ ] ctest green including `test_xai_oauth`
- [ ] README + config docs updated for auth subcommand
- [ ] Cron `"kind": "cron"` jobs fire on schedule in integration test
- [ ] Gateway slash MVP works on at least CLI + one async channel (Telegram or Discord)
- [ ] Skills section present in README and CONFIGURATION
- [ ] `docs/integrations/mcp-cookbook.md` published with ≥1 tested MCP example
- [ ] MoA: `tests/test_moa.c` green; preset with mock references + aggregator passes one iteration
- [ ] MoA: `local_only` airgap preset rejects cloud provider at config load

---

## 4. Risks

| Risk                         | Mitigation                                      |
|------------------------------|-------------------------------------------------|
| OAuth token leakage in logs  | Redaction tests                                 |
| Session compact breaks tree  | Parse validation before swap; `.bak`            |
| Loopback blocked on some VPS | Document `--no-browser`; user opens URL locally |
| Compact during active turn   | Session lock + `--force` gate                   |
| MoA cost / latency blow-up   | Default off; cap 3 references; document multiplier |
| Cloud egress on "local" task | `local_only` preset + CONFIGURATION warnings  |

---

## 5. Suggested PR order

1. `feat: provider health tracking for fallback chain`
2. `feat: smolclaw session compact and prune`
3. `feat: gateway slash commands MVP (/reset, /model, /compress, /status, /help)`
4. `feat: cron expression parser for scheduled jobs`
5. `feat: xAI Grok OAuth provider and auth subcommand`
6. `fix: port conflict diagnostics on web channel bind`
7. `docs: skills format + MCP integration cookbook`
8. `feat: mixture-of-agents virtual provider (MoA-lite)` — after 2.6 provider health + `/model` (2.10)

---

## 6. Slice log

- **Slice 1 — `task/2.6-provider-reliability` (tasks 2.6 + 2.8)** — 2026-06-27.
  Provider-health `AUTH_EXPIRED`/401 mapping + unhealthy-transition logging +
  `sc_provider_health_reset()`; backoff audited (no gap). 2 new tests.
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest
  --test-dir build` 43/43 green; `check_size_budget.sh` minimal-dynamic 257 KB ≤
  1024 KB; no new Kconfig flag (KC-1 N/A).
- **Slice 2 — `task/2.3-session-compact-prune` (tasks 2.3 + 2.4)** — 2026-06-27.
  New `src/session_maint.c` (compact/prune + gateway run-lock) + `cmd_session`
  CLI + help; gateway acquires the `flock` run-lock. 5 new tests
  (`tests/test_session_maint.c`). Verified end-to-end (20 KB → 3.3 KB compact,
  `.bak` retained, prune keeps newest N, audit entries written).
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest` 44/44;
  `check_size_budget.sh` minimal-dynamic 261 KB ≤ 1024 KB; `check_claude_md.sh`
  clean; no new Kconfig flag (KC-1 N/A).
- **Slice 3 — `task/2.10-gateway-slash-mvp` (task 2.10)** — 2026-06-27.
  New `src/slash.c` (`/help`, `/status`, `/reset`+`/new`, `/model`, `/compress`)
  + `sc_session_reset()` in session.c; wired into the gateway loop and CLI REPL.
  5-case `tests/test_slash.c`.
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest` 45/45;
  `check_size_budget.sh` minimal-dynamic 269 KB ≤ 1024 KB; `check_claude_md.sh`
  clean; no new Kconfig flag (KC-1 N/A).
- **Slice 4 — `task/2.9-cron-parser` (task 2.9)** — 2026-06-27.
  New `src/cron/cron_parse.c` (5-field parser + `next_after` with tz); re-enabled
  `"cron"` in `compute_next_run`; extended the `cron` tool with
  `schedule_type:"cron"`/`expr`/`tz`; documented in CONFIGURATION.md. 7 new cron
  tests. Gated by `SC_ENABLE_CRON` (not in minimal).
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest` 45/45;
  `check_size_budget.sh` minimal-dynamic 269 KB ≤ 1024 KB (unchanged — cron not
  in minimal); `check_claude_md.sh` clean; existing `SC_ENABLE_CRON` flag (KC-1
  N/A).
- **Slice 5 — `task/2.7-port-conflict` (task 2.7)** — 2026-06-27.
  New `src/util/port_diag.c` (`sc_port_holder` via `/proc`); web.c bind-failure
  log now names the holding process; `auto_port` documented. 3-case
  `tests/test_port_diag.c`.
  **Verification gates:** Release build clean (KC-2 `implicit`=0, no new
  warnings); `ctest` 46/46; `check_size_budget.sh` minimal-dynamic 269 KB ≤
  1024 KB; `check_claude_md.sh` clean; no new Kconfig flag (KC-1 N/A).
- **Slice 6 — `task/2.11-skills-docs` (task 2.11)** — 2026-06-27. Docs-only.
  Skills sections in `README.md` + `docs/CONFIGURATION.md` (frontmatter, search
  paths, slash + `skill`-tool invocation, agentskills.io note); README commands
  updated with `session`. Fields verified against `src/skill.c`/`src/agent.c`.
  **Verification gates:** docs-only (no code changed → build/ctest/size
  unchanged from slice 5); `check_claude_md.sh` clean; cross-link verified.
- **Slice 7 — `task/2.13-moa-lite` (task 2.13)** — 2026-06-27. New
  `src/providers/moa.c` (+`moa.h`): virtual `moa` provider — parallel reference
  fan-out → tail injection → aggregator. Config parse (`config.{c,h}`), factory
  routing, `Kconfig SC_ENABLE_MOA` (default n) + FEATURE_SYMS/cmake/defconfig,
  `/model` hint, CONFIGURATION.md + README. 9-case `tests/test_moa.c`.
  **Verification gates:** Release+`-DSC_ENABLE_MOA=ON` build clean (KC-2
  `implicit`=0); `ctest` 47/47; `check_size_budget.sh` minimal-dynamic 269 KB ≤
  1024 KB (MoA off in minimal — `SC_ENABLE_MOA 0`); `check_claude_md.sh` clean;
  KC-1 satisfied (FEATURE_SYMS + cmake override + defconfig comment).

---

**Next phase:** [Phase 3 — Optional Surface Area](phase-3-optional-surface-area.md)
