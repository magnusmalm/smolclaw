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

- [ ] Subcommand: `smolclaw session compact [--force] [path...]`
- [ ] Truncate large tool stdout / web_fetch bodies in session JSON
- [ ] Keep head + tail + `...[truncated N bytes]...` marker
- [ ] Atomic rewrite via temp + rename; write `.bak`
- [ ] Validate rewritten session parses before swap
- [ ] Refuse active session without lock; refuse during gateway unless `--force`
- [ ] Audit log entry per file
- [ ] Help text: audit log retains full outputs

### 2.4 Session prune

- [ ] `smolclaw session prune [--keep N] [--yes]`
- [ ] Delete sessions older than N newest (default keep 20)
- [ ] Optional soft-delete to trash dir (config)

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

- [ ] On bind failure, log process holding port (parse `/proc/net/tcp` or `ss` equivalent)
- [ ] Document that `auto_port` already exists

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

- [ ] Parse standard 5-field cron expressions (`min hour dom month dow`)
- [ ] Compute `next_run` from expression + timezone (reuse existing job storage)
- [ ] Re-enable `"kind": "cron"` in config; document in `docs/CONFIGURATION.md`
- [ ] Unit tests: daily, weekly, `*/15` intervals, invalid expression errors
- [ ] Keep existing `"kind": "every"` and `"kind": "at"` behavior unchanged (the
  three schedule kinds in `src/cron/service.h` are `"at"`, `"every"`, `"cron"` — there is no `"interval"`)

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

- [ ] Detect leading `/` in inbound gateway messages before agent turn
- [ ] Dispatch without LLM call; reply via same channel
- [ ] Per-channel allowlist config (optional); admins = all commands (future 3.7 tier)
- [ ] Tests: mock channel receives `/reset`, `/model`, `/help` responses

### 2.11 Skills format documentation

**Source:** audit finding — skills ship in code but README/CONFIGURATION lack operator docs.

**Files:** `README.md`, `docs/CONFIGURATION.md` (no code unless examples need fixtures)

- [ ] Document `SKILL.md` frontmatter (name, description, optional model/tool overrides)
- [ ] Document search paths: `~/.smolclaw/skills/`, `{workspace}/.claude/skills/`
- [ ] Document slash-command invocation (`/skill-name`) and `skill` tool
- [ ] Note [agentskills.io](https://agentskills.io) compatibility goal (no Skills Hub in core)
- [ ] Cross-link `docs/development/using-grok-implement-skill.md`

### 2.12 MCP integration cookbook (Tier 2 kickoff)

**Source:** Hermes "Use MCP with Hermes" — smolclaw closes browser/HA/media gaps via MCP, not in-process.

**Files:** new `docs/integrations/mcp-cookbook.md` (authoritative); link from README

- [ ] Document smolclaw MCP client config pattern (`mcp.servers` in config.json)
- [ ] **Browser automation** — example Playwright MCP server; Landlock binary path resolution
- [ ] **Home Assistant** — example MCP server or community reference
- [ ] **Media (image/TTS)** — delegate to MCP until xAI OAuth Phase 2 wrappers (Phase 4)
- [ ] Smoke-test recipe: one MCP server + `smolclaw gateway` end-to-end
- [ ] Tier 2 rule: zero smolclaw binary cost; optional thin native wrapper only after ≥3 fleet deployments

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

---

## 4. Risks

| Risk                         | Mitigation                                      |
|------------------------------|-------------------------------------------------|
| OAuth token leakage in logs  | Redaction tests                                 |
| Session compact breaks tree  | Parse validation before swap; `.bak`            |
| Loopback blocked on some VPS | Document `--no-browser`; user opens URL locally |
| Compact during active turn   | Session lock + `--force` gate                   |

---

## 5. Suggested PR order

1. `feat: provider health tracking for fallback chain`
2. `feat: smolclaw session compact and prune`
3. `feat: gateway slash commands MVP (/reset, /model, /compress, /status, /help)`
4. `feat: cron expression parser for scheduled jobs`
5. `feat: xAI Grok OAuth provider and auth subcommand`
6. `fix: port conflict diagnostics on web channel bind`
7. `docs: skills format + MCP integration cookbook`

---

## 6. Slice log

- **Slice 1 — `task/2.6-provider-reliability` (tasks 2.6 + 2.8)** — 2026-06-27.
  Provider-health `AUTH_EXPIRED`/401 mapping + unhealthy-transition logging +
  `sc_provider_health_reset()`; backoff audited (no gap). 2 new tests.
  **Verification gates:** Release build clean (KC-2 `implicit`=0); `ctest
  --test-dir build` 43/43 green; `check_size_budget.sh` minimal-dynamic 257 KB ≤
  1024 KB; no new Kconfig flag (KC-1 N/A).

---

**Next phase:** [Phase 3 — Optional Surface Area](phase-3-optional-surface-area.md)
