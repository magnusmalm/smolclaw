# Phase 2: Operator & Provider UX

**Status**: Not started  
**Master plan**: [`../master-plan.md`](../master-plan.md)  
**Prerequisite**: [Phase 1](phase-1-context-efficiency.md) complete  
**Goal**: Auth for Grok subscribers, session maintenance CLI, provider reliability helpers.  
**LOC budget**: ~900–1,400  
**Binary target**: +≤80 KB when xAI OAuth enabled; +~15 KB for session CLI without OAuth

---

## 1. Scope

| # | Task | Source | LOC | Binary | Gate |
|---|------|--------|-----|--------|------|
| 2.1 | xAI Grok OAuth provider | xai-grok-oauth.md | <650 | +40–60 KB | `SC_ENABLE_XAI_OAUTH` |
| 2.2 | `smolclaw auth` subcommand | xai-grok-oauth.md | (in 2.1) | — | same |
| 2.3 | `smolclaw session compact` | lazyagent #2 | 150–250 | ~5 KB | CLI |
| 2.4 | `smolclaw session prune` | lazyagent #3 | 80–150 | ~5 KB | CLI |
| 2.5 | Incremental session reload (optional) | lazyagent #1 | 100–200 | ~5 KB | if needed |
| 2.6 | Provider health tracking | zed-patterns T6 | 80–150 | ~5 KB | always |
| 2.7 | Port conflict diagnostics | todo.md | 30–50 | ~0 | always |
| 2.8 | Verify exponential backoff + fallback | claude-code P1 #5 | 20–50 | ~0 | always |

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
- [ ] Kconfig `SC_ENABLE_XAI_OAUTH` (default y or tied to xAI provider)
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

**Files:** `src/providers/factory.c`, `src/analytics.c` or `src/main.c`

- [ ] Per-provider status: HEALTHY, RATE_LIMITED, AUTH_EXPIRED, UNREACHABLE
- [ ] Update from HTTP responses (429, 401, timeouts)
- [ ] Fallback chain skips unhealthy until `retry_after`
- [ ] Visible in `smolclaw analytics` or logs

### 2.7 Port conflict logging

**Source:** todo.md

**Files:** `src/channels/web.c` (and shared bind helper if exists)

- [ ] On bind failure, log process holding port (parse `/proc/net/tcp` or `ss` equivalent)
- [ ] Document that `auto_port` already exists

### 2.8 Backoff verification

**Source:** claude-code P1 #5

**Files:** `src/agent_turn.c`

- [ ] Audit existing retry/fallback logic
- [ ] Ensure exponential backoff (1s, 4s, 16s) on 429/529
- [ ] Honor `retry_after_secs` from provider
- [ ] Add tests if gaps found

---

## 3. Exit Criteria

- [ ] xAI OAuth: manual login + chat via `provider: xai-oauth` works
- [ ] Session compact/prune tested on tree-format sessions
- [ ] Provider health skips rate-limited backend in fallback test
- [ ] ctest green including `test_xai_oauth`
- [ ] README + config docs updated for auth subcommand

---

## 4. Risks

| Risk | Mitigation |
|------|------------|
| OAuth token leakage in logs | Redaction tests |
| Session compact breaks tree | Parse validation before swap; `.bak` |
| Loopback blocked on some VPS | Document `--no-browser`; user opens URL locally |
| Compact during active turn | Session lock + `--force` gate |

---

## 5. Suggested PR order

1. `feat: provider health tracking for fallback chain`
2. `feat: smolclaw session compact and prune`
3. `feat: xAI Grok OAuth provider and auth subcommand`
4. `fix: port conflict diagnostics on web channel bind`

---

**Next phase:** [Phase 3 — Optional Surface Area](phase-3-optional-surface-area.md)
