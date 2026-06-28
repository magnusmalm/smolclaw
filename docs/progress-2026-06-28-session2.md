# Progress — 2026-06-28 (session 2: autonomous backlog completed)

## Summary

Continued the master-plan roadmap from `1aa179a` and **exhausted the autonomous
READY backlog across Phases 0–4** (plus the Phase 2 OAuth leftovers 2.1/2.2).
Five slices landed, each slice-by-slice: one task → one branch → gated by clean
build (KC-2), `ctest`, and the ≤1024 KB minimal size budget → ff-merge to
`master` → push to Gitea only → prune. HEAD is `911e07b`. `ctest` grew 50 → **52**.

Everything that remains is gated on an external system or human acceptance
(live provider/key, SuperGrok login, signal-cli, MCP server, KVM host) — there
is no autonomous-READY work left in Phases 0–4. Phase 5 stays do-not-build.

## Changes

- **4.1 arena allocator** (`8229946`, docs-only) — **closed as
  rejected-after-recon.** The allocator + per-turn reset already ship; the
  remaining "convert provider SSE/response parsing to the arena" deliverable is
  unsafe: parsed `sc_llm_response_t`/`sc_llm_message_t` is long-lived (returned,
  stored in cross-turn session history, freed individually with `free()`) while
  the arena resets every turn — arena-backing it would corrupt the heap, and the
  spec's own "long-lived stays on heap" rules out ~all 9 sites. Mirrors the
  recon-first outcomes of 4.10 (measurement) and 4.4 (config gate). **Closes
  Phase 4.**

- **3.1 Signal acceptance runbook** (`ca8ab16`, docs-only) — added
  `docs/channels/signal-acceptance.md` (the manual smoke-test procedure for the
  3.1 human gate: exact JSON-RPC wire protocol the polling loop expects, daemon
  setup, raw-curl shape verification, pass criteria, mismatch-fix pointers).
  Fixed stale "not yet available" / "(Planned)" wording in
  `docs/channels/signal.md` now that the channel ships.

- **4.3 Anthropic prompt caching** (`67e70ef`) — made caching **actually hit.**
  Recon found `cache_control: ephemeral` already emitted in
  `providers/claude.c` (first system block + last tool, Anthropic-only by
  construction) but silently non-functional: `context.c` built one system block
  with a minute-resolution timestamp at the top, and caching is a prefix match,
  so the cache invalidated every minute. Split the system prompt into a **static**
  block (`build_static_system`: identity sans-timestamp + bootstrap + skills +
  deferred tools + per-session info) and a **dynamic** block
  (`build_dynamic_system`: timestamp + memory; summary/scratchpad/action-log
  appended in `sc_context_build_messages`), emitted as two `sc_msg_system`
  messages `[static, dynamic]`. The existing "mark first system block" logic now
  caches the static prefix; the dynamic block follows uncached — **no provider
  change.** Public `sc_context_build_system_prompt` still returns the full prompt
  (4.7 `context` cmd + tests). Runtime config gate dropped (owner scope). New
  `test_prompt_cache_static_dynamic_split`; `test_session_isolation` mock now
  concatenates all leading system blocks. 🟠 Live `cache_read_input_tokens > 0`
  verification = Anthropic-key gate.

- **4.6 `doctor --local`** (`e7f01bf`) — live provider capability probe on top of
  the existing static `doctor`. New `src/doctor_local.{c,h}`:
  `smolclaw doctor --local [--model M]` probes basic chat, streaming, tool calls,
  and inline-JSON output, caching the report at
  `{SMOLCLAW_HOME}/capabilities/<model>.json`. Pure helpers
  (`to_json`/`from_json`/`cache_path`/`response_is_json`) + a mockable
  `sc_doctor_probe_provider(provider, model, report)` are split from the live
  `sc_provider_create_for_model` + filesystem wiring, so the probe is unit-tested
  with a mock provider and no network (tri-state `SC_CAP_YES`/`NO`/`SKIPPED`).
  Lives in `smolclaw_lib` so the binary and test both link it. The spec's "models
  list" probe was omitted (no vtable method; single-model target). 🟠 Live probe
  against a real provider = human gate; degrades gracefully without one.

- **2.1/2.2 xAI Grok OAuth** (`911e07b`) — full PKCE OAuth MVP behind
  `SC_ENABLE_XAI_OAUTH` (default n). New `src/util/xai_oauth.{c,h}`: PKCE
  (sha256 + base64url), JWT `exp` decode + refresh decision (120s skew),
  authorize-URL builder, token-endpoint origin validation (https + `*.x.ai`),
  `auth.json` store (0600, atomic `.tmp.$pid` + rename), discovery/exchange/
  refresh (endpoint as a param → mock-testable), runtime resolver
  `sc_xai_oauth_ensure_fresh_token()` wired into the factory for
  `xai-oauth`/`grok-oauth`/`grok-sub` (+ `xai-oauth/<model>` prefix), interactive
  loopback `evhttp` login (`127.0.0.1:0` `/callback` + state check + browser-open
  with SSH auto-detection + `--no-browser`), and
  `smolclaw auth login|status|logout|refresh xai`. base64url added to
  `util/base64.c`. KC-1 wired. `test_xai_oauth.c` (12 cases incl. mock_http
  discovery/refresh/invalid_grant). 🟠 Live SuperGrok login = human gate.

## Validation

- Clean Release builds (feature flags on where relevant): **KC-2 `implicit`=0,
  no errors** for each slice.
- `ctest`: **52/52** at session end (`+test_prompt_cache_static_dynamic_split`,
  `+test_doctor_local`, `+test_xai_oauth`; `test_session_isolation` mock updated).
- Size budget: minimal-dynamic held at **285 KB** stripped ≤ 1024 KB across all
  slices (4.6 always-compiled but tiny; 2.1/2.2 default-off).
- `check_claude_md.sh`: clean. KC-1 satisfied for the one new flag
  (`SC_ENABLE_XAI_OAUTH`) — FEATURE_SYMS + cmake override + defconfig.minimal.

## Recon-first / smoke-test lessons reinforced

- **Recon keeps changing the task.** 4.1's remaining work was unsafe (rejected);
  4.3's `cache_control` was shipped-but-dead (a top-of-prompt timestamp killed
  the prefix match); 4.6's `doctor` already existed (extended, not rebuilt); and
  the spec's `SC_ENABLE_XAI` Kconfig flag doesn't exist (xAI is always-compiled).
- **Smoke-test new CLI subcommands.** A `doctor --local`/`auth status` smoke run
  caught a double-free in the xAI OAuth store: `load`/`from_json` didn't zero
  `*out` on the failure path, so callers freed garbage — fixed by memset-at-entry.
- **Caching is a prefix match.** Any volatile byte (a minute-resolution
  timestamp, a changing memory-capacity %) before the breakpoint silently
  defeats it — consult the claude-api caching reference before touching
  `cache_control`.

## Remaining work / next steps

The autonomous-READY backlog (Phases 0–4) is **complete.** What's left:

- **Live-verify only (code shipped, needs an external system / human):**
  - 2.1/2.2 xAI OAuth — live SuperGrok login (also re-verify the 2026-05 client_id/
    endpoints/scopes, which are unverifiable offline)
  - 4.3 Anthropic prompt caching — Anthropic key (`cache_read_input_tokens > 0`)
  - 4.6 `doctor --local` — live provider (Ollama/vLLM or a real key)
  - 3.1 Signal — live `signal-cli` (runbook: `docs/channels/signal-acceptance.md`)
  - 4.13 post-turn memory review — live LLM
  - 1.5 adaptive tools / 1.8 prompt warmup — live Ollama/vLLM benchmarks
- **Not implemented (weak autonomous fit; deps are external):**
  - 2.12 MCP cookbook — a doc, but validating the recipe needs ≥1 real MCP server
  - 4.9 microsandbox exec — ops-heavy (KVM host + `microsandbox-server`)
- **Phase 5** — do-not-build parking lot.
