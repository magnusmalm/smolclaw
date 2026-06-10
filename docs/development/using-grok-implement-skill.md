# Using the Grok `/implement` Skill in smolclaw

This document captures the recommended workflow for using Grok's `/implement` skill (the `implement` skill from `~/.grok/bundled/skills/implement/`) to turn completed design documents into production code.

The `/implement` skill runs a full `implement → review → fix` loop with specialized subagents (general reviewer + automatic specialists for security, tests, and plan alignment) until zero issues of any severity remain. It also maintains a workspace-scoped memory of recurring mistakes to brief future runs.

---

## Why Use a Structured Prompt?

Free-form requests like "implement the Signal channel" often produce incomplete or inconsistent results. A high-quality prompt:

- Treats the design document as the **single source of truth**
- Names a **concrete reference implementation** for style, structure, and testing patterns
- Explicitly calls out **non-negotiable architectural contracts** (security model, base helpers, Kconfig/ CMake patterns, etc.)
- Scopes the work to a **shippable increment** (MVP / specific phase)
- Lists **exact deliverables** so nothing is forgotten (new files, config wiring, tests, user docs)

This pattern has proven effective for complex, security-sensitive features in smolclaw.

---

## Worked Example: Signal Channel (MVP)

The Signal channel (`docs/design/signal-channel.md`) was the first major feature designed with the explicit intent of being driven by the Grok `/implement` skill.

### The Prompt

```text
/implement --effort 3 Add Signal channel (MVP) via external signal-cli daemon as specified in docs/design/signal-channel.md

Primary reference: docs/design/signal-channel.md (the complete authoritative design, including architecture, security model, config shape, identifier normalization rules, and phased checklist).

Secondary reference for style and patterns: the recently completed X (Twitter) channel implementation in src/channels/x.c + src/channels/x.h + tests/test_x.c. Use the same modern structure, polling thread pattern, libcurl + cJSON usage, error handling, and test approach with tests/mock_http.h.

Also study:
- src/channels/base.h and base.c (the vtable and security helpers: sc_channel_init_security, sc_channel_is_allowed, sc_channel_handle_message, pairing store integration)
- src/channels/manager.c (how channels are conditionally compiled in, initialized, and wired with quarantine_check under SC_STRICT_SECURITY)
- src/config.h and src/config.c (how other channel configs are defined, parsed from JSON, and given env var overrides)
- CMakeLists.txt and Kconfig (the SC_ENABLE_* pattern for optional channels)
- Existing simple channel tests (test_telegram.c or test_x.c) for the expected test structure and mock usage

Scope for this run: **Phase 0 + Phase 1 (MVP)** from the design doc only. Deliver a fully functional, text-only, polling-based Signal channel (DMs + groups) that passes the security model exactly. Do not implement SSE streaming, attachments, or Phase 2/3 items.

Critical requirements that must be satisfied:
- Full integration with the existing dm_policy / allow_from / pairing / SC_STRICT_SECURITY model (no reimplementation of pairing logic).
- Strong preference for `uuid:...` sender identifiers when `sourceUuid` is present in envelopes from the daemon; both phone numbers (`+...`) and `uuid:...` forms must work correctly in allow_from lists and the pairing flow.
- JSON-RPC client over HTTP to a user-provided signal-cli daemon (or bbernhard container). Use the documented endpoint layout and `receive` / `send` / `subscribeReceive` methods.
- Proper validation and defensive handling of all data coming from the external daemon.
- Polling MVP (no real-time SSE yet).
- Text messages only.
- Group support via the existing `group_trigger` mechanism.

Deliverables for this implementation:
- Kconfig entry `SC_ENABLE_SIGNAL` (with appropriate help text and `select NEED_PTHREADS`).
- Config struct `sc_signal_config_t` in config.h + parsing + env overrides in config.c (following the exact shape sketched in the design doc: account, http_host/port/url, proxy, group_trigger, etc.).
- New files: src/channels/signal.c + signal.h (the channel implementation, ~550-700 LOC target).
- Wiring in src/channels/manager.c (under `#if SC_ENABLE_SIGNAL`).
- CMakeLists.txt updates to include the new source when the Kconfig symbol is enabled.
- Complete test file: tests/test_signal.c using the mock_http server to cover the cases listed in the design (DM from phone, DM from UUID, group handling, pairing flow, allow_from for both ID forms, error/backoff, send to DM and group, etc.).
- Update the placeholder user documentation in docs/channels/signal.md to be accurate for the implemented MVP (setup instructions for both native signal-cli daemon and Docker modes, pairing examples, security warnings, config reference).
- Any necessary updates to README.md feature table or Kconfig summary.

Security & testing bar (non-negotiable):
- The implementation must survive the same strict security quarantine checks as X, Web, etc.
- Primary tests must be deterministic via the existing libevent-based mock_http infrastructure (modeled directly on test_x.c).
- Include at least one real-daemon smoke test note in the test file or a separate RUN_MANUAL.md-style comment.
- All inbound data from the daemon must be treated as untrusted.

Use the existing common infrastructure everywhere possible (sc_curl_init, bus, rate limiter, pairing store, etc.). Follow the "smol" philosophy and the exact security posture described in the design document.

When done, the channel should be usable with a config snippet like:
"signal": {
  "enabled": true,
  "account": "+15551234567",
  "http_url": "http://127.0.0.1:7583/api/v1/rpc",
  "dm_policy": "pairing",
  "group_trigger": "!smol"
}

Write a clear implementation summary at the end.
```

### Why This Prompt Works Well

- **Design doc is the authority** — the agent is told to treat `docs/design/signal-channel.md` as the complete spec.
- **Reference implementation** — X channel was chosen because it is the most recent polling-based REST channel and has excellent tests using `mock_http`.
- **Explicit contracts** — base security helpers, strict mode quarantine, identifier normalization (`uuid:...` preference), and validation rules are called out so they are not reinvented.
- **Clear scope and deliverables** — prevents both under- and over-implementation.
- **Effort level** — `--effort 3` provides good coverage (general + specialists) for a feature that touches the security model and requires thorough tests.

---

## General Guidance for New Features

When a design document is marked "ready for implementation":

1. **Choose the right effort level**
   - 2: Most day-to-day features
   - 3: Features with security implications or complex integration (recommended starting point for new channels, auth, etc.)
   - 4–5: Critical or highly regulated work

2. **Always name a reference implementation**
   - Recent, high-quality code in the same domain (e.g., X for new channels, another tool for new tool families).

3. **Explicitly list the security / architectural invariants**
   - For channels: `sc_channel_init_security`, pairing, `quarantine_check`, `dm_policy` handling.
   - For tools: sandboxing, input validation, `sc_tool_*` helpers.

4. **Include documentation updates**
   - Almost every feature has a corresponding `docs/channels/*.md` or `docs/tools/*.md` stub that should be completed as part of the same run.

5. **Scope to a shippable slice**
   - Prefer "Phase 0 + Phase 1 (MVP)" over "the entire design" when the design is multi-phase.

---

## Related Files

- Design documents: `docs/design/`
- Channel user guides: `docs/channels/`
- Claude Code workflow notes: `docs/claude-code-improvements.md`
- Project CLAUDE.md (inherits from `~/.claude/CLAUDE.md`)

---

*Document created 2026-05 from a real `/implement` prompt developed for the Signal channel feature.*
