# Design: Signal Channel for smolclaw

**Status**: Design Complete — Implementation Not Started  
**Author**: Planning session (2026)  
**Last Updated**: 2026-05  
**Related**: todo.md, SECURITY.md, channels/base.h, src/channels/manager.c

---

## 1. Summary

This document describes the design for adding a **Signal** communication channel to smolclaw, allowing users to interact with the agent directly via Signal (DMs and groups).

smolclaw will **not** implement the Signal Protocol itself. Instead, it will communicate with an externally managed `signal-cli` daemon (or the `bbernhard/signal-cli-rest-api` Docker container) over its HTTP JSON-RPC API.

The design prioritizes:
- Consistency with existing channels (Telegram, Discord, IRC, etc.)
- Strong security posture (pairing, allowlists, strict mode)
- Minimal binary size impact
- Testability via mock HTTP server
- Clear separation of responsibilities (smolclaw does not manage the Java daemon)

---

## 2. Motivation

Users increasingly want to run autonomous agents inside the messaging apps they already use. Signal is particularly attractive because of its strong privacy and security properties. Adding Signal support would give smolclaw users a high-trust, end-to-end encrypted channel.

OpenClaw (a related but larger project) has proven that integrating via `signal-cli` is the only practical and maintainable approach in 2026.

---

## 3. Goals

- Support DMs and group chats over Signal.
- Full integration with existing security model (`dm_policy`, `allow_from`, pairing, strict security).
- Reuse as much existing infrastructure as possible (`sc_channel` vtable, pairing store, rate limiting, `sc_curl_init()`, bus, etc.).
- Keep the implementation auditable and relatively small (~550-700 LOC for the channel).
- Provide a clear, documented path for users to set up the required external daemon.

### Non-Goals (MVP)

- Implementing the Signal Protocol directly (libsignal).
- Spawning or managing the `signal-cli` Java process inside smolclaw.
- Attachments, voice notes, reactions, polls, or read receipts in the first version.
- Multi-account support.
- Real-time SSE streaming (polling is acceptable for MVP).

---

## 4. Architecture Overview

### 4.1 External Daemon Model (Mandatory)

smolclaw will **only** support talking to a separately running `signal-cli` daemon.

Two supported modes:

1. **Native mode** (recommended for most users):
   - User runs: `signal-cli -a +15551234567 daemon --http 127.0.0.1:7583 --receive-mode manual`
   - smolclaw talks to `http://127.0.0.1:7583/api/v1/rpc` (JSON-RPC) and optionally `/api/v1/events` (SSE in Phase 2).

2. **Container mode**:
   - User runs the `bbernhard/signal-cli-rest-api` Docker container (`MODE=json-rpc`).
   - smolclaw can auto-detect or be pointed at the container's REST + WebSocket endpoints.

**Rationale**: Embedding or auto-spawning a JVM would significantly increase binary size, startup time, and operational complexity — violating the "smol" philosophy.

### 4.2 MVP Scope

- Text-only (DMs + groups)
- Polling-based receive (`receive` RPC method)
- Full support for `dm_policy` (especially `"pairing"`)
- Support for both phone numbers (`+1...`) and UUIDs (`uuid:...`) as sender identifiers
- Basic group support via `group_trigger`

---

## 5. Configuration

### 5.1 Kconfig

```kconfig
config SC_ENABLE_SIGNAL
	bool "Signal channel (via external signal-cli daemon)"
	default n
	select NEED_PTHREADS
	help
	  Enable the Signal channel. Requires a running signal-cli daemon
	  (or bbernhard/signal-cli-rest-api container).

	  Recommended: dedicated bot phone number + dm_policy="pairing".
```

### 5.2 Config Struct (`src/config.h`)

```c
typedef struct {
    int enabled;
    char *account;             /* E.164 bot number, e.g. "+15551234567" */
    char *http_host;           /* default "127.0.0.1" */
    int http_port;             /* default 7583 */
    char *http_url;            /* full override URL */
    char *proxy;
    char *group_trigger;
    char *dm_policy;
    char **allow_from;
    int allow_from_count;
    char **tools;
    int tool_count;
} sc_signal_config_t;
```

### 5.3 Parsing & Environment Overrides

Standard patterns already used by Telegram/IRC/X will be followed:
- JSON parsing in `config.c`
- Environment variable overrides (`SMOLCLAW_SIGNAL_ACCOUNT`, `SMOLCLAW_SIGNAL_HTTP_URL`, etc.)
- Serialization back to JSON for `config dump`

---

## 6. Channel Implementation (`src/channels/signal.c`)

### 6.1 Core Data Structures

```c
typedef struct {
    char *account;
    char *base_url;
    char *proxy;
    char *group_trigger;

    pthread_t poll_thread;
    int thread_started;

    long last_receive_ts;
    int subscribed;
} signal_data_t;
```

### 6.2 Key Components

- **JSON-RPC Client Layer**
  - `signal_rpc(const char *method, cJSON *params)` — core function using `sc_curl_init()`
  - Proper error handling for JSON-RPC `error` objects
  - Response size limits

- **Receive / Polling Thread**
  - Calls `subscribeReceive` once on startup (when using manual mode)
  - Periodically calls `receive` with `since` timestamp
  - Parses `envelope` objects, extracts `source`, `sourceUuid`, `dataMessage`
  - Normalizes sender to `uuid:...` when available (preferred)
  - Normalizes group chat_id to `signal:group:<id>`
  - Respects `group_trigger`
  - Calls `sc_channel_is_allowed()` and `sc_channel_handle_message()`

- **Send**
  - Supports both individual recipients and `groupId`
  - Basic message chunking

- **Identifier Normalization**
  - Phone numbers kept as `+1555...`
  - UUIDs stored/passed as `uuid:xxxxxxxx-xxxx-...`
  - This is critical for reliable `allow_from` and pairing

---

## 7. Security Considerations (Critical)

### 7.1 Dedicated Number Recommendation

**Strongly recommended** that users register a dedicated phone number for the bot rather than linking their personal Signal account. This avoids:
- Message loops
- Accidental de-authentication of the user's main device
- Privacy leakage

### 7.2 Key Management

- `signal-cli` stores account keys in `~/.local/share/signal-cli` (or Docker volume).
- Users **must** back up this directory.
- Loss of keys = loss of the Signal identity.

### 7.3 Pairing & Access Control

The existing `sc_channel_handle_message()` logic in `channels/base.c` will be used automatically:
- When `dm_policy == "pairing"`, unknown senders receive a challenge code.
- The message tells them to run: `smolclaw pairing approve signal <CODE>`
- Both phone numbers and `uuid:...` forms must be supported in `allow_from` and revoke commands.

### 7.4 Strict Security Mode

Signal will participate in the existing `quarantine_check()` logic in `manager.c` when `SC_STRICT_SECURITY` is enabled.

### 7.5 Attack Surface

- smolclaw makes HTTP requests to a user-controlled (but external) daemon.
- JSON-RPC responses must be carefully validated (size limits, schema checks).
- Group IDs and UUIDs from the daemon must be treated as untrusted input.
- No new privileged operations are introduced.

### 7.6 Input Sanitization

- Group IDs (base64) and UUIDs should be validated for reasonable length and character set before use in logs or config.
- Message content is passed through the normal tool allowlist and output filtering systems.

---

## 8. Testing Strategy (Very Important)

### 8.1 Primary Approach: Mock HTTP Server

Use the existing `tests/mock_http.h` infrastructure (libevent `evhttp`).

The mock server will emulate:
- `POST /api/v1/rpc` for `receive`, `send`, `subscribeReceive`
- `GET /api/v1/check`

### 8.2 Required Test Cases

1. Channel construction and lifecycle (start/stop)
2. Receiving a DM from a phone number
3. Receiving a DM from a UUID (`sourceUuid`)
4. Receiving a group message and correct `chat_id` normalization
5. Pairing flow (unknown sender triggers `send` with pairing code)
6. `allow_from` matching for both phone and `uuid:...` forms
7. Group trigger filtering
8. Send to DM and send to group
9. Error handling (daemon returns HTTP 500, malformed JSON-RPC error, timeout)
10. Backoff behavior on repeated failures (resilience)

### 8.3 Real Daemon Smoke Test

In addition to unit tests, a manual smoke test with a real `signal-cli` daemon (using a test number) is required before considering the feature stable.

### 8.4 Test File

`tests/test_signal.c` — target ~230-260 lines, modeled after `test_telegram.c` and `test_discord.c`.

---

## 9. Implementation Roadmap

### Phase 0 — Foundations (1–2 days)
- Kconfig, config struct, basic parsing, CMake wiring

### Phase 1 — MVP (8–11 days)
- Core channel implementation
- JSON-RPC layer
- Polling + receive logic
- Send logic
- Identifier normalization
- Full manager integration
- `tests/test_signal.c`
- Basic documentation

**Exit criteria**: Functional text DM + group support with full security model.

### Phase 2 — Real-time & Polish (4–6 days)
- SSE streaming
- Typing indicators
- Health monitoring / `channels status`

### Phase 3 — Media & Advanced (6–8 days)
- Attachments + voice transcription
- Reactions
- Per-group tool scoping

See the full phased checklist in the original planning session for day-by-day breakdown.

---

## 10. Documentation Deliverables

1. Update `README.md` feature table and Kconfig list once implemented.
2. New file: `docs/channels/signal.md` (user-facing setup guide).
3. This design document (`docs/design/signal-channel.md`).

A full draft of the user-facing `docs/channels/signal.md` was created during planning and should be included or linked.

---

## 11. Open Questions

- Should we eventually support optional supervised spawning of the daemon (behind a very explicit flag)?
- What is the long-term story for multi-account Signal support?
- Should `group_trigger` be deprecated in favor of a more general mention system later?

---

## 12. Appendix: Draft User Documentation

The complete draft for `docs/channels/signal.md` (including setup instructions for both native and container modes, pairing examples, security warnings, troubleshooting, and config reference) was produced during the design session and should be placed in `docs/channels/signal.md` when the feature is implemented.

---

**End of Design Document**

This document captures the complete planning output from the 2026 design session, with particular emphasis on security and testability. Future implementers should treat this as the authoritative reference.

---

## Implementation Prompt Example

A carefully engineered prompt for Grok's `/implement --effort 3` skill (the full implement-review-fix loop) was developed for this feature. It references this design doc as the single source of truth, uses the X channel as the style and testing reference, and explicitly calls out the security model, deliverables, and test bar.

See: [docs/development/using-grok-implement-skill.md](../development/using-grok-implement-skill.md) — contains the complete prompt plus guidance on writing effective `/implement` prompts for other smolclaw features.