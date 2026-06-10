# Design: xAI Grok OAuth (SuperGrok Subscription) Provider

**Status**: Design Complete — Ready for Implementation  
**Author**: Planning session with Grok (2026-05)  
**Last Updated**: 2026-05-16  
**Related**: 
- [x.ai/news/grok-hermes](https://x.ai/news/grok-hermes)
- Hermes Agent xAI Grok OAuth docs (`hermes-agent.nousresearch.com/docs/guides/xai-grok-oauth`)
- `src/providers/factory.c`, `src/providers/http.c`, `src/config.{c,h}`
- `src/util/vault.c`, `src/util/sha256.c`, `src/util/base64.c`, `src/util/curl_common.c`
- `src/main.c` (subcommands), `tests/mock_http.h`
- `docs/SECURITY.md`, `README.md` (smol philosophy), `src/channels/x.c` + `src/util/x_api.c` (existing OAuth 1.0a precedent)
- Hermes reference implementation: `hermes_cli/auth.py` (especially `_xai_oauth_loopback_login`, `resolve_xai_oauth_runtime_credentials`, JWT exp decoder, callback server)

---

## 1. Summary

This document describes the design for adding **xAI Grok OAuth (SuperGrok Subscription)** support to smolclaw. Users with an active Grok subscription (any SuperGrok tier) will be able to authenticate via a one-time browser-based OAuth 2.0 PKCE flow and use Grok models (`grok-4.3`, reasoning variants, etc.) **without** providing an `XAI_API_KEY` from console.x.ai.

The implementation reuses the **exact same public client_id and OIDC flow** that the official (closed-source) Grok CLI and Hermes Agent use:

- Client ID: `b1a00492-073a-47ea-816f-4c329264a828`
- Issuer / Discovery: `https://auth.x.ai/.well-known/openid-configuration`
- Scope: `openid profile email offline_access grok-cli:access api:access`
- Special params: `plan=generic` + `referrer=smolclaw`

A fresh access token is obtained on `smolclaw auth login xai` (or via provider picker), stored securely, automatically refreshed before expiry, and supplied as the `Authorization: Bearer` token to the existing OpenAI-compatible xAI HTTP provider. The same token will be reusable for future direct-to-xAI features (image generation via Grok Imagine, TTS, video).

**Core constraint**: Everything must honor the **smolclaw "smol" philosophy** — tiny binary, zero new runtime dependencies, auditable C code, minimal footprint on edge/VPS/container deployments.

---

## 2. Motivation

xAI publicly announced (May 2026) that Grok subscriptions can now be used inside third-party open-source agents via OAuth, starting with Hermes. The official Grok CLI (`grok login`) already uses this OIDC flow under the hood (tokens live in `~/.grok/auth.json`).

smolclaw is positioned as the **lightweight C alternative** to both the official Grok CLI (Rust, closed) and Hermes (full Python agent with browser automation, Playwright, heavy deps). Adding subscription support keeps feature parity for Grok users while preserving smolclaw's unique strengths:

- Runs on constrained hardware where Python + uv + Node + Playwright would be impossible.
- Multi-channel (Telegram/Discord/IRC/Slack/X/Web/CLI) with the same Grok backend.
- Existing multi-provider fallback, cost tracking, sandbox, skills, and memory all continue to work unchanged.

Without this, smolclaw Grok users are forced to use a separate console.x.ai API key (different quota/billing model from the subscription they already pay for).

---

## 3. Goals

- Full login + automatic refresh flow for xAI OAuth using the public client_id.
- Seamless integration: `provider: "xai-oauth"` (or `grok-oauth`) in config / `--provider` / inline `Use grok-oauth: ...` works exactly like `xai` today, but pulls a dynamic token.
- One login covers chat (and future image/TTS/video).
- Excellent remote / headless / SSH / container / VPS UX (`--no-browser` mode prints URL; callback still works).
- Clear errors and re-auth path on refresh failure.
- **Zero impact** on users who continue using `XAI_API_KEY`.

### Non-Goals (MVP)

- New chat transport (reuse `providers/http.c` + `codex_responses`-style surface; xAI is OpenAI-compatible).
- Implementing image/video/TTS tools in the first cut (the credential resolver will be designed to be shared, like Hermes `tools/xai_http.py`).
- Support for the legacy `https://accounts.x.ai/sign-in` scope (only the modern OIDC one).
- Multi-account xAI OAuth or credential pools (Hermes has this; smolclaw defers).
- Device-code flow (loopback PKCE only; simpler and matches Hermes + official CLI).
- Automatic migration from `~/.grok/auth.json` (nice-to-have later; documented as possible).

---

## 4. "smol" Theme Alignment (Critical)

smolclaw's entire identity is **"C11 lightweight AI agent framework for constrained hardware"**:

- 280 KB dynamic-minimal / 4.6 MB fully static musl binary
- Zero runtime dependencies (no Python, Node, JVM, heavy frameworks)
- Kconfig feature flags, compile-time trimming
- Runs on edge devices, cheap VPS ($5), Termux, containers, air-gapped-ish setups
- Auditable, small LOC, reuse existing infrastructure everywhere

**This feature must not violate the smol contract**:

- **Code size**: Target **< 650 net new LOC** (mostly `src/util/xai_oauth.c` + small glue in factory/main/config + tests). Compare to X OAuth1a (~400 LOC in `util/x_api.c`).
- **Binary impact**: < 40-60 KB stripped (PKCE + JWT decoder + small evhttp one-shot server + JSON handling reuse cJSON). No new libraries.
- **Dependencies**: Reuse **exclusively** what we already link:
  - `libevent` evhttp (already used by web channel + `tests/mock_http.h`)
  - libcurl (via `curl_common`)
  - cJSON
  - sha256.c (we already have it)
  - base64.c (add base64url variant — ~30 LOC)
  - Existing str/ arena / json_helpers
  - Optional: vault for master-password protection of the auth store (opt-in)
- **No bloat**: No Playwright, no browser engine, no Node, no Python venv, no heavy OAuth libraries. The callback server is a 60-line one-shot handler.
- **Runtime cost**: Login is a one-time CLI action. Runtime refresh is a single small HTTPS POST (same cost as any other provider call). No background threads unless a channel is active.
- **Fits edge**: Works in the same musl-static Docker image, Termux, Raspberry Pi-class devices, etc. Hermes cannot run in these environments; smolclaw + Grok OAuth can.
- **Philosophy**: "Reuse the battle-tested http provider instead of forking a new transport." "The token is just a fancy api_key that expires and refreshes."

If a design choice increases binary size or adds a new dep, it is rejected.

---

## 5. Architecture Overview

### 5.1 High-Level Flow

1. User runs `smolclaw auth login xai` (or selects "xAI Grok OAuth (SuperGrok Subscription)" in a future model picker, or sets `provider: "xai-oauth"` and triggers on first use).
2. smolclaw performs OIDC discovery → builds PKCE authorize URL with `plan=generic` + `referrer=smolclaw`.
3. Opens browser (or prints URL for `--no-browser` / remote detection).
4. Temporary **loopback-only** evhttp server binds to `127.0.0.1:56121` (or first free port) and serves `/callback`.
5. User completes consent on accounts.x.ai → redirect brings `code` + `state` back to the local server.
6. smolclaw validates state, performs token exchange (using `code_verifier`), stores structured tokens + discovery metadata.
7. On every subsequent xAI chat (when provider is `xai-oauth`):
   - `sc_xai_oauth_ensure_fresh_token()` is called.
   - Decodes JWT `exp` claim (cheap, local, no network).
   - If within 120s skew → refresh using `refresh_token`.
   - Re-validates the `token_endpoint` origin on every refresh (defense against poisoned discovery cache).
8. The fresh access token is passed as `api_key` to `sc_provider_http_new()` — zero changes to the actual chat/streaming/tool-calling path.

### 5.2 Storage

**Recommended**: `~/.smolclaw/auth.json` (mode 0600, atomic replace, fcntl/msvcrt locking).

Structure (inspired by Hermes but simpler):

```json
{
  "version": 1,
  "providers": {
    "xai-oauth": {
      "auth_mode": "oauth_pkce",
      "tokens": {
        "access_token": "eyJ...",
        "refresh_token": "...",
        "id_token": "...",
        "token_type": "Bearer",
        "expires_in": 3600
      },
      "discovery": {
        "authorization_endpoint": "...",
        "token_endpoint": "https://auth.x.ai/oauth/token"
      },
      "redirect_uri": "http://127.0.0.1:56121/callback",
      "last_refresh": "2026-05-16T12:34:56Z"
    }
  }
}
```

**Why not put tokens in the main `config.json`?**  
Secrets never belong in the user-editable config (same reason API keys go to `vault://` or env). `auth.json` is internal, like Hermes.

**Alternative considered**: Store `access_token` / `refresh_token` as vault items (`xai_oauth_access`, `xai_oauth_refresh`). Rejected for MVP because:
- Vault is password-protected (friction for a login flow).
- Structured state (discovery endpoints, redirect_uri, timestamps) is easier in JSON.
- Future credential pool / multiple identities would be harder.

**Hybrid future**: Allow `vault://` references inside auth.json for the refresh_token (advanced).

File is created with `chmod 0600`. Directory `~/.smolclaw/` is assumed 0700 (standard).

### 5.3 Integration Points

- `providers/factory.c`: Add `{"xai-oauth", "grok-oauth", "grok-sub"}` (or special-case inside the xai entry when `oauth_mode` detected). Set `allow_no_key = 1`.
- `providers/http.c`: No change — it just receives a bearer string.
- `config.c/h`: Minor — new `SMOLCLAW_PROVIDERS_XAI_OAUTH` override + possible `providers.xai.oauth: true` or separate top-level `xai_oauth` section for future.
- `main.c`: New `auth` subcommand (parallel to `vault`, `pairing`, `analytics`):
  ```
  smolclaw auth login xai [--no-browser] [--timeout 180]
  smolclaw auth status [xai]
  smolclaw auth logout xai
  smolclaw auth refresh xai
  ```
- `util/xai_oauth.c` (new): All the logic — pure functions + one public entrypoint for the CLI and one for runtime resolution.
- `audit.c`: New event types (`auth_xai_login_success`, `auth_xai_refresh`, `auth_xai_relogin_required`).
- Redaction: Ensure access/refresh tokens are redacted in all logs (reuse existing redaction machinery).

---

## 6. Security Aspects (Critical)

OAuth for a powerful LLM backend is high-value; we must be **more paranoid** than a typical web app because the token grants access to the user's Grok subscription (and in the future image/video generation that could be abused).

### 6.1 Threat Model & Mitigations

| Threat | Mitigation |
|--------|------------|
| **Token theft** from disk | `~/.smolclaw/auth.json` created 0600. User home directory perms are the outer boundary (standard for `~/.ssh/`, `~/.netrc`, `~/.aws/credentials`). Never world-readable. |
| **MITM / cache poisoning** of discovery or token_endpoint | On every refresh we re-validate that the `token_endpoint` from cached discovery is under `auth.x.ai` (or `*.x.ai`). See Hermes `_xai_validate_oauth_endpoint`. Discovery itself is fetched over HTTPS with normal curl verification. |
| **CSRF / state mismatch** on callback | Cryptographically random `state` (uuid4 hex) + `nonce`. Server rejects if returned state != sent state. |
| **Redirect URI confusion / open redirect** | Strict validation in C: scheme must be `http`, host exactly `127.0.0.1`, explicit port present. Loopback-only binding (`evhttp_bind_socket` on 127.0.0.1, never 0.0.0.0 or `::`). |
| **Malicious callback server on same port** | `allow_reuse_address` is used carefully; we bind first and fail fast if port busy. Short-lived (180s timeout). |
| **JWT confusion / alg:none / signature bypass** | We **never** verify the signature for expiry check. We only parse the `exp` claim after base64url decode (untrusted input). All real validation happens at xAI when the bearer token is presented. If the JWT is garbage we treat it as "not expiring soon" (safe fallback). |
| **Refresh token replay / invalid_grant** | On 400/401 from refresh we surface a typed error with `relogin_required` and tell the user to run `smolclaw auth login xai` again. We do **not** retry forever. |
| **Token leakage in logs / audit / traces / crash dumps** | All token fields go through the existing redaction filter (`src/util/redact.c` / prompt guard). `Authorization` headers are never logged at INFO level. |
| **Long-lived refresh token** | `offline_access` scope is required for refresh; this is intentional (matches official CLI + Hermes). User can revoke at accounts.x.ai settings or via `smolclaw auth logout xai`. |
| **Browser / local attacker** | Callback page is minimal static HTML. No JavaScript. CORS allowlist is extremely narrow (only `https://accounts.x.ai` and `https://auth.x.ai`). |
| **Remote / SSH session abuse** | Automatic detection (env vars `SSH_CONNECTION`, `SSH_CLIENT`, `TERM=dumb`, no controlling tty, `SMOLCLAW_NO_BROWSER=1`) forces `--no-browser` behavior: URL is printed, user must open it on their workstation. The callback listener still runs on the remote host. |
| **Client impersonation** | We are a public client (no client_secret). Security comes from PKCE + exact redirect_uri + short-lived codes. We add `referrer=smolclaw` for attribution (same as Hermes uses `hermes-agent`). |
| **Supply-chain / future client_id rotation** | Client ID is a constant in the source (easy to update in one place + release note). Document that xAI could change it and we will follow. |

### 6.2 Comparison to Existing OAuth 1.0a (X Channel)

smolclaw already has production OAuth code in `src/util/x_api.c` (HMAC-SHA1 signing for Twitter API v2, used by both channel and X tools). Lessons applied:
- All secrets live in dedicated structs that are zeroed after use where possible.
- Signing never logs intermediate values.
- We will apply the same discipline to the bearer token (treat it like `consumer_secret`).

### 6.3 File Locking & Atomicity

Use the same pattern already present in smolclaw for other sensitive files (or copy the robust one from Hermes `auth.py`):
- `fcntl` (Unix) / `msvcrt` (Windows) advisory lock with timeout.
- Write to `.tmp.$$` then `rename()` (or `atomic_replace` helper if we extract one).
- Never truncate-in-place while a reader might be holding a token.

### 6.4 Audit & Observability

- Every login, successful refresh, forced re-auth, and logout emits an audit event.
- `smolclaw doctor` (or equivalent) will show "xAI OAuth: valid (expires in 47m, last refresh 12m ago)" or "needs re-login".
- Failed refresh with `invalid_grant` is a high-severity audit item.

---

## 7. Configuration & CLI

### 7.1 Provider Selection

Users can select the OAuth variant in any of the existing ways smolclaw supports provider choice:

- Config: `"provider": "xai-oauth"` (or `"grok-oauth"`)
- Per-message: `Use grok-oauth: explain the new feature`
- CLI flag / env: `--provider xai-oauth` or `SMOLCLAW_INFERENCE_PROVIDER=xai-oauth`
- Future TUI/model picker (if one is added)

When `xai-oauth` is active and no static `api_key` is present, the runtime resolver is invoked.

Priority for xAI credentials (proposed):
1. Explicit `XAI_API_KEY` env or `providers.xai.api_key` in config (backward compat, highest priority)
2. Fresh token from `xai-oauth` resolver (if `provider: xai-oauth` or `providers.xai.oauth: true`)
3. Error ("no xAI credentials")

This matches Hermes behavior.

### 7.2 New `auth` Subcommand

Modeled on `vault` and Hermes `hermes auth`:

```bash
smolclaw auth login xai [--no-browser] [--timeout 180]
smolclaw auth status
smolclaw auth logout xai
smolclaw auth refresh xai   # force refresh for testing
```

`smolclaw auth login xai --no-browser` is the documented path for VPS / Docker / SSH.

### 7.3 Kconfig

```kconfig
config SC_ENABLE_XAI_OAUTH
	bool "xAI Grok OAuth (SuperGrok subscription support)"
	default y
	select SC_ENABLE_XAI   # if xai provider is optional
	help
	  Enable browser-based OAuth login for users with a Grok subscription.
	  Adds ~50KB to the binary and the `auth` subcommand for xai.
	  Requires libevent (already present for web channel).
```

Can be unconditionally compiled if we decide the xai provider is always on.

---

## 8. Implementation Notes & File Changes

**New file**: `src/util/xai_oauth.c` + `.h`

Major internal functions (modeled on Hermes but in C style):

- `sc_xai_oauth_discover()`
- `sc_xai_oauth_pkce_generate_verifier_challenge()` (uses our sha256)
- `sc_xai_oauth_start_callback_server()` — returns `struct evhttp*`, actual port, result struct
- `sc_xai_oauth_wait_for_callback()` — runs event loop with timeout, returns code/state/error
- `sc_xai_oauth_build_authorize_url()`
- `sc_xai_oauth_exchange_code()`
- `sc_xai_oauth_save_tokens()`
- `sc_xai_oauth_read_tokens()`
- `sc_xai_jwt_get_exp()` — the critical cheap expiry parser
- `sc_xai_oauth_refresh_pure()`
- `sc_xai_oauth_ensure_fresh_token()` — the one called by the provider factory at runtime

**Base64url**: Add `base64url_encode()` / `base64url_decode()` helpers in `util/base64.c` (or new `base64url.c`). RFC 4648 §5, no padding for challenge.

**Browser open**: Small cross-platform helper (`xdg-open`, `open`, `start`, `cygstart`). Falls back to "please open this URL manually".

**Remote detection**: Centralize in a new `util/remote.c` or reuse existing patterns from web channel / pairing.

**Error type**: Extend existing error handling or add small `sc_auth_error_t` with code + `relogin_required` flag (mirrors Hermes `AuthError`).

---

## 9. Test Coverage (Critical)

OAuth flows are notoriously easy to get wrong on security edges. We will have **excellent** test coverage.

### 9.1 Unit Tests (pure C, no network)

- `tests/test_xai_oauth.c` (new)
  - JWT exp decoder: valid token, expired token, skew, malformed base64, missing exp, non-numeric exp, etc. (use known-good JWTs generated once).
  - PKCE: verifier generation length, challenge = base64url(sha256(verifier)), known test vectors.
  - URL building: all required params present, `plan=generic`, `referrer=smolclaw`, proper escaping.
  - State machine: refresh decision logic, skew handling.
  - Token serialization round-trip (auth.json shape).

### 9.2 Mock HTTP + Callback Tests

- Extend `tests/mock_http.h` (already used for Telegram, web tools, providers) with an `xai_oauth_mock` that can:
  - Serve a fake OIDC discovery document.
  - Serve `/token` for authorization_code and refresh_token grants.
  - Simulate error responses (400 invalid_grant, 401, network timeout).
- Headless login test: call the login path with `no_browser=true`, inject a synthetic `code` into the callback result struct, verify exchange happens and tokens are written to a temp auth.json.
- Callback server tests: bind failure, port fallback, wrong path, state mismatch, timeout, CORS headers.

### 9.3 Integration / Provider Tests

- In `tests/test_providers.c` (existing): add cases for `provider=xai-oauth` that use the mock credential source and verify the Bearer header contains the expected token.
- Config round-trip tests in `tests/test_config.c`.
- End-to-end with real xAI would be manual / gated (token would be short-lived in CI). Use recorded responses where possible.

### 9.4 Security & Negative Tests

- File permission test: after login, assert `stat(auth.json).st_mode & 0777 == 0600`.
- Redaction test: verify tokens do not appear in log output or audit JSON even at DEBUG level.
- Concurrency: two processes trying to refresh at the same time (lock contention test).
- Malformed discovery / token responses.
- Very long `state` / `code` (buffer safety — we use bounded buffers + `sc_str_*` helpers).

### 9.5 Coverage Goals

- ≥ 90% line coverage on `src/util/xai_oauth.c`
- 100% of security-critical paths (JWT decode, refresh decision, origin validation, state check) exercised by unit + mock tests.
- CI runs the new test binary on Linux (glibc + musl) and macOS.

---

## 10. Phased Delivery & Future Work

**MVP (this design)**: Chat + tool calling via `xai-oauth` provider using the shared access token. Full `auth` subcommand, remote support, refresh, tests.

**Phase 2** (small follow-up):
- Direct-to-xAI image generation tool (`grok-imagine-image`, `grok-imagine-image-quality`).
- TTS and video generation tools reusing the same `sc_xai_oauth_ensure_fresh_token()` resolver.
- Optional: read tokens from `~/.grok/auth.json` (official CLI interoperability) as a fallback source.

**Phase 3** (if demand):
- Credential pool support (multiple xAI identities, like Hermes).
- Device-code flow variant for environments where loopback is blocked.
- TUI model picker that surfaces the OAuth option.

---

## 11. Open Questions / Risks

1. **Interoperability with `~/.grok/auth.json`**: Should we read (but never write) the official scope key as a read-only source? Low priority but nice for users who already ran `grok login`.
2. **Client ID rotation by xAI**: How do we communicate an update? (Release note + constant in one place is acceptable.)
3. **Windows support**: evhttp works on Windows via libevent, but browser launch + file perms are different. Is Windows a first-class target for smolclaw today? (Current X OAuth1a already has some Windows considerations.)
4. **Vault integration depth**: Should the refresh_token be optionally wrapped by the AES-256-GCM vault? Adds friction but increases security on multi-user machines.
5. **Rate limiting on auth endpoints**: xAI may have strict limits on token exchange/refresh during development. Document backoff.

---

## 12. References & Prior Art

- Hermes Agent implementation (the authoritative public reference for this exact flow in 2026).
- Official Grok CLI installer (shows the OIDC_SCOPE string containing the client UUID).
- smolclaw existing OAuth 1.0a (`util/x_api.c`) — signing discipline and secret handling.
- `tests/mock_http.h` + web channel evhttp usage — the pattern we will reuse for the callback server.
- `docs/SECURITY.md` and deny-patterns philosophy — everything new must pass the same bar.
- RFC 7636 (PKCE), RFC 8414 (OAuth 2.0 Authorization Server Metadata / OIDC discovery), RFC 7519 (JWT).

---

**This design keeps smolclaw smol while giving Grok subscribers the same first-class experience that Hermes users now enjoy.** Implementation can proceed once this doc is reviewed and approved.

Next concrete step after approval: create the skeleton `src/util/xai_oauth.h` + basic JWT + PKCE functions + test file, then the full login flow.