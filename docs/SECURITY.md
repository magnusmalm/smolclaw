# Security Reference

Full security documentation for smolclaw. This file is not loaded into LLM context automatically — read it when working on security-related code.

## Defense Layers Overview

Multiple layers prevent the LLM from performing destructive actions, exfiltrating data, or being manipulated via prompt injection.

## Tool Confirmation

`src/tools/registry.c`: Tools with `needs_confirm = 1` (exec, exec_background, git, write_file, edit_file, append_file, memory_write) require user approval before execution. In CLI mode, a `[CONFIRM] Tool: <name>` prompt is shown; the user types y/N. In gateway mode, an auto-approve callback is set so these tools execute without prompting — deny patterns and the allowlist are the security guards in unattended mode. The confirm callback is set on the registry via `sc_tool_registry_set_confirm()`.

## Tool Allowlist

`src/tools/registry.c`, `src/config.c`: Config `agents.defaults.allowed_tools` (JSON array) or env `SMOLCLAW_AGENTS_DEFAULTS_ALLOWED_TOOLS` (comma-separated) restricts which tools the LLM can see and call. When set, disallowed tools are filtered from tool definitions sent to the LLM and blocked at execution with an audit log entry. When NULL/empty, all tools are available (backward compatible).

## Exec Deny Patterns

`src/tools/deny_patterns.h`: ~90 POSIX ERE patterns shared between shell.c and background.c. Covers:

- rm -rf, format/mkfs, dd, shutdown, fork bombs, absolute path bypass (/bin/rm)
- Scripting language one-liners (python -c, perl -e, ruby -e, node -e)
- Pipe to shell, reverse shells (nc, ncat, /dev/tcp, socat)
- sudo/su, chmod 777 (including with -R flag), writes to /etc/
- killall/pkill, crontab, eval, source, bash octal/hex escapes
- Variable expansion evasion, find -delete/-exec rm, truncate, shred
- curl/wget data exfiltration, LD_PRELOAD injection, tee to system paths, systemctl
- Command substitution (bare backtick, bare `$(`)
- sh/bash -c invocation, pipe to interpreters (python/perl/ruby/node/php)
- xargs rm, env bypass, busybox wrappers, heredoc to shell, base64 decode pipe, wget -O - pipe
- IFS variable evasion (`$IFS`, `${IFS}`, inline `ifs=`), glob evasion (`r?`, `r*`)
- mv to system dirs, ln (symlink/hardlink), kill with signal
- tar extract to system dirs (both `-x` and flag-style `xf`), chown/chgrp, mount/umount
- docker/podman, iptables/ufw/nft, sed -i to system paths
- rsync/scp exfiltration (remote targets with @), strace/ltrace/nmap
- Package managers (apt/yum/dnf/pacman/pip/npm install/remove)
- Sensitive file reads (cat/head/tail of /etc/shadow, /etc/passwd, /etc/sudoers, .ssh/)
- Brace expansion evasion (`{rm,-rf,/}`), awk/gawk `system()` calls, printf hex format abuse, pipe to awk/gawk
- Writes to `.smolclaw/` config directory (redirects and cp/mv/tee/sed)
- Archive extraction (unzip -o, unzip -d to system dirs, cpio, 7z x)
- Mail exfiltration (sendmail/mailx/msmtp/mutt)

Shell commands are normalized (newlines, `\r`, `\v`, `\f` → semicolons) and non-ASCII bytes are stripped before pattern matching to prevent newline-based and invisible Unicode character evasion.

## Exec Allowlist Mode

`src/tools/shell.c`, `src/tools/background.c`: Optional allowlist mode restricts exec to a configured set of commands. Config: `agents.defaults.exec_mode` ("denylist"/"allowlist") and `agents.defaults.exec_allowed_commands` (JSON array). Env: `SMOLCLAW_AGENTS_DEFAULTS_EXEC_MODE`, `SMOLCLAW_AGENTS_DEFAULTS_EXEC_ALLOWED_COMMANDS` (comma-separated).

Denylist always runs even in allowlist mode (defense in depth). First command word extraction strips leading quotes (`"rm"` → `rm`) and terminates on shell metacharacters including `$`, backtick, `\`, and quote chars. Multi-segment checking: ALL command segments (split on `;`, `|`, `&&`, `||`) are verified, not just the first.

## SSRF Protection

`src/tools/web.c`: `web_fetch` resolves hostnames via `getaddrinfo(AF_UNSPEC)` before fetching and blocks private/reserved IP ranges:

- IPv4: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
- IPv6: ::1, ::ffff:mapped-private, fe80::/10, fc00::/7
- Cloud metadata hostnames

DNS rebinding is prevented via `CURLOPT_RESOLVE` pinning (resolved IP from SSRF check is passed to curl). Redirect bypass prevented via `http_get_no_follow()` + manual redirect loop with per-hop `check_ssrf()`. Tests bypass SSRF via `sc_web_set_ssrf_bypass(1)` (internal API, not settable via environment).

## Message Restriction

`src/tools/message.c`: Config `agents.defaults.restrict_message_tool` (bool) or env `SMOLCLAW_AGENTS_DEFAULTS_RESTRICT_MESSAGE_TOOL`. When true, the message tool can only send to the channel/chat_id that initiated the conversation.

## Environment Sanitization

**MCP** (`src/mcp/client.c`): Before spawning MCP server subprocesses, dangerous environment variables are removed: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `PYTHONPATH`, `RUBYLIB`, `NODE_PATH`, `PERL5LIB`, `BASH_ENV`, `ENV`, `SHELLOPTS`.

**Exec children** (`src/tools/shell.c`, `src/tools/background.c`): Fork/exec children receive a sanitized environment via `execle()`. Only safe variables are passed: PATH, HOME, TERM, LANG, LC_ALL, USER, SHELL, LOGNAME, TMPDIR, TZ.

## FD Cleanup

Forked exec children and MCP child processes close all inherited file descriptors >= 3 before exec, preventing bus pipes, IRC sockets, audit log FDs, etc. from leaking.

## File Permissions

Config, session, and audit files are created with mode 0600. Pairing directory created with mode 0700. Config load warns if permissions are too open.

## Prompt Injection Defense

`src/agent_turn.c`, `src/util/prompt_guard.c`: Tool output is CDATA-wrapped in `<tool_output tool="..." id="..."><![CDATA[...]]></tool_output>` XML tags before being fed back to the LLM. The `sc_xml_cdata_wrap()` helper splits `]]>` sequences in content to prevent CDATA escape. Tool name and ID in XML attributes are escaped via `sc_xml_escape_attr()` (`& < > " '` → XML entities).

High-confidence prompt injection patterns (via `sc_prompt_guard_scan_high()`) trigger an active `[WARNING: suspected prompt injection]` prefix inside the CDATA content. Prompt guard normalizes whitespace before pattern matching. High-confidence patterns include LLM control tokens (`<|endoftext|>`, `<|im_end|>`, `[/inst]`, `<s>`, `</s>`, `<|im_start|>`).

## Secret Scanning

`src/util/secrets.c`: Regex-based detection and redaction of 13 pattern types:

1. API keys (`sk-...`)
2. PEM private keys
3. Key=value secrets (password, token, apikey, secret_key, access_key, client_secret, auth_token, refresh_token)
4. JWT tokens
5. AWS access keys (AKIA...)
6. GitHub tokens (ghp_/gho_/ghs_/ghr_/github_pat_)
7. Bearer tokens
8. Slack tokens (xox[bpras]-)
9. Google API keys (AIza...)
10. Stripe keys (sk_live/sk_test)
11. Database connection strings (postgres/mysql/mongodb/redis://)
12. Anthropic API keys (sk-ant-api)
13. SSH key variants (DSA/ECDSA/EC/OPENSSH)

Applied to: tool output before LLM, assistant messages before session storage, summarization transcripts before LLM, summary output before storing, memory context before system prompt injection, outbound responses to users.

## Filesystem Protection

**Symlink protection** (`src/tools/filesystem.c`): All file operations check the original path via `lstat()` before `realpath()` resolution. Symlinks are rejected.

**Bootstrap file protection** (`src/tools/filesystem.c`, `src/context.c`): Write/edit/append blocked on: AGENTS.md, SOUL.md, USER.md, IDENTITY.md, HEARTBEAT.md. Context builder checks for symlinks before loading bootstrap files.

**Sensitive path blocklist** (`src/tools/filesystem.c`): Blocks `.ssh/`, `.aws/`, `.gnupg/`, `.kube/`, `.smolclaw/` (directories) and `.env`, `.netrc`, `.npmrc`, `.pypirc` (files, case-insensitive). Exception: `.smolclaw/workspace/` is allowed.

**File type validation:** Reads reject non-regular files (devices, pipes) and enforce 10 MB limit. Writes/appends verify target is regular file via `fstat()`/`S_ISREG()`.

**MCP tool name sanitization** (`src/mcp/bridge.c`): Alphanumeric + single underscore + hyphen only, no `__`, max 64 chars.

## Encrypted Vault

`src/util/vault.c`: AES-256-GCM encrypted storage for API keys and secrets. Key derivation via PBKDF2-HMAC-SHA256 (600,000 iterations). Config references secrets via `vault://key_name`. Vault file created with mode 0600. Atomic writes (temp + rename). Memory zeroing after use. CLI management: `smolclaw vault init/set/get/list/remove/export/change-password`. Feature-gated: `SC_ENABLE_VAULT`.

## OS-Level Sandbox

`src/util/sandbox.c`: Exec children sandboxed via Landlock + seccomp-bpf after `fork()`, before `exec()`. Config: `agents.defaults.sandbox` (bool, default true).

**Landlock** (filesystem): Workspace and `/tmp` get full rw. System binary dirs get read+execute. `/etc` and `/proc` get read-only. Device nodes get appropriate access. Everything else denied. Graceful fallback on unsupported kernels.

**seccomp-bpf** (syscalls): 26 dangerous syscalls blocked with `SECCOMP_RET_ERRNO` (EPERM): mount/umount/pivot_root, reboot, kexec, kernel modules, ptrace/process_vm, swap, time setting, hostname, bpf/perf/userfaultfd, memory migration, keyctl. 27 on armv7l (adds `clock_settime64`). Graceful fallback.

## Resource Limits

`src/agent_turn.c`: Per-turn limits — `max_tool_calls_per_turn` (50), `max_turn_secs` (300), `max_output_total` (500KB). Configurable via `agents.defaults.*` or `SMOLCLAW_AGENTS_DEFAULTS_*` env vars.

## Rate Limiting

`src/rate_limit.c`: Token-bucket per channel+chat_id, 64-slot LRU table. Config: `agents.defaults.rate_limit_per_minute` (default 20). Thread-safe (mutex-protected).

## Network Security

**TLS verification** (`src/util/websocket.c`, `src/channels/irc.c`): All TLS connections verify certificates via `SSL_CTX_set_default_verify_paths()` + `SSL_VERIFY_PEER` + `SSL_set1_host()`.

**Cryptographic RNG** (`src/util/websocket.c`): WebSocket masking uses `RAND_bytes()` with `/dev/urandom` fallback.

**Protocol restrictions**: All curl handles restrict to HTTP/HTTPS via `CURLOPT_PROTOCOLS_STR`. Applied to all `curl_easy_init()` sites.

**Response size caps**: `SC_CURL_MAX_RESPONSE` (50 MB), `SC_SSE_MAX_LINE` (1 MB), `SC_DOWNLOAD_MAX_SIZE` (25 MB), `SC_MAX_READ_FILE_SIZE` (10 MB).

**Connect timeout**: 10s `CURLOPT_CONNECTTIMEOUT` + 30s `CURLOPT_TIMEOUT` on all curl handles.

## Thread Safety

Bus message queue uses `pthread_mutex_t`. Rate limiter is mutex-protected. Audit log is mutex-protected. Channel `running` flag is `volatile int`. Discord WebSocket state (`sequence`, `heartbeat_acked`) uses `atomic_int`. Async summarization uses `atomic_int` for thread status and cloned providers for thread isolation.

## Access Control

**DM policies** (per-channel): `"open"` (explicit only), `"allowlist"` (default, fail-closed), `"pairing"` (challenge code). `sc_dm_policy_from_str(NULL)` → allowlist (not open).

**Pairing** (`src/pairing.c`): 12-char codes (60-bit entropy, `/dev/urandom`), 1hr expiry, max 3 pending, 5-attempt brute force lockout (15min). Timing-safe comparison.

**Sender ID validation** (`src/channels/base.c`): Multiple pipe characters rejected.

**Discord channel_id** (`src/channels/discord.c`): Numeric-only validation before URL interpolation.

**Slack** (`src/channels/slack.c`): Socket Mode WSS connection with app_token for receiving, bot_token for Web API sends. Bearer token never exposed to LLM.

**Web** (`src/channels/web.c`): REST API with required Bearer token authentication. Binds to 127.0.0.1 by default (localhost only). Users should put nginx/caddy in front for TLS.

**Spawn depth** (`src/tools/spawn.c`): `SC_MAX_SPAWN_DEPTH` (3) via `_Thread_local` counter.

## Audit

`src/audit.c`: `sc_audit_log_ext()` records tool name, args summary, status, duration, event type, channel, user ID. Security events (deny blocks, confirm denials, allowlist rejections, SSRF blocks) are logged.

## Production Security Tests

`test_security_prod` — `EXCLUDE_FROM_ALL`, loads `~/.smolclaw/config.json`, 300 assertions across 177 test functions. Combined with `test_sandbox` (22 assertions) and IRC smoke tests (3): 325 total security tests.

```bash
scripts/test_security.sh --local --verbose   # Full run (C + IRC)
scripts/test_security.sh --skip-irc          # C tests only
```

Test categories: deny patterns (110), SSRF (30), allowlist (12), secret redaction (30), XML CDATA (14), MCP names (8), symlink TOCTOU (8), bootstrap files (8), prompt injection (20), outbound scanning (4), rate limiting (6), session redaction (4), message restriction (4), TLS (4), exec allowlist (8), sensitive paths (12), OpenClaw post-mortem (2), and more. See `tests/test_security_prod.c` for the full inventory.
