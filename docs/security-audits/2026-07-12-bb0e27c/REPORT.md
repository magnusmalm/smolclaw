# Penetration Test Report

**Target:** smolclaw  
**Local path:** `/home/user/devel/smolclaw`  
**Repository:** `https://github.com/magnusmalm/smolclaw.git`  
**Commit:** `bb0e27c74296d47f000025afa96061aaf7918b11`  
**Version:** 1.0  
**Date:** 2026-07-12  
**Engagement type:** Crystal-box security code review (agent-assisted, ROS-style)  
**Depth mode:** standard  
**Classification:** Private / Internal  
**Authors:** crystal-box-audit (Grok)  
**Finding ID prefix:** SML  
**Prior audit:** `docs/security-audits/2026-07-12-a1135e9/` at `a1135e9` (Initial commit; 337 commits behind this HEAD)

## Document Properties

| Field | Value |
|-------|-------|
| Client / owner | magnus |
| Title | Penetration Test Report — smolclaw (HEAD retest) |
| Target summary | C11 multi-channel AI agent; gateway + tools + sandbox |
| Tools available | cloc, rg, clang, semgrep, afl-fuzz (not required for standard) |
| Tools missing | codeql |
| Scope | `src/` security surfaces; retest of SML-001…008 |

## Version control

| Version | Date | Description |
|---------|------|-------------|
| 1.0 | 2026-07-12 | Standard audit of `bb0e27c` |

---

# 1 Executive Summary

## 1.1 Introduction

On 2026-07-12, a standard crystal-box review was performed against **smolclaw** at commit `bb0e27c` (current `~/devel/smolclaw` HEAD). This is a **retest relative to** the earlier audit of `a1135e9` (the repository’s initial commit).

## 1.2 Scope of Work

- In scope: agent/gateway tool path, exec denylist, sandbox, web auth, SSRF, MCP spawn, channel DM defaults, prior finding status.  
- Out of scope: multi-hour AFL campaign, full CodeQL, live multi-channel production traffic.  
- Effort: standard agent-assisted session.

## 1.3 Project Objectives

Determine which prior findings remain, which were fixed in the 337-commit delta, and whether new high-priority issues appear on HEAD.

## 1.4 Timeline

2026-07-12 (single session).

## 1.5 Results In A Nutshell

**Prior findings (a1135e9 → bb0e27c):**

| Prior ID | a1135e9 severity | Status on `bb0e27c` |
|----------|------------------|---------------------|
| SML-001 | Elevated | **Open** (stock builds still default DM `open`; opt-in `SC_STRICT_SECURITY`) |
| SML-002 | Elevated | **Open** (gateway hardcodes auto-confirm; denylist still incomplete) |
| SML-003 | Moderate | **Fixed** (sandbox apply failure → `_exit(126)`) |
| SML-004 | Moderate | **Fixed** (web refuses start without bearer) |
| SML-005 | Moderate | **Fixed** (CGNAT + expanded private ranges; minor residual below) |
| SML-006 | Moderate | **Partially fixed** (MCP sandboxed, but apply result ignored) |
| SML-007 | Low | **Fixed** (`cwd` uses resolved path) |
| SML-008 | Low | **Fixed** (timing-safe bearer compare) |

**This engagement promotes 3 open formal findings** (2 Elevated, 1 Moderate) plus residual notes. Security posture is **substantially improved** since `a1135e9` (fail-closed sandbox for exec, mandatory web bearer, richer SSRF, operator docs, many security tests). Residual risk remains concentrated on **unattended gateway + incomplete denylist + open DM defaults** for stock (non-strict) builds — consistent with the project’s own `docs/operations/gateway-threat-model.md`.

## 1.6 Summary of Findings

| ID | Level | Type | Description | Status |
|----|-------|------|-------------|--------|
| SML-001 | Elevated | CWE-1188 | Stock default channel `dm_policy` is `open` (`SC_STRICT_SECURITY` off by default) | open |
| SML-002 | Elevated | CWE-78 / CWE-184 | Gateway always auto-confirms tools; denylist allows interpreter files & curl upload forms | open |
| SML-006 | Moderate | CWE-755 | MCP child calls `sc_sandbox_apply` but ignores failure (fail-open for MCP) | open |

### 1.6.1 By threat level

| Level | Count |
|-------|------:|
| Elevated | 2 |
| Moderate | 1 |
| Low | 0 (promoted) |

### 1.6.2 Closed since prior audit

SML-003, SML-004, SML-005 (core), SML-007, SML-008 — see §5 Non-Findings.

## 1.7 Summary of Recommendations

| ID | Recommendations |
|----|-----------------|
| SML-001 | Default stock builds to `allowlist`/`pairing`, or default-on `SC_STRICT_SECURITY`; refuse gateway start for open DM with empty `allow_from` without explicit override |
| SML-002 | Expand denylist (interpreter scripts, curl `-T`/`-F`/`--data-binary`); prefer `exec_mode=allowlist` for gateway; optional confirm policy for dangerous tools; mandatory tool allowlists for web companion |
| SML-006 | On MCP sandbox apply failure, `_exit(126)` like exec children (unless `no_sandbox` explicitly set) |

---

# 2 Methodology

## 2.1 Planning

1. Inventory HEAD vs prior audit commit.  
2. Threat model (agent/gateway trust boundary).  
3. Grep sinks; read config defaults, exec_common, sandbox, web SSRF/auth, MCP, shell.  
4. POSIX ERE denylist probe against known bypass commands.  
5. Retest each prior SML-ID; promote residual issues only.

## 2.2 Risk Classification

PTES: Extreme / High / Elevated / Moderate / Low.

## 2.3 Known limitations

- Standard depth (no overnight fuzz).  
- Not CodeQL.  
- Denylist probe is representative, not exhaustive.  
- `SC_STRICT_SECURITY` behavior verified via Kconfig/source, not a full strict rebuild in this session.

---

# 3 Reconnaissance and Fingerprinting

See `artifacts/recon.md`, `artifacts/detect-stack.txt`, `artifacts/deny-probe.txt`, `artifacts/cloc-src.txt`.

| Item | Value |
|------|--------|
| HEAD | `bb0e27c` |
| `src/` size | ~44k code lines (111 `.c` + 120 headers) |
| Security docs | `docs/SECURITY.md`, `docs/operations/gateway-threat-model.md` |

---

# 4 Findings

## 4.1 SML-001 — Stock DM policy still defaults to open

| Field | Value |
|-------|-------|
| Vulnerability ID | SML-001 |
| Vulnerability type | CWE-1188: Insecure Default Initialization of Resource |
| Threat level | Elevated |

### Description

Unless compiled with `SC_STRICT_SECURITY`, factory defaults set every network channel’s `dm_policy` to `"open"`.

### Technical description

`src/config.c` (~856–898):

```c
#if SC_STRICT_SECURITY
    const char *default_dm = "allowlist";
    cfg->exec_use_allowlist = 1;
#else
    const char *default_dm = "open";
#endif
/* telegram/discord/irc/slack/x/signal/web all get default_dm */
```

`Kconfig`: `SC_STRICT_SECURITY` **defaults to `n`** (help text documents open/allowlist tradeoff).

`sc_channel_is_allowed()` still allows all senders when allow list is empty and policy is OPEN.

Improvement vs `a1135e9`: strict mode exists; docs honest about stock vs strict.

### Steps to reproduce

1. Build without `SC_STRICT_SECURITY`.  
2. Enable Telegram (or other channel) with token; leave `dm_policy` unset.  
3. Message bot from arbitrary sender → accepted.

### Impact

Any party who can reach an enabled channel can drive the unattended agent (especially with SML-002).

### Recommendation

- Flip stock default to `allowlist` or default-enable `SC_STRICT_SECURITY` for release builds.  
- Gateway startup gate: open + empty `allow_from` requires explicit override flag.  
- Keep strict mode as the documented production path.

---

## 4.2 SML-002 — Gateway auto-confirm + incomplete exec denylist

| Field | Value |
|-------|-------|
| Vulnerability ID | SML-002 |
| Vulnerability type | CWE-78 / CWE-184 |
| Threat level | Elevated |

### Description

`smolclaw gateway` always registers `gateway_auto_confirm` (approve-all). The shared denylist (~90 patterns) still **allows** script-file interpreters and several curl upload/exfil forms. Containment relies on Landlock (when applied) and operator tool allowlists.

### Technical description

**Gateway** (`src/main.c` ~2172–2173):

```c
/* Gateway auto-approves tools — deny patterns and allowlist are the guards */
sc_tool_registry_set_confirm(agent->tools, gateway_auto_confirm, NULL);
```

Project docs (`docs/operations/gateway-threat-model.md`) state operators must not rely on `auto_confirm: false` in gateway — always auto-approves.

**Denylist probe** (POSIX ERE against current `deny_patterns.h`, artifact `deny-probe.txt`):

| Command | Result |
|---------|--------|
| `python3 -c '…'` | BLOCK |
| `python3 ./evil.py` | **ALLOW** |
| `node evil.js` | **ALLOW** |
| `perl`/`ruby`/`php`/`lua` scripts | **ALLOW** |
| `curl … -T` / `--data-binary @` / `-F` / `--upload-file` | **ALLOW** |
| `gcc -o x x.c` / `./x` | **ALLOW** |
| `rm -rf /` / `python3 -c` / `cat /etc/passwd` | BLOCK |

**Exec path** still ends in `execle("/bin/sh", "sh", "-c", …)` after guards (`exec_common.c`).

Improvements vs prior: async-signal-safe prep, sandbox fail-closed for exec (SML-003 fixed), tool-covered command block list, more patterns, operator documentation.

### Steps to reproduce

1. Run deny probe or gateway with `exec` enabled.  
2. Confirm `python3 ./evil.py` is not denied.  
3. In gateway, note no human confirm for `exec` / `write_file`-class tools (file tools no longer need confirm per SECURITY.md — deny/allowlist only).

### Impact

Authenticated or open-channel callers can coerce the LLM into write-script + run-interpreter or curl-upload exfil within Landlock/workspace bounds (network often still allowed from sandbox). Web bearer + tool allowlist reduce exposure when configured; stock multi-channel open DM + full tools remains high risk.

### Recommendation

- Expand denylist: bare `python[23]?`, `node`, `perl`, `ruby`, `php`, `lua` without requiring `-c`/`-e`; curl upload flags; optionally `gcc`/`clang`.  
- Prefer structural: argv allowlist, no shell.  
- Gateway: configurable confirm policy for dangerous tools (already noted as future work in gateway-threat-model).  
- Production: mandatory `allowed_tools` / per-channel tool lists + `exec_mode=allowlist` + `SC_STRICT_SECURITY`.

---

## 4.3 SML-006 — MCP sandbox apply failure is ignored

| Field | Value |
|-------|-------|
| Vulnerability ID | SML-006 |
| Vulnerability type | CWE-755: Improper Handling of Exceptional Conditions |
| Threat level | Moderate |

### Description

MCP server children now call `sc_sandbox_apply()`, improving on the prior “no sandbox” finding, but the return value is ignored — sandbox failure still proceeds to `execvp`.

### Technical description

`src/mcp/client.c` (~352–375): builds `sandbox_opts`, then:

```c
sc_sandbox_apply(&sandbox_opts);  /* return not checked */
setenv("TMPDIR", tmpdir, 1);
…
execvp(argv[0], argv);
```

Contrast **exec children** (`src/tools/exec_common.c` ~380–385), which correctly fail closed:

```c
if (sc_sandbox_apply(&sandbox_opts) != 0) {
    … _exit(126);
}
```

`capabilities.sandbox=false` / `no_sandbox` intentionally opts out for trusted multi-process servers (e.g. npx) — that path is by design; the bug is silent failure when sandbox was requested.

### Steps to reproduce

1. Configure an MCP server with sandbox intended (default path with workspace).  
2. Force Landlock/seccomp failure (unsupported kernel or policy).  
3. Observe child still execs (logs may warn; process continues unrestricted FS-wise beyond env scrub).

### Impact

Operators may believe MCP is sandboxed when it is not. Severity lower than exec fail-open was, because MCP commands are local config (trusted operator) rather than LLM-chosen shell strings — still a real fail-open for defense-in-depth.

### Recommendation

Mirror exec: if sandbox was requested and `sc_sandbox_apply != 0`, `_exit(126)`. Only skip apply when `no_sandbox` is explicit.

---

# 5 Non-Findings

## 5.1 NF-001 — Threat model

See `artifacts/threat-model.md`. Residual: unattended LLM tool loop is inherent; stock convenience defaults remain the main outer-perimeter risk.

## 5.2 NF-RET-003 — Prior SML-003 fixed (sandbox fail-closed for exec)

`sc_exec_child` refuses to execute if sandbox apply fails (`_exit(126)`). Async-signal-safe prep moved to parent. **Closed.**

## 5.3 NF-RET-004 — Prior SML-004 fixed (web bearer required)

`web_start` refuses empty bearer (`channels/web.c` ~1639–1642). Manager/companion also gate on token. Timing-safe compare via `sc_web_check_bearer_auth` / `sc_timing_safe_cmp`. **Closed** (prior SML-008 also closed by same change).

## 5.4 NF-RET-005 — Prior SML-005 largely fixed (SSRF ranges)

`is_private_ipv4` now includes CGNAT `100.64/10`, TEST-NETs, multicast, reserved, etc.; IPv6 NAT64/6to4 private embeds handled. Network scope (`public`/`local`/`none`/`any`) added.  

**Residual (not promoted):** `198.18.0.0/15` (benchmark) still classifies as public in a manual reimplementation of the range checks — Low priority special-use gap.

## 5.5 NF-RET-007 — Prior SML-007 fixed (working_dir)

`shell.c` sets `cwd = resolved_cwd` after `sc_validate_path` when restricted. **Closed.**

## 5.6 NF-002 — Positive controls on HEAD

- Mandatory web bearer + rate limit on `/api/message` (IP + token hash).  
- Exec sandbox fail-closed; Landlock/seccomp; close_range FD cleanup.  
- Expanded deny list (~90), normalization, tool-covered command block.  
- Optional `SC_STRICT_SECURITY` (allowlist DM + exec allowlist).  
- Gateway threat model documentation.  
- Large `test_security*` / sandbox / web_auth coverage (see SECURITY.md).  
- Secret redaction, CDATA tool wrap, pairing, vault, network_scope.

## 5.7 NF-003 — xai_oauth `system()` browser open

`src/util/xai_oauth.c` uses `system()` with `xdg-open '…'` for local OAuth browser launch. URL comes from OIDC discovery validated to x.ai endpoints. Not a remote unauthenticated sink; residual shell metacharacter risk is low if validation holds. **Not promoted.**

## 5.8 NF-004 — Fuzz

Standard depth: no AFL campaign this pass. Harnesses from prior deep audit can be rebuilt against this tree if desired.

---

# 6 Future Work

- Retest after denylist expansion / gateway confirm policy.  
- Fail-closed MCP sandbox.  
- Default-on strict security for release artifacts.  
- Overnight AFL on IRC/path/deny against current sources.  
- Add `198.18.0.0/15` to SSRF blocklist if relevant to deployments.

---

# 7 Conclusion

Moving from `a1135e9` to `bb0e27c`, smolclaw **closed most moderate/low audit items** with serious engineering (sandbox fail-closed, web auth, SSRF expansion, docs, tests). The **two elevated residual issues** are the same systemic themes as before: **open stock DM defaults** and **gateway auto-confirm + incomplete denylist**. A third moderate residual is **MCP sandbox fail-open on apply error**.

Production deployments should use `SC_STRICT_SECURITY` (or equivalent config: allowlist DMs, exec allowlist, tool allowlists, sandbox on, loopback web + bearer) and treat gateway exposure as shell-equivalent for authenticated/open-channel users.

---

# Appendix A — Testing Team

| Role | Who |
|------|-----|
| Analyst | crystal-box-audit |
| Prior baseline | `2026-07-12-a1135e9` report |

# Appendix B — Artifact index

| Path | Description |
|------|-------------|
| `artifacts/threat-model.md` | Threat model |
| `artifacts/recon.md` | Inventory |
| `artifacts/detect-stack.txt` | Tools/langs |
| `artifacts/deny-probe.txt` | ERE allow/block results |
| `artifacts/cloc-src.txt` | src/ LOC |
| `artifacts/commands.log` | Session log |
| `../2026-07-12-a1135e9/REPORT.md` | Prior baseline |

# Appendix C — Finding ID log

| ID | Title | Level | Primary location |
|----|-------|-------|------------------|
| SML-001 | Open DM defaults (stock) | Elevated | `config.c` ~856–898; `Kconfig` SC_STRICT_SECURITY |
| SML-002 | Gateway auto-confirm + denylist gaps | Elevated | `main.c` ~2172; `deny_patterns.h` |
| SML-006 | MCP sandbox ignore failure | Moderate | `mcp/client.c` ~373 |

# Appendix D — Prior finding disposition

| ID | Disposition |
|----|-------------|
| SML-001 | Open (refined) |
| SML-002 | Open (refined) |
| SML-003 | Fixed |
| SML-004 | Fixed |
| SML-005 | Fixed (minor residual range not promoted) |
| SML-006 | Partial → open residual |
| SML-007 | Fixed |
| SML-008 | Fixed |
