# Penetration Test Report

**Target:** smolclaw  
**Repository:** `https://github.com/magnusmalm/smolclaw.git`  
**Local path:** `/home/user/devel/smolclaw`  
**Commit / tag:** `a1135e9c15b393b83bb11421fb3c4d77af662e91`  
**Version:** 1.0  
**Date:** 2026-07-12  
**Engagement type:** Crystal-box security code review (agent-assisted, ROS-style)  
**Depth mode:** standard  
**Classification:** Private / Internal  
**Authors:** Grok crystal-box-audit skill (agent-assisted)  
**Finding ID prefix:** SML  

## Document Properties

| Field | Value |
|-------|-------|
| Client / owner | magnus |
| Title | Penetration Test Report — smolclaw |
| Target summary | C11 multi-channel AI agent with shell/filesystem/web tools and OS sandbox |
| Tools available | cloc, rg, git, clang, POSIX regex (custom deny probe) |
| Tools missing | semgrep, codeql, afl-fuzz, trivy |
| PDF-method gaps acknowledged | See §2.3 |

## Version control

| Version | Date | Author | Description |
|---------|------|--------|-------------|
| 0.1 | 2026-07-12 | crystal-box-audit | Initial draft |
| 1.0 | 2026-07-12 | crystal-box-audit | Delivered standard-depth report |

---

# 1 Executive Summary

## 1.1 Introduction

On 2026-07-12, a crystal-box security review was performed against **smolclaw** (Gitea `magnus/smolclaw`) at commit `a1135e9c`.

## 1.2 Scope of Work

- **In scope:** Source under `src/` (agent, tools, channels, util security modules), security-relevant config defaults, deny-pattern effectiveness probe.
- **Out of scope:** Live production gateway traffic, long-running AFL campaigns, third-party model providers’ security, full dependency CVE database, vendored sqlite internals beyond use sites.
- **Effort:** Standard agent-assisted depth (hours, not multi-day human ROS engagement).

## 1.3 Project Objectives

Assess whether smolclaw’s layered defenses (DM policy, tool confirmation, exec denylist, Landlock/seccomp, SSRF, path checks, secret redaction) hold against realistic attacker models: unsolicited channel users, prompt injection, and LLM-coerced tool use in **gateway** mode.

## 1.4 Timeline

Single-session review: 2026-07-12.

## 1.5 Results In A Nutshell

During this crystal-box review we found **0 Extreme, 0 High, 2 Elevated, 4 Moderate, 2 Low** issues.

smolclaw has **substantial, intentional security engineering** (deny lists, sandbox, SSRF with DNS pinning and redirect re-check, CDATA tool-output wrapping, secret redaction, pairing, sensitive-path blocks). The residual risk concentrates on **defaults and fail-open behavior for unattended operation**:

1. **Channel DM policy defaults to `open`**, so any party who can reach a configured bot can drive the agent unless the operator hardens config.
2. **Gateway mode auto-approves all `needs_confirm` tools**, relying on denylist + sandbox. POSIX ERE probing shows the denylist **does not block** scripted interpreters (`python3 file.py`, `node file.js`, …) or several **curl upload/exfil forms** (`-T`, `--data-binary @`, `-F`). Containment then depends almost entirely on Landlock/seccomp (which still allow **outbound network**).
3. **Sandbox apply failures are ignored** in the child before `exec`, so degraded kernels silently lose FS/syscall restrictions while still running `sh -c`.
4. Secondary issues: optional open Web API without bearer token, incomplete private-IP ranges for SSRF (e.g. CGNAT `100.64.0.0/10`), unsandboxed MCP children, minor path/timing issues.

**Highest priority:** change safe defaults for DM policy and gateway confirmation, expand denylist or switch default exec to allowlist, fail closed if sandbox cannot apply, require web bearer token.

## 1.6 Summary of Findings

| ID | Level | Type (CWE) | Description | Status |
|----|-------|------------|-------------|--------|
| SML-001 | Elevated | CWE-1188: Insecure Default Initialization of Resource | Channel `dm_policy` defaults to `open` for all network channels | open |
| SML-002 | Elevated | CWE-78 / CWE-184 | Gateway auto-confirm + incomplete exec denylist enables scripted interpreter & curl exfil paths | open |
| SML-003 | Moderate | CWE-755: Improper Handling of Exceptional Conditions | `sc_sandbox_apply` return value ignored; sandbox can fail open | open |
| SML-004 | Moderate | CWE-306: Missing Authentication for Critical Function | Web channel treats empty bearer token as open access | open |
| SML-005 | Moderate | CWE-918: Server-Side Request Forgery | SSRF private-range blocklist incomplete (e.g. 100.64/10) | open |
| SML-006 | Moderate | CWE-250: Execution with Unnecessary Privileges | MCP server children not sandboxed (Landlock/seccomp) | open |
| SML-007 | Low | CWE-59 / CWE-22 class | `exec` `working_dir` validated then discarded; `chdir` uses original string | open |
| SML-008 | Low | CWE-208: Observable Timing Discrepancy | Web bearer compared with `strcmp`, not timing-safe | open |

### 1.6.1 Findings by Threat Level

| Level | Count |
|-------|------:|
| Extreme | 0 |
| High | 0 |
| Elevated | 2 |
| Moderate | 4 |
| Low | 2 |

### 1.6.2 Findings by Type

- Insecure defaults / missing auth (SML-001, SML-004)
- Incomplete neutralization / denylist (SML-002)
- Fail-open security control (SML-003)
- SSRF range gaps (SML-005)
- Privilege / sandbox scope (SML-006)
- Path / timing nits (SML-007, SML-008)

## 1.7 Summary of Recommendations

| ID | Level | Recommendations |
|----|-------|-----------------|
| SML-001 | Elevated | Default `dm_policy` to `allowlist` or `pairing`; refuse gateway start for open policy without explicit `--i-accept-open-dms` |
| SML-002 | Elevated | Prefer exec allowlist in gateway; expand denylist for interpreters-without-flags and curl upload forms; optional re-prompt for confirm in gateway |
| SML-003 | Moderate | If sandbox enabled and `sc_sandbox_apply` fails, `_exit` child rather than exec |
| SML-004 | Moderate | Fail start if web enabled and bearer empty; never open-auth |
| SML-005 | Moderate | Block CGNAT, benchmark, and other special-use ranges; consider IP policy library |
| SML-006 | Moderate | Apply same sandbox to MCP children or document as trusted-only |
| SML-007 | Low | `chdir` to resolved path; keep ownership of validated string |
| SML-008 | Low | Use `sc_timing_safe_cmp` for bearer tokens |

---

# 2 Methodology

## 2.1 Planning

Phases executed (library/agent-adapted; not network host scanning):

1. **Reconnaissance** — inventory, architecture, `docs/SECURITY.md`, stack detect  
2. **Enumeration** — trust boundaries (channels, tools, config defaults)  
3. **Scanning** — `rg` sinks, custom POSIX ERE denylist probe (semgrep/CodeQL unavailable)  
4. **Validation** — code-path confirmation for each promoted finding; deny-probe binary against candidate bypasses  

## 2.2 Risk Classification

PTES-style labels: Extreme, High, Elevated, Moderate, Low  
(see http://www.pentest-standard.org/index.php/Reporting)

## 2.3 Known limitations (mandatory)

- Method adapted from public ROS raylib PDF structure, not ROS internal playbooks.  
- **Not equivalent** to a multi-day human pentest or ~200h fuzz campaign.  
- Missing tools: semgrep, CodeQL, AFL++.  
- No full ASAN build of smolclaw in this session; validation is static + isolated regex probe.  
- LLM coercion and model-level jailbreaks are residual by nature of the product.  
- Deny-list is infinite-surface by design; probe is representative, not exhaustive.

---

# 3 Reconnaissance and Fingerprinting

See `artifacts/recon.md` and `artifacts/detect-stack.txt`.

Automated / manual scans:

| Tool | Notes |
|------|--------|
| cloc | Language / LOC summary |
| ripgrep | Sinks: system/exec/fork, path, auth |
| Custom C deny probe | `/tmp/test_deny` style against `deny_patterns.h` ERE |
| Manual review | shell, exec_common, sandbox, web SSRF, web channel, MCP, config defaults, registry confirm |

Relevant probe output: `artifacts/deny-probe.txt`.

---

# 4 Findings

## 4.1 SML-001 — Channel DM policy defaults to open

| Field | Value |
|-------|-------|
| Vulnerability ID | SML-001 |
| Vulnerability type | CWE-1188: Insecure Default Initialization of Resource |
| Threat level | Elevated |

### Description

Factory defaults set every network channel’s `dm_policy` string to `"open"`, allowing all senders when the allow list is empty.

### Technical description

In `src/config.c` (defaults around lines 590–609):

```c
cfg->telegram.dm_policy = sc_strdup("open");
cfg->discord.dm_policy = sc_strdup("open");
cfg->irc.dm_policy = sc_strdup("open");
cfg->slack.dm_policy = sc_strdup("open");
cfg->web.dm_policy = sc_strdup("open");
```

`sc_channel_is_allowed()` (`src/channels/base.c:19–22`) returns **allow-all** when the allow list is empty and policy is OPEN:

```c
if (ch->allow_list_count == 0 || !ch->allow_list) {
    return (ch->dm_policy == SC_DM_POLICY_OPEN) ? 1 : 0;
}
```

Note: `sc_dm_policy_from_str(NULL)` fails closed to allowlist (`src/pairing.c:162`), and `docs/SECURITY.md` describes allowlist as the default — **documentation and code disagree**. Comments in `pairing.h` also call OPEN the backward-compat default.

### Steps to reproduce

1. Onboard with a channel token (e.g. Telegram) without setting `dm_policy` / `allow_from`.  
2. Start `smolclaw gateway`.  
3. Message the bot from an arbitrary account not on any allow list.  
4. Observe the message is accepted and processed by the agent.

### Impact

Any internet user who can reach the bot identity can send prompts that drive tools (especially under gateway auto-confirm — SML-002). Combined with open tools, this is the primary remote trust boundary failure for multi-channel deployments.

### Recommendation

- Change factory defaults to `"allowlist"` or `"pairing"`.  
- On gateway start, if any enabled channel is OPEN with empty allow list, **warn loudly or refuse** unless an explicit override flag is set.  
- Align `docs/SECURITY.md` with code (or fix code to match docs).

---

## 4.2 SML-002 — Gateway auto-confirm + incomplete exec denylist

| Field | Value |
|-------|-------|
| Vulnerability ID | SML-002 |
| Vulnerability type | CWE-78: OS Command Injection / CWE-184: Incomplete List of Disallowed Inputs |
| Threat level | Elevated |

### Description

Gateway mode auto-approves all tools that require confirmation. The shared exec denylist blocks many one-liners but **allows** running interpreter **files** and several **curl-based exfiltration** forms. Containment then relies on Landlock/seccomp, which still permit outbound network sockets.

### Technical description

**Auto-confirm** (`src/main.c:948–953`, wired at ~1145):

```c
static int gateway_auto_confirm(const char *tool, const char *args, void *ctx)
{
    (void)tool; (void)args; (void)ctx;
    return 1;
}
```

Comment in source: “deny patterns and allowlist are the guards.”

**Exec path** always ends in (`src/tools/exec_common.c:216`):

```c
execle("/bin/sh", "sh", "-c", command, (char *)NULL, envp);
```

**POSIX ERE probe** against `src/tools/deny_patterns.h` (artifact `deny-probe.txt`) — representative results:

| Command | Result |
|---------|--------|
| `python3 -c '…'` | BLOCK |
| `python3 ./evil.py` | **ALLOW** |
| `node evil.js` | **ALLOW** |
| `perl evil.pl` / `ruby evil.rb` / `php evil.php` / `lua evil.lua` | **ALLOW** |
| `gcc -o x x.c` / `./x` | **ALLOW** |
| `curl … -d @file` | BLOCK |
| `curl … -T file` / `--data-binary @` / `-F f=@` / `--upload-file` | **ALLOW** |
| `busybox wget …` | **ALLOW** (unless other patterns hit) |

Attack chain in gateway + open DM (SML-001):

1. Adversary prompts agent to `write_file` a Python script (auto-approved).  
2. Agent `exec` runs `python3 that_script.py` (not denied).  
3. Script uses sockets to exfil workspace data (Landlock allows network; workspace is RW).  
4. Alternatively use allowed `curl -T` / multipart upload forms.

CLI mode mitigates via interactive confirm; gateway does not.

### Steps to reproduce

1. Build smolclaw; configure gateway with exec tool enabled and denylist mode (default).  
2. Compile deny probe (or call `sc_exec_guard_command` via tests) for `python3 ./evil.py` — expect not blocked.  
3. Optionally run under gateway: instruct model to write and execute a workspace script that `urllib` POSTs a file to an external host (sandbox permitting).  
4. Confirm Landlock does not block `connect()`.

### Impact

Unattended gateway + remote chatter ≈ **LLM-mediated remote tool RCE** inside the agent’s sandbox. Workspace confidentiality/integrity and outbound exfiltration are realistic; full host compromise is reduced if Landlock works, increased if sandbox fails open (SML-003) or is disabled.

### Recommendation

- **Default gateway** to `exec_mode=allowlist` with a tight command set, or disable `exec` / `exec_background` unless explicitly enabled.  
- Expand denylist: block `python[23]?` / `node` / `perl` / `ruby` / `php` / `lua` **without** requiring `-c`/`-e`; block `curl` upload flags (`-T`, `--upload-file`, `--data-binary`, `-F`); treat compiled `./a.out` / `gcc` as high risk.  
- Prefer structural fix: no shell — argv array allowlist only.  
- Optional: gateway confirm via pairing owner channel, or “dangerous tools require second channel approval.”  
- Document residual risk: denylists are never complete.

---

## 4.3 SML-003 — Sandbox apply failure is non-fatal

| Field | Value |
|-------|-------|
| Vulnerability ID | SML-003 |
| Vulnerability type | CWE-755: Improper Handling of Exceptional Conditions |
| Threat level | Moderate |

### Description

When sandbox is enabled, the child calls `sc_sandbox_apply()` but ignores its return value and continues to `execle("/bin/sh", …)`.

### Technical description

`src/tools/exec_common.c:202–216`:

```c
if (sandbox_enabled) {
    sc_sandbox_opts_t sandbox_opts = {
        .workspace = workspace,
        .tmpdir = NULL,
    };
    sc_sandbox_apply(&sandbox_opts);  /* return value ignored */
}
…
execle("/bin/sh", "sh", "-c", command, (char *)NULL, envp);
```

Inside `sc_sandbox_apply` (`src/util/sandbox.c`), Landlock or seccomp failures log warnings and return `-1`, but still fall through. If `PR_SET_NO_NEW_PRIVS` fails, apply returns `-1` early with **no** restrictions.

Background exec uses the same helper.

### Steps to reproduce

1. Build/run on a kernel without Landlock (or force `landlock` failure).  
2. Enable `agents.defaults.sandbox: true`.  
3. Execute a command that would be blocked by Landlock (e.g. read outside workspace via shell if denylist misses).  
4. Observe command still runs; logs may show sandbox warnings.

### Impact

Operators believe sandbox is on while children run with only denylist + env scrub. Amplifies SML-002 when Landlock/seccomp unavailable (older kernels, containers without support, misconfigured seccomp).

### Recommendation

```c
if (sandbox_enabled) {
    if (sc_sandbox_apply(&sandbox_opts) != 0)
        _exit(126); /* refuse to run unrestricted */
}
```

Optionally distinguish “soft” vs “hard” sandbox in config; default hard.

---

## 4.4 SML-004 — Web API open when bearer token empty

| Field | Value |
|-------|-------|
| Vulnerability ID | SML-004 |
| Vulnerability type | CWE-306: Missing Authentication for Critical Function |
| Threat level | Moderate |

### Description

If Web channel is enabled without a bearer token, authentication always succeeds.

### Technical description

`src/channels/web.c:113–126`:

```c
static int check_auth(struct evhttp_request *req, const web_data_t *wd)
{
    if (!wd->bearer_token || !wd->bearer_token[0])
        return 1; /* No token configured = open */
    …
}
```

Default bind is `127.0.0.1` (`config.c` / web channel constructor), which limits remote exposure. Binding `0.0.0.0` without a token makes the agent API world-open. Header comment in `config.h` says bearer is “required,” but runtime does not enforce it.

### Steps to reproduce

1. Enable web channel with empty `bearer_token`, bind `127.0.0.1`.  
2. `curl -X POST http://127.0.0.1:<port>/api/message -H 'Content-Type: application/json' -d '{"message":"hi"}'` without Authorization.  
3. Request is accepted (auth check returns success).

### Impact

Local users/processes can drive the agent without a secret. Misconfiguration to non-loopback bind yields remote unauthenticated access to the full agent tool surface (with SML-001/002).

### Recommendation

- Refuse to start web channel if bearer is missing/empty.  
- Generate a random token at onboard and print it once.  
- Keep default bind loopback; warn if bind is non-local.

---

## 4.5 SML-005 — Incomplete SSRF private address coverage

| Field | Value |
|-------|-------|
| Vulnerability ID | SML-005 |
| Vulnerability type | CWE-918: Server-Side Request Forgery |
| Threat level | Moderate |

### Description

`web_fetch` SSRF checks block major RFC1918 and link-local ranges but miss several special-use ranges commonly used in cloud/private networks (notably CGNAT `100.64.0.0/10`).

### Technical description

`src/tools/web.c` `is_private_ipv4()` (~684–699) blocks: `127/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `0.0.0.0`.

Not blocked (examples):

- `100.64.0.0/10` (CGNAT / many cloud internal meshes)  
- `198.18.0.0/15` (benchmark)  
- Other special-use prefixes depending on deployment  

Positive controls present: hostname metadata block, `getaddrinfo` dual-stack checks, DNS pinning via resolve, manual redirect loop with per-hop re-check, `SC_TEST_DISABLE_SSRF` for tests only.

### Steps to reproduce

1. Point `web_fetch` at a host that resolves only to `100.64.x.x` (lab DNS).  
2. Observe fetch not rejected by `is_private_ipv4`.  
3. Confirm production code path does not set `SC_TEST_DISABLE_SSRF`.

### Impact

In environments where sensitive services sit on CGNAT or similar ranges, the LLM/`web_fetch` tool can reach them, enabling internal reconnaissance or metadata-like services not on classic RFC1918.

### Recommendation

- Expand blocklist (CGNAT, documentation, benchmarking, multicast as appropriate).  
- Prefer a maintained “is public IP” helper.  
- Optional allowlist of destinations for fetch.

---

## 4.6 SML-006 — MCP children run without OS sandbox

| Field | Value |
|-------|-------|
| Vulnerability ID | SML-006 |
| Vulnerability type | CWE-250: Execution with Unnecessary Privileges |
| Threat level | Moderate |

### Description

MCP server processes are forked/exec’d with env scrubbing and FD close, but **without** Landlock/seccomp applied to exec tool children.

### Technical description

`src/mcp/client.c` child path (~246–297): closes FDs, unsets `LD_PRELOAD`/etc., `execvp(argv[0], argv)`. No `sc_sandbox_apply`.

MCP command lines come from **local configuration** (trusted operator), not raw chat. Risk is: malicious or buggy MCP package + broad FS/network access equal to the smolclaw user, plus any tools MCP exposes back into the agent.

### Steps to reproduce

1. Configure an MCP server that runs a shell.  
2. Confirm process is not landlocked (e.g. can read paths outside workspace).  
3. Compare to `exec` tool child with sandbox on.

### Impact

Configured MCP servers inherit full user privileges (minus scrubbed env). Supply-chain or confused-deputy MCP tools can exceed workspace tool restrictions.

### Recommendation

- Apply the same sandbox helper to MCP children where feasible.  
- Document MCP as “fully trusted code.”  
- Optional: run MCP under a dedicated user/container.

---

## 4.7 SML-007 — working_dir validated then discarded

| Field | Value |
|-------|-------|
| Vulnerability ID | SML-007 |
| Vulnerability type | CWE-22 / TOCTOU-adjacent path handling |
| Threat level | Low |

### Description

For `exec`, when `restrict_to_workspace` is set, `working_dir` is validated with `sc_validate_path`, the resolved path is freed, and `chdir` later uses the **original** string.

### Technical description

`src/tools/shell.c:183–191`:

```c
if (working_dir && *working_dir) {
    if (d->restrict_to_workspace) {
        char *resolved_wd = sc_validate_path(...);
        if (!resolved_wd)
            return sc_tool_result_error("working_dir outside workspace");
        free(resolved_wd);
    }
    cwd = working_dir;  /* original, not resolved */
}
```

### Steps to reproduce

1. Code review as above.  
2. Pass a path that validates now but could race (symlink swap) before `chdir` — theoretical TOCTOU.

### Impact

Low under normal conditions (`realpath` already followed links at validation time; race window is narrow). Still incorrect ownership of the security decision (validated ≠ used).

### Recommendation

Keep `resolved_wd` and pass it to `sc_exec_child` / `chdir`.

---

## 4.8 SML-008 — Web bearer token compared without constant-time equality

| Field | Value |
|-------|-------|
| Vulnerability ID | SML-008 |
| Vulnerability type | CWE-208: Observable Timing Discrepancy |
| Threat level | Low |

### Description

Web auth uses `strcmp` on the bearer secret; the codebase already has `sc_timing_safe_cmp` used for pairing.

### Technical description

`src/channels/web.c:125`:

```c
return strcmp(auth + 7, wd->bearer_token) == 0;
```

### Steps to reproduce

Code inspection; theoretical remote timing against localhost-bound service is hard.

### Impact

Low practical exploitability on loopback; more relevant if web is exposed with TLS on the open internet.

### Recommendation

Use `sc_timing_safe_cmp(auth + 7, wd->bearer_token) == 0` after length-aware checks.

---

# 5 Non-Findings

## 5.1 NF-001 — Threat Model

See `artifacts/threat-model.md` (finalized).

**Did we do a good enough job?** Adequate for standard depth on the agent/tool boundary and defaults. Not a substitute for continuous security tests (`test_security_prod`) or long fuzzing of parsers (IRC, JSON, websocket).

## 5.2 NF-002 — Positive controls observed

The following were reviewed and appear **intentional, strong design** (not promoted as findings):

- Exec uses `execle` + sanitized env; FD cloexec loop; process group kill on timeout.  
- ~80+ deny patterns with normalization (newlines → `;`, strip non-ASCII).  
- Landlock path policy + seccomp denylist for dangerous syscalls.  
- Filesystem: symlink reject, bootstrap file lock, sensitive path blocklist, size caps.  
- SSRF: dual-stack resolve, pin, redirect revalidation, scheme allowlist.  
- Tool output CDATA wrap + `]]>` split; secret redaction on tool I/O and outbound LLM text.  
- Pairing codes with entropy + timing-safe compare API.  
- Config/session modes 0600; config permission warnings.  
- Git tool uses `execvp` without shell; limited subcommands.  
- Rate limiting per channel/chat.  

## 5.3 NF-003 — Areas probed without formal finding

- **Classic stack buffer overflows** in first-pass C review: widespread use of bounded reads/`sc_strbuf`; no high-confidence CLN-style overflow promoted without ASAN campaign.  
- **Hardcoded production API keys** in `src/`: none found (only test/placeholder `not_required` for ollama).  
- **Prompt guard** is detection/warning only by design; CDATA is primary — residual model jailbreak is product-inherent, not a single code bug.  

## 5.4 NF-004 — Fuzz / dynamic testing notes

No AFL++ campaign in this engagement. Host lacks `afl-fuzz`. Recommend future harnesses for IRC line parser, JSON tool args, path validation, and deny normalizer.

---

# 6 Future Work

- Retest after default and sandbox fail-closed changes.  
- Expand `test_security_prod` with interpreter-file and curl-upload cases (currently one-liner focused).  
- Install semgrep/CodeQL for continuous CI.  
- Long-running fuzz on channel parsers.  
- Consider network namespace / landlock net restrictions for exec children if kernel supports.  
- Review MCP tool surface with least privilege.  

---

# 7 Conclusion

smolclaw’s security posture is **above average for a personal AI agent codebase**: multiple defense layers are real and tested in-project. The critical systemic pattern is **unattended gateway trust**: open DM defaults plus auto-confirm plus an incomplete denylist shift almost all residual risk onto Landlock — which is fail-open and network-permissive.

Immediate remediation order:

1. **SML-001** safe DM defaults  
2. **SML-002** gateway tool policy / denylist / allowlist  
3. **SML-003** sandbox fail-closed  
4. **SML-004–006** web auth, SSRF ranges, MCP sandbox  
5. **SML-007–008** cleanup  

This report is a **one-time snapshot**, not continuous assurance. Security for LLM agents must be revalidated as tools and defaults change.

---

# Appendix A — Testing Team

| Role | Who |
|------|-----|
| Analyst | crystal-box-audit (Grok agent) |
| Reviewer | (pending human) |

# Appendix B — Artifact index

| Path | Description |
|------|-------------|
| `artifacts/threat-model.md` | Threat model |
| `artifacts/recon.md` | Inventory |
| `artifacts/detect-stack.txt` | Stack/tool detection |
| `artifacts/deny-probe.txt` | ERE denylist allow/block results |
| `artifacts/commands.log` | Command log |
| `artifacts/source-files.txt` | Source file list |
| `artifacts/secrets-grep.txt` | High-signal secret grep |

# Appendix C — Finding ID log

| ID | Title | Level | Primary location |
|----|-------|-------|------------------|
| SML-001 | Open DM policy defaults | Elevated | `src/config.c` ~590–609; `src/channels/base.c` |
| SML-002 | Gateway confirm + denylist gaps | Elevated | `src/main.c` ~948; `deny_patterns.h`; `exec_common.c` |
| SML-003 | Sandbox fail-open | Moderate | `src/tools/exec_common.c` ~202–216 |
| SML-004 | Web open without bearer | Moderate | `src/channels/web.c` ~113–118 |
| SML-005 | SSRF range gaps | Moderate | `src/tools/web.c` `is_private_ipv4` |
| SML-006 | MCP unsandboxed | Moderate | `src/mcp/client.c` child |
| SML-007 | working_dir resolve discard | Low | `src/tools/shell.c` ~183–191 |
| SML-008 | Bearer strcmp | Low | `src/channels/web.c` ~125 |
