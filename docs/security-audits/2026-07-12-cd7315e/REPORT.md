# Penetration Test Report

**Target:** smolclaw  
**Local path:** `/home/user/devel/smolclaw`  
**Repository:** `https://github.com/magnusmalm/smolclaw.git`  
**Commit:** `cd7315e4d762e39b7918c18da590630207db27ff`  
**Security remediation commit:** `15bc77b`  
**Version:** 1.0  
**Date:** 2026-07-12  
**Engagement type:** Crystal-box security code review (agent-assisted, ROS-style)  
**Depth mode:** standard (retest after remediation)  
**Classification:** Private / Internal  
**Authors:** crystal-box-audit (Grok)  
**Finding ID prefix:** SML  
**Prior report:** `docs/security-audits/2026-07-12-bb0e27c/REPORT.md`

## Document Properties

| Field | Value |
|-------|-------|
| Title | Penetration Test Report — smolclaw (post-remediation retest) |
| Scope | Verify SML-001/002/006 fixes; residual risk; related closed findings |
| Tools | rg, custom deny probe, code path review |

## Version control

| Version | Date | Description |
|---------|------|-------------|
| 1.0 | 2026-07-12 | Standard retest of `cd7315e` |

---

# 1 Executive Summary

## 1.1 Introduction

On 2026-07-12, a standard crystal-box **retest** was performed against smolclaw at `cd7315e` (includes security commit `15bc77b` and rollout helper scripts). The previous standard audit at `bb0e27c` left **SML-001, SML-002, and SML-006 open**.

## 1.2 Scope of Work

- Retest of prior formal findings against current code.  
- Deny-pattern probe against known bypasses.  
- Residual risk around lab escape hatches and gateway auto-confirm.  
- Out of scope: multi-hour AFL, full CodeQL, re-auditing unrelated modules from scratch.

## 1.5 Results In A Nutshell

**Prior elevated/moderate findings are closed** under stock defaults and normal gateway operation. No new Elevated findings.

| Prior ID | At bb0e27c | At cd7315e |
|----------|------------|------------|
| SML-001 Open DM defaults | Elevated open | **Closed** (default allowlist + quarantine) |
| SML-002 Gateway auto-confirm + denylist | Elevated open | **Closed** for start-gate + probe cases (residual Low design notes) |
| SML-003 Sandbox fail-open exec | Fixed earlier | **Still closed** |
| SML-004 Web bearer | Fixed earlier | **Still closed** |
| SML-005 SSRF ranges | Fixed earlier + 198.18 | **Still closed** |
| SML-006 MCP sandbox ignore | Moderate open | **Closed** (`_exit(126)`) |
| SML-007 working_dir | Fixed earlier | **Still closed** |
| SML-008 Bearer timing | Fixed earlier | **Still closed** |

**This engagement promotes 1 Low residual finding** (gateway auto-confirm design under allowlisted tools). Overall: **material improvement; production posture depends on not enabling lab escapes.**

## 1.6 Summary of Findings

| ID | Level | Type | Description | Status |
|----|-------|------|-------------|--------|
| SML-009 | Low | CWE-862 residual / design | Gateway still auto-approves all `needs_confirm` tools once started; mitigated by exec allowlist gate and tool allowlists | open (residual) |

### Closed this cycle (were open at bb0e27c)

SML-001, SML-002 (primary), SML-006 — see §5.

### 1.6.1 By threat level (open)

| Level | Count |
|-------|------:|
| Elevated | 0 |
| Moderate | 0 |
| Low | 1 |

## 1.7 Summary of Recommendations

| ID | Recommendation |
|----|----------------|
| SML-009 | Optional future: gateway confirm policy that denies `git`/`exec` without human when not in allowlist; or default strip `git` from needs_confirm under gateway until allowlisted |
| Ops | Never set `accept_open_dms` / `allow_unrestricted_exec` in production; keep tool allowlists tight |

---

# 2 Methodology

## 2.1 Planning

1. Confirm HEAD and remediation commits.  
2. Grep/code-read for each prior finding’s fix.  
3. POSIX ERE deny probe (105 patterns).  
4. Residual scan for lab escapes and incomplete denylist under unrestricted mode.  
5. Promote only residual issues with evidence.

## 2.3 Known limitations

- Standard retest, not deep fuzz.  
- Does not re-validate every fleet host config (deploy verification was separate).  
- Denylist probe is sample-based.

---

# 3 Reconnaissance

See `artifacts/recon.md`, `artifacts/detect-stack.txt`, `artifacts/deny-probe.txt`, `artifacts/residual-scan.txt`.

HEAD: `cd7315e` — security fixes in `15bc77b`, helpers in `cd7315e`.

---

# 4 Findings

## 4.1 SML-009 — Gateway auto-confirm remains unconditional (residual)

| Field | Value |
|-------|-------|
| Vulnerability ID | SML-009 |
| Vulnerability type | Design residual (authorization automation) |
| Threat level | Low |

### Description

Once gateway starts successfully, all tools with `needs_confirm` are still auto-approved via `gateway_auto_confirm`. Human-in-the-loop is not available headless.

### Technical description

`src/main.c` still registers:

```c
sc_tool_registry_set_confirm(agent->tools, gateway_auto_confirm, NULL);
```

**Mitigations now in place (why severity is Low, not Elevated):**

1. Gateway **refuses to start** if `exec`/`exec_background` available without allowlist (`gateway_exec_policy_ok`).  
2. Factory DM default allowlist + open-DM quarantine.  
3. Expanded denylist for script-file interpreters and curl upload forms.  
4. Exec sandbox fail-closed.  
5. Operators can remove tools via `allowed_tools` / channel `tools`.

Residual impact is mainly: auto-approved **git** (and other confirm-flagged tools) for authenticated/allowlisted users on a running gateway.

### Steps to reproduce

1. Configure gateway with exec allowlist (or no exec) so start succeeds.  
2. Include `git` in tools.  
3. Authenticated channel user induces model to call `git` → no human prompt.

### Impact

Limited to tools still exposed after gates; not remote unauthenticated RCE by default.

### Recommendation

- Keep production tool lists minimal.  
- Optional: gateway policy to refuse `git` unless explicitly allowed, or require dual-channel approval later.

---

# 5 Non-Findings / Closed Findings

## 5.1 SML-001 — Closed

**Evidence:**

- `src/config.c`: `default_dm = "allowlist"` for all builds; `accept_open_dms = 0`.  
- `src/channels/manager.c`: `quarantine_check(..., accept_open_dms)` on all external channels always (not only `SC_STRICT_SECURITY`).  
- Explicit `open` + empty `allow_from` → channel not started unless lab flag.

**Residual:** Lab hatch `accept_open_dms=true` is intentional and documented.

## 5.2 SML-002 — Closed (primary); residual under lab hatch

**Evidence:**

- `gateway_exec_policy_ok()` in `main.c` fatals if exec tools available without allowlist / unrestricted flag.  
- Deny probe (`artifacts/deny-probe.txt`):

| Command | Result |
|---------|--------|
| `python3 ./evil.py` | BLOCK |
| `node evil.js` | BLOCK |
| `curl … -T` / `--data-binary @` / `-F f=@` | BLOCK |
| `gcc -o x x.c` | BLOCK |
| `echo` / `ls` / `git status` | ALLOW |

**Residual (not re-elevated):**

- `allow_unrestricted_exec=true` re-opens full denylist surface (including still-ALLOW `wget -O`, bare `curl`, `make`, `cargo`, `busybox ls`).  
- CLI (non-gateway) still defaults to denylist mode with human confirm for exec — incomplete denylist is acceptable with confirm, not an Elevated finding.

## 5.3 SML-006 — Closed

**Evidence:** `src/mcp/client.c` — if sandbox requested and `sc_sandbox_apply != 0`, child `_exit(126)`. Explicit `no_sandbox` / `capabilities.sandbox=false` opts out by design.

**Residual:** Sandbox skipped when `workspace == NULL` (API allows NULL). Normal agent paths pass workspace.

## 5.4 Previously closed (spot-check still good)

| ID | Evidence at HEAD |
|----|------------------|
| SML-003 | `exec_common.c` sandbox apply failure → `_exit(126)` |
| SML-004 | `web.c` refuses start without bearer_token |
| SML-005 | CGNAT + 198.18/15 + TEST-NETs etc. in `is_private_ipv4` |
| SML-007 | `shell.c` uses `cwd = resolved_cwd` |
| SML-008 | `sc_web_check_bearer_auth` uses `sc_timing_safe_cmp` |

## 5.5 Positive controls

- Documented gateway threat model updated for enforceable gates.  
- Deploy helpers: `scripts/patch_security_configs.py`, `scripts/deploy_security_rollout.sh`.  
- Fleet configs patched (deploy session) to satisfy gates.  
- Large security test suite including new deny/SSRF cases.

## 5.6 Threat model

See `artifacts/threat-model.md`.

---

# 6 Future Work

- Optional gateway confirm policy beyond exec allowlist (SML-009).  
- Block `wget -O` / unrestricted outbound download helpers if allow_unrestricted_exec remains supported.  
- Fail closed MCP when workspace NULL and sandbox expected.  
- Deep mode AFL retest on current tree.  
- Prefer default-on `SC_STRICT_SECURITY` for release artifacts (optional).

---

# 7 Conclusion

The remediations in `15bc77b` successfully close the three open findings from the `bb0e27c` audit for **stock and gated gateway** operation:

- **No open Elevated findings.**  
- **No open Moderate findings.**  
- **One Low residual** (gateway auto-confirm of remaining tools).

Security is no longer primarily “hope the denylist is complete under open DM + auto-confirm”; it is “fail closed at config/start, then layered runtime controls.” Residual risk is operator-controlled lab escapes and intentional unattended tool use for allowlisted surfaces.

---

# Appendix A — Testing Team

| Role | Who |
|------|-----|
| Analyst | crystal-box-audit |
| Prior open baseline | `2026-07-12-bb0e27c` |
| Remediation | `15bc77b` |

# Appendix B — Artifact index

| Path | Description |
|------|-------------|
| `artifacts/threat-model.md` | Threat model |
| `artifacts/recon.md` | Inventory |
| `artifacts/detect-stack.txt` | Tools |
| `artifacts/deny-probe.txt` | ERE probe results |
| `artifacts/residual-scan.txt` | Extra residual commands |
| `artifacts/sml-retest-greps.txt` | Code path greps |
| `artifacts/commands.log` | Session metadata |

# Appendix C — Finding ID log

| ID | Title | Level | Disposition |
|----|-------|-------|-------------|
| SML-001 | Open DM defaults | Elevated | **Closed** |
| SML-002 | Gateway + denylist | Elevated | **Closed** (primary) |
| SML-003 | Sandbox fail-open exec | Moderate | Closed (prior) |
| SML-004 | Web bearer | Moderate | Closed (prior) |
| SML-005 | SSRF ranges | Moderate | Closed (prior) |
| SML-006 | MCP sandbox ignore | Moderate | **Closed** |
| SML-007 | working_dir | Low | Closed (prior) |
| SML-008 | Bearer timing | Low | Closed (prior) |
| SML-009 | Gateway auto-confirm residual | Low | **Open residual** |

# Appendix D — Verification evidence (code)

| Check | Location |
|-------|----------|
| default_dm allowlist | `config.c` ~862 |
| accept_open_dms default 0 | `config.c` ~866 |
| quarantine always | `manager.c` quarantine_check + all channels |
| gateway_exec_policy_ok | `main.c` ~2111–2150 |
| MCP sandbox fail-closed | `mcp/client.c` ~373–379 |
| Deny script/curl | `deny_patterns.h`; probe artifact |
| SSRF 198.18 | `web.c` ~852–856 |
