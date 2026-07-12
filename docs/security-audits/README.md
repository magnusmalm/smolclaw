# Security audits (smolclaw)

Crystal-box (ROS-style) audit artifacts.

| Directory | Commit | Depth | Notes |
|-----------|--------|-------|-------|
| `2026-07-12-bb0e27c/` | `bb0e27c` | standard | Retest: SML-001/002/006 were open |
| `2026-07-12-a1135e9/` | `a1135e9` | standard | Historical baseline (initial commit) |
| `2026-07-12-a1135e9-deep/` | `a1135e9` | deep | Semgrep + AFL harnesses on old tree |

**Remediation (PR-1 + PR-2, post-`bb0e27c`):**

| ID | Fix |
|----|-----|
| SML-001 | Default `dm_policy=allowlist`; quarantine open+empty unless `accept_open_dms` |
| SML-002 | Gateway requires exec allowlist; denylist script-files + curl upload; tests |
| SML-006 | MCP `sc_sandbox_apply` fail-closed (`_exit(126)`) |
| SSRF residual | Block `198.18.0.0/15` |

Re-run `/crystal-box-audit` after these land on HEAD to confirm closure.

