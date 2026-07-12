# Security audits (smolclaw)

**Historical archives only.** Each directory is a point-in-time crystal-box
(ROS-style) audit of the tree at the listed commit. Counts, findings, and
tool output are **not** current product documentation and may disagree with
`README.md` / `docs/SECURITY.md` on HEAD. Prefer the product docs for live
behavior; re-run `/crystal-box-audit` for a fresh assessment of HEAD.

## Index

| Directory | Commit | Depth | Notes |
|-----------|--------|-------|-------|
| `2026-07-12-bb0e27c/` | `bb0e27c` | standard | Retest baseline: SML-001/002/006 open |
| `2026-07-12-a1135e9/` | `a1135e9` | standard | Historical baseline |
| `2026-07-12-a1135e9-deep/` | `a1135e9` | deep | Semgrep + AFL harnesses on old tree |
| `2026-07-12-cd7315e/` | `cd7315e` | standard | Post-remediation retest (includes `15bc77b`) |

## Remediation noted after `bb0e27c` (context for archives)

| ID | Fix (landed around `15bc77b` / `cd7315e`) |
|----|------------------------------------------|
| SML-001 | Default `dm_policy=allowlist`; quarantine open+empty unless `accept_open_dms` |
| SML-002 | Gateway requires exec allowlist; denylist script-files + curl upload; tests |
| SML-006 | MCP `sc_sandbox_apply` fail-closed (`_exit(126)`) |
| SSRF residual | Block `198.18.0.0/15` |

These rows describe what the later archives were verifying; they are not a
substitute for reading HEAD or re-auditing.
