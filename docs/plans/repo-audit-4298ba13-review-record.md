# Review Record — Repo Audit 4298ba13 Remediation

**Start here (reviewers):** `docs/plans/repo-audit-4298ba13-REVIEW-START-HERE.md`  
**Plan:** `docs/plans/repo-audit-4298ba13-remediation.md`  
**Baseline:** `docs/plans/repo-audit-4298ba13-baseline.md`  
**Pre-remediation commit:** `bd0f829f2685ec57c17c44c250d995ac52b53494`

---

## PR log

| PR | Title | Commit | Review tool | P0 open | Notes |
|----|-------|--------|-------------|---------|-------|
| PR-0 | docs: audit + baseline + plan | 74f8a9a | — | — | landed |
| PR-1 | web fail-closed | f8c67c4 | ctest 42/42 | 0 | landed |
| PR-2 | exec safety bundle | 6d5e83a | ctest 42/42 | 0 | landed |
| PR-3 | memory index mutex | 7665a37 | ctest 42/42 | 0 | landed |
| PR-4 | security tests in CI | d2b288f | ctest 42/42 full | 0 | landed |
| PR-5 | git + worktree | bf19d1f | ctest 42/42 | 0 | landed |
| PR-6 | web rate limits + health | b42891a | ctest 42/42 | 0 | landed |
| PR-7 | notify sc_curl_init | ca5a02a | ctest 42/42 | 0 | landed |
| PR-8 | docs threat model | 4debe3e | ctest 42/42 | 0 | landed |
| PR-9 | optional main.c / e2e | 64cb401 | ctest 42/42 | 0 | landed |

**Land scripts (reproducible close-out):** `scripts/land-pr5.sh` … `scripts/land-pr9.sh`

---

## Traceability matrix

| Plan ID | PR | Commit | Test evidence | Status |
|---------|----|--------|---------------|--------|
| P0-1 | PR-1 | f8c67c4 | test_web_auth | closed |
| P0-2 | PR-3 | 7665a37 | test_memory_search concurrent | closed |
| P0-3 | PR-2 | 6d5e83a | test_exec_safety deny-list init | closed |
| P0-4 | PR-2 | 6d5e83a | test_sandbox mandatory workspace | closed |
| P0-5 | PR-4 | d2b288f | test_security + test_security_prod (ctest label) | closed |
| P1-1 | PR-5 | bf19d1f | test_git_security | closed |
| P1-2 | PR-8 | 4debe3e | gateway-threat-model.md | closed |
| P1-3 | PR-5 | bf19d1f | test_git_security | closed |
| P1-4 | PR-6 | b42891a | test_web_auth rate-limit helpers | closed |
| P1-5 | PR-7 | ca5a02a | test_curl_common grep gate | closed |
| P1-6 | PR-8 | 4debe3e | README + Kconfig | closed |
| P1-7 | PR-2 | 6d5e83a | test_exec_safety resolved wd | closed |
| P1-8 | PR-2 | 6d5e83a | test_exec_safety chdir 126 | closed |
| P1-9 | PR-3 | 7665a37 | test_index_rebuild_truncates_oversized | closed |
| P2-1 | PR-9 | 64cb401 | doctor.c extract | closed |
| P2-3 | PR-8 | 4debe3e | RELEASE_NOTES 256 KB | closed |
| P2-4 | PR-9 | 64cb401 | test_e2e SMOLCLAW_BIN | closed |
| P2-5 | PR-6 | b42891a | test_web_auth + health auth | closed |
| P2-2 | — | — | — | deferred |

---

## Final Review Record

**Final Reviewed Commit (code):** `64cb401463976f52e2c3f1c09d2c88bb588bb531`  
**Close-out documentation commit:** `012ef83` (this review record + land scripts)  
**Review Baseline Commit (PR-0):** `74f8a9a`  
**Date:** 2026-06-22

### Executive summary

**Grade: Production Ready** for the deployment model documented in
`docs/operations/gateway-threat-model.md`: web channel requires bearer
token to start; `/api/message` rate-limited; `/api/health` authenticated;
exec/deny-list/sandbox/memory concurrency/security tests in ctest full
profile.

Pre-remediation **Not Ready** (internet-exposed, fail-open web) findings
from audit `4298ba13` are addressed in code and traced below. Operators
who bind web beyond loopback without TLS/reverse-proxy still assume
residual network risk — documented, not eliminated.

### Verification (close-out run)

```bash
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure -j$(nproc)
# 2026-06-22: 42/42 passed, ~5.5s wall (full local profile)
```

Key security tests: `test_web_auth`, `test_git_security`, `test_exec_safety`,
`test_sandbox`, `test_security`, `test_security_prod` (label `security`).

### Accepted residuals (explicitly out of arc scope)

| Item | Rationale |
|------|-----------|
| **P2-2** `parse_channel_security()` | Deferred per plan gate — no `config.c` channel-parser edits in this arc |
| Bus queue drop at 1024 | Medium stability; no PR touched `bus.c` |
| SIGHUP config reload mid-turn | Medium stability; deferred |
| Discord heartbeat thread failure | Medium stability; deferred |
| Audit log `fflush` errors | Medium stability; deferred |
| Scattered 280 KB refs in design docs | P2-3 closed RELEASE_NOTES; older design notes may still mention 280 KB |
| Formal `/team-review` per PR | Not captured in-repo; implementation verified via ctest + land scripts |

### Sign-off

| Check | Result |
|-------|--------|
| All P0 plan IDs | Closed (P0-1 … P0-5) |
| All P1 plan IDs in arc | Closed (P1-1 … P1-9) |
| P2 in arc | Closed P2-1, P2-3, P2-4, P2-5; P2-2 deferred |
| ctest full profile @ `64cb401` | **42/42 pass** |
| Reviewed state = git artifact | PR-0 … PR-9 commits on `master` |

**Recommendation:** Run `/team-review --diff 74f8a9a..64cb401` or human
security review before claiming production deployment on internet-facing
hosts without reverse-proxy hardening.