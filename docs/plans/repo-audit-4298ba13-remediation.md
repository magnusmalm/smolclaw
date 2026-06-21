# Implementation Plan — Repo Audit 4298ba13 Remediation (smolclaw)

**Status:** Draft — ready for `/implement`  
**Audit source:** `audit/repo-audit-4298ba13/net-recommendation.md`  
**Plan baseline commit:** `bd0f829f2685ec57c17c44c250d995ac52b53494` (pre-remediation)  
**Process guide:** `~/.grok/skills/my-planner/references/22-implementation-plans.md`

---

## Executive summary

Drive all **P0**, **P1**, and selected **P2** findings from the 2026-06-21 five-agent `/repo-audit` into a **stack of small, reviewable PRs** with tests and in-repo traceability. Goal: move gateway posture from **Not Ready** (internet-exposed) to **Production Ready** for operators who bind web beyond loopback.

Work is ordered **work > right > fast** (global mantra). No size-budget regressions; run `scripts/check_size_budget.sh` on minimal profile each code PR.

---

## Background — verified reproduction anchors

These are the *current* failure modes grounding the plan (not paraphrased).

### B1 — Web API open without bearer token (P0-1, critical)

```c
// src/channels/web.c:307-310
if (!wd->bearer_token || !wd->bearer_token[0])
    return 1; /* No token configured = open */
```

**Repro:** Start gateway with `channels.web.enabled=true`, empty `bearer_token`, bind reachable address → `curl -X POST http://host:port/api/message` drives full agent without auth.

### B2 — SQLite race under parallel read-only tools (P0-2, high)

Parallel batch in `src/agent_turn.c:1336+` runs `memory_search` / `context_search` concurrently on one `sc_memory_index_t` / `sqlite3 *db`.

**Repro signal:** Theoretical under concurrent tool batch; no dedicated ctest today. Add stress test or disable parallel until mutex lands.

### B3 — Deny-list regcomp failure → regexec UB (P0-3, high)

`sc_deny_list_init` warns on `regcomp` failure but returns 0; `sc_deny_list_matches` always calls `regexec`.

### B4 — Landlock path rules silently skipped (P0-4, high)

`ll_add_path_rule` / `apply_landlock` do not fail closed when mandatory workspace rules cannot be added.

### B5 — Security tests not in CI (P0-5)

`tests/test_security_prod.c` is `EXCLUDE_FROM_ALL` and not registered in ctest (`CMakeLists.txt:645-648`).

### Test baseline (committed before PR-1 code)

| Command | Result (2026-06-21) | Commit context |
|---------|---------------------|----------------|
| `ctest --test-dir build -j4` | **23/23 passed** | existing `build/` |
| `ctest --test-dir build-audit -j4` | **27/27 passed** | fresh configure |
| `test_security_prod` manual build | not run in CI | gap |

**Baseline artifact:** `docs/plans/repo-audit-4298ba13-baseline.md` (created in PR-0 with exact `git rev-parse HEAD`).

---

## Goals and success criteria

### P0 — must pass before “internet-exposed gateway” claim

| ID | Finding | Success criterion |
|----|---------|-------------------|
| P0-1 | Web fail-open | Gateway **refuses to start** web on non-loopback without bearer token, OR binds loopback-only by default with explicit opt-in documented. ctest proves 401 without token. |
| P0-2 | SQLite race | All `sc_memory_index_*` access serialized **or** parallel execution disabled for memory/context search tools. New ctest or TSAN-clean stress path. |
| P0-3 | Deny-list UB | `sc_deny_list_init` returns -1 on any `regcomp` failure; exec/shell tools not registered. ctest with invalid pattern injection or unit test on init failure path. |
| P0-4 | Landlock silent skip | Mandatory workspace (and configured capability) rules propagate errors; sandboxed exec fails closed if rules incomplete. Extend `test_sandbox.c`. |
| P0-5 | Security CI gap | `test_security_prod` (or split `test_security` subset) runs in **full** CI profile; document minimal-profile exclusion. |

### P1 — strong recommendations (ship in same arc, after P0)

| ID | Finding | Success criterion |
|----|---------|-------------------|
| P1-1 | Git push `strstr` bypass | URL host/path normalized match; `remote set-url` blocked or requires confirm. Tests in security or `test_tools.c`. |
| P1-2 | Gateway auto-confirm threat model | `docs/SECURITY.md` or `docs/operations/gateway-threat-model.md` states unattended execution; optional `gateway.confirm_policy` config stub (`auto`/`deny`) — implement `deny` for dangerous tools if low cost. |
| P1-3 | worktree shell bypass | `worktree.c` uses `execvp`/`fork` like `git.c`; no `popen`/`system`. ctest if feasible. |
| P1-4 | Web rate limit | Per-IP and/or per-token limit on `/api/message`; reuse `rate_limit.c` patterns. |
| P1-5 | notify curl | `notify.c` uses `sc_curl_init()`. Trivial ctest or compile-time assert path. |
| P1-6 | Doc falsehoods | README cron→`cron`; analytics gated; Kconfig TLS help updated. |
| P1-7 | Shell working_dir TOCTOU | Child `chdir` uses resolved path from `sc_validate_path`. Test in `test_tools.c` or security suite. |
| P1-8 | Exec chdir ignored | `chdir` failure → `_exit(126)` in child (`exec_common.c:278`). |

### P2 — included in arc (incremental, no big-bang refactor)

| ID | Finding | Success criterion |
|----|---------|-------------------|
| P2-1 | `main.c` split | Extract **one** cohesive slice (recommend: `doctor.c` or `vault_cli.c` first) only if touched by P0/P1; no standalone 2k-line rewrite. |
| P2-2 | `config.c` helper | Add `parse_channel_security()` helper **only if** a channel config edit occurs in this arc; otherwise defer with TODO in plan review record. |
| P2-3 | Stale size docs | RELEASE_NOTES + scattered 280 KB → 256 KB. |
| P2-4 | E2E binary path | `test_e2e.c` respects `SMOLCLAW_BIN` env or cmake variable. |
| P2-5 | `/api/health` | Require auth or loopback-only bind; document in CONFIGURATION.md. |

### P2 — explicitly deferred (logged in Final Review Record)

Medium stability items **not** in this arc unless a PR already touches the file:

- Bus queue drop at 1024 (`bus.c`)
- SIGHUP config reload mid-turn (`main.c` / `agent.c`)
- `memory_index.c` uncapped `read_file` (recommend **P1-9** if PR-3 touches memory_index)
- Discord heartbeat thread failure path
- Audit log fflush errors

---

## Scope boundaries

**In scope:** All P0; all P1; P2-1 through P2-5 as defined above.  
**Out of scope:** New features, provider/channel additions, size-budget increases, musl CI matrix expansion.  
**Pre-existing tests:** All ctest targets in full + minimal CI profiles must remain green unless a test is **intentionally updated** for new fail-closed behavior (document in PR description).

---

## PR stack (recommended merge order)

Each PR = one clean commit (or ≤3 logically atomic commits). **No unrelated changes.**

```
PR-0  docs: audit artifacts + baseline + this plan
PR-1  fix(web): fail-closed auth + tests                    [P0-1]
PR-2  fix(exec): deny-list + landlock + chdir + wd resolve    [P0-3, P0-4, P1-7, P1-8]
PR-3  fix(memory): sqlite serialization + prepare checks    [P0-2, +P1-9 if touching file]
PR-4  ci: wire security tests into ctest full profile       [P0-5]
PR-5  fix(git,worktree): push allowlist + execvp worktree   [P1-1, P1-3]
PR-6  fix(web): rate limits + health hardening              [P1-4, P2-5]
PR-7  fix(notify): sc_curl_init                             [P1-5]
PR-8  docs: threat model + README/Kconfig truthfulness      [P1-2, P1-6, P2-3]
PR-9  refactor/docs: main.c slice + e2e path (optional)     [P2-1, P2-4]
```

**Parallelization:** PR-1, PR-2, PR-3 can be implemented in parallel worktrees after PR-0; merge order above respects dependencies (PR-4 should follow PR-1–3 so security tests encode new behavior).

---

## PR details

### PR-0 — Land audit + baseline (docs only)

**Files:**
- Commit `audit/repo-audit-4298ba13/*.md` (if not already on master)
- Add `docs/plans/repo-audit-4298ba13-baseline.md` with `git rev-parse HEAD`, ctest commands, raw pass counts
- This plan file

**Success:** `git show PR-0` contains only docs/plans + audit.

---

### PR-1 — Web fail-closed [P0-1]

**Design decision (document in source):**
- Option A (recommended): Refuse `sc_channel_web_start` if `bearer_token` empty.
- Option B: Allow loopback bind only without token; fatal on `0.0.0.0` without token (keep existing warn, upgrade to error).

**Tests:**
- Extend `test_web.c` or add `test_web_auth.c` (enable `SC_ENABLE_WEB` in test target): request without `Authorization` → 401; gateway start without token → fail.

**Rationale comment location:** `web.c` above `check_auth` — explain fail-closed policy (audit 4298ba13).

**`/implement` effort:** 2 (1 implementer + 2 reviewers: security + tests)

---

### PR-2 — Exec safety bundle [P0-3, P0-4, P1-7, P1-8]

**Changes:**
1. `exec_common.c`: `compiled[]` flags; init returns -1 on any `regcomp` fail; child `_exit(126)` on `chdir` fail; pass resolved wd to child.
2. `sandbox.c`: propagate `ll_add_rule` errors for workspace + required paths.
3. `shell.c`: thread resolved path into exec child (TOCTOU fix).

**Tests:**
- `test_sandbox.c`: simulate or mock landlock rule failure path if possible.
- `test_tools.c` or security: deny-list init failure refuses tool registration.

**Size check:** minimal profile `scripts/check_size_budget.sh`.

**`/implement` effort:** 3 (security + stability + tests reviewers)

---

### PR-3 — Memory index concurrency [P0-2]

**Design options (pick one, document in `memory_index.h`):**

| Option | Pros | Cons |
|--------|------|------|
| A. `pthread_mutex` around all `sc_memory_index_*` | Simple, correct | Serializes searches |
| B. Disable parallel batch for memory/context tools only | Minimal code | Perf hit on batch |
| C. Read-only sqlite connection per thread | True parallelism | More complex lifecycle |

**Recommendation:** **Option A** for P0 (work phase). Revisit Option C in a later perf arc.

**Also in this PR if touching `memory_index.c`:**
- Check all `sqlite3_prepare_v2` return codes (stability medium).
- Cap `read_file` at `MAX_MEMORY_FILE_SIZE` (P1-9).

**Tests:**
- New test: concurrent `sc_memory_index_search` from two threads → no crash, consistent results.
- Or: `agent_turn` parallel batch test with TSAN build (if CI supports).

**`/implement` effort:** 3

---

### PR-4 — Security tests in CI [P0-5]

**Options:**
1. Register `test_security_prod` in ctest for full profile only (may be slow).
2. Split fast subset into `test_security.c` (prompt_guard, web auth, git allowlist) always in ctest; keep prod suite manual nightly.

**Recommendation:** Option 2 for CI latency; Option 1 as `ctest -L security` label.

**CI change:** `.gitea/workflows/ci.yml` — full matrix runs labeled security tests.

**Success:** CI log shows security tests executed; README documents minimal vs full.

**`/implement` effort:** 2

---

### PR-5 — Git + worktree [P1-1, P1-3]

**git.c:** Parse remote URL (existing or new `sc_url_parse_host` util); exact host match; block `remote set-url` / `remote add` subcommands or set `needs_confirm=1`.

**worktree.c:** Replace `popen`/`system` with `fork`+`execvp` pattern from `git.c`.

**Tests:** Port relevant cases from `test_security_prod.c` into ctest-visible `test_git_security.c` if needed.

**`/implement` effort:** 3 (security reviewer mandatory)

---

### PR-6 — Web hardening [P1-4, P2-5]

**Rate limit:** Integrate `sc_rate_limiter_check` in `handle_message` keyed by IP (and token hash if present).

**Health:** Require auth for `/api/health` OR document loopback-only + enforce in non-loopback bind path.

**`/implement` effort:** 2

---

### PR-7 — notify curl [P1-5]

One-line fix + confirm no other raw `curl_easy_init` in `src/` (grep gate in review).

**`/implement` effort:** 1

---

### PR-8 — Documentation [P1-2, P1-6, P2-3]

**New/updated:**
- `docs/operations/gateway-threat-model.md` — auto-confirm, network isolation, bearer token requirement post-PR-1
- README fixes (cron, analytics, TLS note in Kconfig)
- RELEASE_NOTES size table

No code unless `gateway.confirm_policy` stub chosen for P1-2.

**`/implement` effort:** 1 (docs reviewer)

---

### PR-9 — Optional engineering [P2-1, P2-4]

Only if capacity remains:
- Extract `doctor.c` from `main.c` (smallest slice with clear boundaries)
- `test_e2e.c`: `SMOLCLAW_BIN` cmake cache variable

Skip P2-2 unless channel config edited.

**`/implement` effort:** 2

---

## Process & Auditability

*Required per `~/.grok/skills/my-planner/references/22-implementation-plans.md`.*

### 1. Reviewed state is a git artifact

> Any change required for reviewers to sign off must land in a **narrow PR commit** before starting the next PR. No “fixes in working tree only.”

After each PR: `/team-review --diff HEAD~1..HEAD` or `/review --local`. Record result in `docs/plans/repo-audit-4298ba13-review-record.md` (append per PR).

### 2. Source-level rationale

Non-obvious decisions (fail-closed web, mutex vs per-thread sqlite, git URL matching) get **2–5 line comments** at the decision point in C source, referencing audit ID `4298ba13`.

### 3. Hygiene definition (clean delta)

- No drive-by refactors outside PR scope.
- No mechanical “replaced N call sites” claims in commit messages; describe **intent** (“fail closed when landlock workspace rule cannot be applied”).
- `git diff` for each PR must map to plan PR table rows.

### 4. Test scope honesty

| Must pass every code PR | Notes |
|-------------------------|-------|
| `ctest --test-dir build --output-on-failure` | full local default |
| Minimal profile ctest in CI | per matrix cell |
| `scripts/check_size_budget.sh` | code PRs touching src/ |
| `test_security_prod` or successor | after PR-4 |

**Out of scope:** Fixing unrelated flaky tests (`test_tee` sleep, etc.) unless they fail on touched PRs.

### 5. Artifact auditability

| Artifact | Location | When |
|----------|----------|------|
| Audit reports | `audit/repo-audit-4298ba13/` | PR-0 |
| This plan | `docs/plans/repo-audit-4298ba13-remediation.md` | PR-0 |
| Baseline | `docs/plans/repo-audit-4298ba13-baseline.md` | PR-0 |
| Review record | `docs/plans/repo-audit-4298ba13-review-record.md` | After each PR |
| Final Review Record | same file, final section | After PR-8/9 merge |

Chat and `/tmp/grok-*` are **not** canonical.

### 6. Traceability matrix

Maintain in review record:

```
| Plan ID | PR | Commit | Test evidence | Status |
```

### 7. Working tree discipline

Implementation reports cite **`git rev-parse HEAD`** at verification time, not “current tree.”

### 8. Baseline before behavior claims

PR-0 baseline doc is the reference for “tests still green.” Any new fail-closed behavior that changes test count documents **expected** delta in PR description.

---

## Recommended execution strategy

### Phase A — P0 only (ship first)

`/implement` PR-1 through PR-4 sequentially with effort 3.  
**Checkpoint:** Re-run `/repo-audit SCOPE=src/ focus security+stability` — expect **Needs Work (Low)** not Not Ready.

### Phase B — P1

PR-5 through PR-8; parallel where possible.  
**Checkpoint:** `/team-review --diff <baseline>..HEAD`

### Phase C — P2

PR-9 if time; otherwise log accepted deferrals in Final Review Record.

### Final validation

```
/repo-audit SCOPE=.
/qa-audit SCOPE=changed-since=<PR-0-commit> GATE_MODE=pre-release
```

Target grade: **Production Ready** for documented gateway deployment model (loopback or bearer + rate limits).

---

## Final Review Record (template — fill on completion)

Create/update `docs/plans/repo-audit-4298ba13-review-record.md`:

```markdown
# Final Review Record — Repo Audit 4298ba13 Remediation

**Plan:** docs/plans/repo-audit-4298ba13-remediation.md
**Review Baseline Commit:** <PR-0 hash>
**Final Reviewed Commit:** <last PR hash>
**Date:** YYYY-MM-DD

## Executive Summary
[Production Ready / Needs Work — ...]

## Traceability
| Plan ID | PR | Commit | Status |
|---------|----|--------|--------|
| P0-1 | PR-1 | ... | Closed |
...

## Accepted residuals
- P2-2 deferred: no channel added this arc
- Bus queue backpressure: deferred to <issue>

## Sign-off
- /repo-audit: grade ...
- /team-review: 0 P0 open
```

---

## Effort summary for `/implement`

| PR | Effort | Reviewers |
|----|--------|-----------|
| PR-0 | 1 | docs |
| PR-1 | 2 | security, tests |
| PR-2 | 3 | security, stability, tests |
| PR-3 | 3 | stability, tests |
| PR-4 | 2 | tests, CI |
| PR-5 | 3 | security, tests |
| PR-6 | 2 | security |
| PR-7 | 1 | general |
| PR-8 | 1 | docs |
| PR-9 | 2 | general (optional) |

**Total estimated:** 9–10 PRs, ~20 implementer sessions if run sequentially.

---

## Mantra alignment

1. **Work first:** P0 security/stability before `main.c` split.
2. **Right incrementally:** PR-9 split only one file; no framework rewrite for config.
3. **Fast last:** No perf work until `/repo-audit` grade improves; size budget checked but not optimized.

---

*Plan produced with `/my-planner` coach rules. Next step: land PR-0, then `/implement PR-1` or human-driven equivalent.*