# Start Here — Review Audit 4298ba13 Remediation

**Audience:** AI agents (and humans) performing an independent review of the
smolclaw security remediation arc.

**Arc status:** Complete (PR-0 … PR-9 landed on `master`).  
**Declared grade:** Production Ready — for the deployment model in
`docs/operations/gateway-threat-model.md` (see Final Review Record).

---

## TL;DR

| What | Value |
|------|-------|
| Original audit | `audit/repo-audit-4298ba13/net-recommendation.md` |
| Pre-remediation commit | `bd0f829` |
| Remediation start (PR-0) | `74f8a9a` |
| Final reviewed code | `64cb401` |
| Close-out docs | `012ef83` (+ hygiene `d0200aa`) |
| Tests @ close-out | **42/42** ctest (full local profile) |
| Open P0 from plan | **0** |
| Deferred by design | **P2-2** (`parse_channel_security()` — no `config.c` channel edits in arc) |

Your job: confirm the remediation matches the plan, tests pass, residuals are
acceptable, and nothing regressed vs the original audit intent.

---

## Reading order (do this first)

1. **This file** — workflow and pointers.
2. **`docs/plans/repo-audit-4298ba13-review-record.md`** — authoritative close-out:
   PR log, plan-ID traceability matrix, Final Review Record, accepted residuals.
3. **`audit/repo-audit-4298ba13/net-recommendation.md`** — what we were fixing
   (P0/P1/P2 priorities from the 2026-06-21 repo audit).
4. **`docs/plans/repo-audit-4298ba13-remediation.md`** — implementation plan
   (PR stack, success criteria, reproduction anchors). Status line may still
   say "Draft"; treat the **review record** as source of truth for completion.
5. **`docs/operations/gateway-threat-model.md`** — operator-facing threat model
   added in PR-8; defines the "Production Ready" deployment assumptions.
6. **`docs/plans/repo-audit-4298ba13-baseline.md`** — pre-remediation test
   counts (23/27) for before/after comparison.

Optional depth: per-finding agent reports under `audit/repo-audit-4298ba13/`
(`security.md`, `stability.md`, `tests.md`, `simplicity.md`).

---

## Verify in 5 minutes

From repo root, with an existing `build/` directory:

```bash
# 1. Confirm you are reviewing the right commits
git log --oneline 74f8a9a..64cb401

# 2. Build + full test suite
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure -j"$(nproc)"
# Expect: 42/42 passed

# 3. Security-labelled tests only
ctest --test-dir build -L security --output-on-failure

# 4. Diff size (remediation scope)
git diff --stat 74f8a9a..64cb401
```

If `build/` is missing:

```bash
cmake -B build -S .
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure -j"$(nproc)"
```

Fresh configure baseline (optional): see commands in
`docs/plans/repo-audit-4298ba13-baseline.md`.

---

## Review workflow for AI agents

### Step 1 — Traceability check

Open `docs/plans/repo-audit-4298ba13-review-record.md` → **Traceability matrix**.

For each row with status `closed`:

- `git show <commit> --stat` — confirm the PR message references the plan ID.
- Run or inspect the **Test evidence** column (ctest target or doc).

For `P2-2` (`deferred`): confirm no channel JSON parser refactor was smuggled
in without plan ID; deferral is intentional per plan gate.

### Step 2 — Security-critical paths

Prioritize reading/diffing these areas (map to audit P0/P1):

| Area | Files | Plan IDs | Tests |
|------|-------|----------|-------|
| Web auth / rate limits | `src/channels/web.c`, `web.h` | P0-1, P1-4, P2-5 | `test_web_auth` |
| Exec deny-list | `src/tools/exec.c`, deny-list helpers | P0-3, P1-7, P1-8 | `test_exec_safety` |
| Sandbox / Landlock | sandbox sources | P0-4 | `test_sandbox` |
| Memory index concurrency | memory index code | P0-2, P1-9 | `test_memory_search`, index tests |
| Security in CI | `CMakeLists.txt` | P0-5 | `test_security`, `test_security_prod` |
| Git push allowlist | `src/tools/git.c` | P1-1, P1-3 | `test_git_security` |
| Worktree subprocess | `src/tools/worktree.c` | P1-3 | `test_git_security` |
| Notify TLS/curl | `src/tools/notify.c` | P1-5 | `test_curl_common` |
| Threat model / docs | `docs/operations/gateway-threat-model.md` | P1-2, P1-6, P2-3 | manual |

### Step 3 — Regression and scope

- Compare test count: baseline **23–27** → post-remediation **42** (new security
  coverage, not shrinkage).
- Run `scripts/check_size_budget.sh` on minimal profile if you touch code
  (plan requirement for code PRs).
- Do **not** treat these as in-scope defects unless you are starting a new arc:
  bus queue at 1024, SIGHUP reload, Discord heartbeat, audit `fflush`, P2-2
  (listed in review record **Accepted residuals**).

### Step 4 — Produce your verdict

Use the same structure as the original audit where helpful:

- **Grade:** Production Ready | Needs Work (H/M/L) | Not Ready
- **P0 blockers** (if any): must cite file:line and reproduction
- **P1 recommendations**
- **P2 nice-to-haves**
- **Positive observations**

If you find issues, map each to a **plan ID** (or propose a new ID) and
suggest which file/test would close it.

---

## Git commands cheat sheet

```bash
# Full remediation diff
git diff 74f8a9a..64cb401

# Per-PR inspection (examples)
git show f8c67c4   # PR-1 web fail-closed
git show 6d5e83a   # PR-2 exec safety
git show bf19d1f   # PR-5 git + worktree
git show b42891a   # PR-6 web rate limits
git show 64cb401   # PR-9 doctor + e2e

# Reproduce a land procedure (historical; commits already exist)
./scripts/land-pr5.sh   # only if resetting to pre-PR-5 state
```

Land scripts live under `scripts/land-pr5.sh` … `land-pr9.sh` and
`scripts/land-closeout.sh`. They document the mechanical land steps; they are
not meant to be re-run on an already-landed tree.

---

## Deeper review (recommended before internet exposure)

The close-out record recommends a formal multi-agent pass:

```text
/team-review --diff 74f8a9a..64cb401
```

That output is **not** checked into this repo yet. If you run it, append
findings to `docs/plans/repo-audit-4298ba13-review-record.md` under a new
**Post-close-out review** section (date, tool, grade, P0 count).

---

## Ignore (not part of this arc)

Untracked or unrelated noise in the working tree:

- `.config.bak.pr4`
- `foo`
- `docs/CONFIGURATION-VALIDATION.md`

Older design docs may still say "280 KB"; `RELEASE_NOTES` was corrected to
256 KB in PR-8 (P2-3).

---

## Where to report results

| Outcome | Action |
|---------|--------|
| Confirms close-out | Note date + verifier in review record or your session log |
| New P0/P1 | Open issue or new plan; do not silently expand this arc |
| Doc-only fix | Small commit updating review record or this file |

**Canonical artifacts (must stay consistent):**

- `docs/plans/repo-audit-4298ba13-review-record.md` — PR hashes, matrix, grade
- `docs/plans/repo-audit-4298ba13-REVIEW-START-HERE.md` — this entry point

---

## One-paragraph context

The 2026-06-21 five-agent repo audit (`4298ba13`) rated smolclaw **Not Ready**
for internet-exposed gateway use (fail-open web API, exec/sandbox gaps, missing
security tests in CI, git/worktree issues). This arc implemented ten stacked PRs
(PR-0 planning through PR-9 optional engineering), added tests and operator
docs, and closed all P0 and in-scope P1/P2 items with explicit deferrals.
Independent reviewers should validate traceability, re-run ctest 42/42, and
challenge whether residuals are acceptable for their deployment model.