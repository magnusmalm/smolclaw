# Repo Audit 4298ba13 — Measurement Baseline

**Captured:** 2026-06-21  
**Purpose:** Pre-remediation baseline per my-planner lesson §8 (committed before code PRs).

## Git baseline

Record at PR-0 merge:

```bash
git rev-parse HEAD
# bd0f829f2685ec57c17c44c250d995ac52b53494 (pre-remediation baseline, PR-0)
```

**Audit reports commit:** ideas trial run artifacts at `audit/repo-audit-4298ba13/` (added in PR-0).

## Test baseline

Commands and raw results from audit trial:

| Build dir | Command | Result | Wall time |
|-----------|---------|--------|-----------|
| `build/` | `ctest --test-dir build --output-on-failure -j4` | **23/23 passed** | ~5.5s |
| `build-audit/` | `cmake -B build-audit -S . && cmake --build build-audit -j4 && ctest --test-dir build-audit -j4` | **27/27 passed** | ~6.6s |

## Security test gap (pre-fix)

| Suite | In ctest? | In CI? |
|-------|-----------|--------|
| `test_security_prod.c` (~177 tests) | **No** (`EXCLUDE_FROM_ALL`) | **No** |
| `prompt_guard` coverage | Only in prod suite | **No** |

## Gateway posture (pre-fix)

| Check | Status |
|-------|--------|
| Web without bearer token | **Fail-open** (`web.c:310`) |
| `/repo-audit` grade | **Not Ready** (internet-exposed) |

## Size baseline (reference)

README claims **256 KB** stripped minimal; RELEASE_NOTES still cites 280 KB (doc drift — P2-3).

```bash
# Record at PR-0 if build-size exists:
# stat -c %s build-size/smolclaw 2>/dev/null || echo "run minimal build first"
```

## Re-run instructions

After remediation arc completes, compare against this file:

```bash
ctest --test-dir build --output-on-failure -j4
# Expect: prior count + new security/web tests
/repo-audit SCOPE=.
```