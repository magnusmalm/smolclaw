# Net Repo Audit Recommendation — smolclaw (full scope)

**Generated**: 2026-06-21  
**Scope**: Full repository (`/home/magnus/devel/smolclaw`); deep read prioritized `src/`, `tests/`, `scripts/`, `cmake/`, `docs/`; excluded `build*/`, `deps/`  
**Team**: Security + Stability + Simplicity + Tests + Docs (5/5 agents, budgets enforced)  
**Review ID**: 4298ba13

**Overall Grade**: **Not Ready** (for internet-exposed gateway without hardening)

Safe for careful local/dev use with existing CI green (23–27 ctest targets). **Do not expose web gateway to untrusted networks** until P0 security items are fixed.

---

## Executive summary

smolclaw has strong intentional security architecture (deny patterns, Landlock/seccomp, SSRF pinning, vault, pairing on chat channels). The trial audit found **one critical misconfiguration class** (web API open when bearer token unset) amplified by **gateway auto-confirm** and **high-severity stability bugs** (SQLite races under parallel tools, deny-regex UB, silent Landlock rule drops). Test suite passes in CI but **~177 security tests never run in ctest**. Documentation is mostly accurate; a few README/Kconfig claims are false or stale.

---

## Consensus findings

Issues where security + stability/tests overlap:

- **[Security+Tests]** Web channel auth fail-open (`web.c:310`) — no automated test in ctest; `test_security_prod` excluded from CI  
  - Severity: critical  
  - Suggestion: Fail closed at startup; add ctest coverage for auth-required paths  

- **[Security+Stability]** Exec deny-list `regcomp` failure → undefined `regexec` (`exec_common.c:49-81`)  
  - Severity: high  
  - Suggestion: Fail closed on init; refuse exec tools if patterns don't compile  

- **[Security+Stability]** Landlock path rules silently skipped (`sandbox.c:134-224`)  
  - Severity: high  
  - Suggestion: Propagate mandatory rule failures; refuse sandboxed exec if workspace rule missing  

- **[Security+Tests]** Git push allowlist `strstr` bypass (`git.c:345`) — security suite exists but not in CI  
  - Severity: high  
  - Suggestion: Parse/normalize URL host; block or confirm `remote set-url`  

---

## By specialist

### Security (11 findings: 1 critical, 2 high, 4 medium, 2 low, 2 info)

See `security.md`. Top items:

1. **Critical:** Web bearer token unset = full API access  
2. **High:** Gateway auto-approves all `needs_confirm` tools  
3. **High:** Git push allowlist substring bypass  
4. **Medium:** `worktree` tool uses shell/popen outside exec guard  
5. **Medium:** Shell `working_dir` TOCTOU (validate realpath, chdir raw path)  
6. **Medium:** Web bypasses rate limit / pairing (`base.c` path skipped)

### Stability (18 findings: 0 critical, 3 high, 10 medium, 5 low)

See `stability.md`. Top items:

1. **High:** Parallel read-only tools race on shared SQLite connection (`agent_turn.c` + `memory_index.c`)  
2. **High:** Deny-pattern regcomp failures → UB in regexec  
3. **High:** Landlock failures silently ignored  
4. **Medium:** Bus drops messages at depth 1024; pipe notify desync; exec chdir ignored; tmpdir falls back to `/tmp`

### Simplicity (7 findings: 1 high, 6 medium)

See `simplicity.md`. Top items:

1. **High:** `main.c` god file (2241 LOC) — split on next touch, not standalone rewrite  
2. **Medium:** `config.c` parallel edit surfaces (KC-1 class drift)  
3. **Medium:** `notify.c` bypasses `sc_curl_init()` — **fix now** (work phase)  
4. **Medium:** `agent.c` / `agent_turn.c` still very large but recent splits are positive

### Test coverage

See `tests.md`.

- **Run:** `ctest` 23/23 (`build/`) and 27/27 (`build-audit/`) — all green  
- **Gap:** `test_security_prod.c` (~177 tests) **EXCLUDE_FROM_ALL**, not in ctest/CI  
- **Gap:** `prompt_guard` untested in CI; `test_web.c` gated off  
- **Gap:** `gateway_process_message` not integration-tested  
- **Gap:** gitea/worktree/notify/host tools have no dedicated tests

### Documentation truthfulness

See `docs.md`.

- **3 false:** README `cronjob` vs `cron`; `analytics` CLI without Kconfig note; Kconfig "no TLS" vs implemented TLS  
- **5 stale:** RELEASE_NOTES 280 KB vs ~256 KB; scattered doc size refs  
- **Missing:** Several web API endpoints and tools undocumented in primary refs

---

## Prioritized action list

### P0 (blockers before internet-exposed gateway)

1. **Fail closed** if web channel enabled without bearer token (or bind non-loopback without auth) — `web.c:307-310`  
2. **Fix SQLite concurrency** — mutex or per-thread connections before parallel read-only tools — `agent_turn.c:1336+`  
3. **Fail closed on deny-list init** — any `regcomp` failure aborts exec registration — `exec_common.c:49-81`  
4. **Landlock mandatory paths** — propagate failures; refuse exec if workspace rule fails — `sandbox.c`  
5. **Wire `test_security_prod` into ctest/CI** (or split and gate a `test_security` target on full profile)

### P1 (strong recommendations)

1. Git push allowlist: URL parsing, not `strstr` — `git.c:342-349`  
2. Document gateway as unattended privileged execution; configurable confirm policy  
3. Refactor `worktree.c` off `popen`/`system` onto `execvp` path  
4. Web rate limiting per IP/token — `web.c` bypass of `sc_channel_handle_message`  
5. `notify.c`: use `sc_curl_init()` — one-line correctness fix  
6. README/Kconfig doc fixes (cron tool name, analytics flag, TLS note)

### P2 (nice-to-have)

1. Incremental `main.c` split (gateway/doctor/vault CLI) on next touch  
2. `config.c` shared channel-security parse helper on next new channel  
3. Refresh RELEASE_NOTES size table and stale 280 KB references  
4. E2E test binary path parametrization  
5. `/api/health` auth or loopback-only

---

## Positive observations

- Substantial defense-in-depth already present (deny patterns, sandbox, SSRF, vault, pairing on chat channels)  
- CI matrix (gcc/clang × full/minimal) with size budget enforcement  
- Recent architectural splits (`agent_turn`, `curl_common`) show discipline  
- Core paths well tested: sandbox, pairing, providers, session isolation, tool registry basics  
- README security claims largely verified (~90 deny patterns, secret redaction, Kconfig count)

---

## Mantra alignment notes

- **notify.c curl fix** = **work** — do immediately  
- **main.c split** = **right** — defer until next gateway/CLI touch (simplicity agent agrees)  
- **Security P0** = **work** — must precede perf/size tuning  
- Voxly tie-break override does not apply; default **work > right > fast** applies

---

## Artifacts

| Report | Path |
|--------|------|
| Security | `audit/repo-audit-4298ba13/security.md` |
| Stability | `audit/repo-audit-4298ba13/stability.md` |
| Simplicity | `audit/repo-audit-4298ba13/simplicity.md` |
| Tests | `audit/repo-audit-4298ba13/tests.md` |
| Docs | `audit/repo-audit-4298ba13/docs.md` |
| **This synthesis** | `audit/repo-audit-4298ba13/net-recommendation.md` |

## Audit metadata

- Agents launched: **5/5** (all returned within budget)  
- Tests executed: ctest 23/23 + 27/27 green  
- Out-of-scope: `deps/`, `build*/` deep read; 878 tracked source files — agents sampled hotspots  
- Critical finding verified by orchestrator: `web.c:310` open-auth comment confirmed