# Analyzer sweep — cd7315e — 2026-07-12 (quick tier)

Produced by the `/analyzer-sweep` skill. Shares this directory with the
crystal-box retest at the same commit; `REPORT.md` is crystal-box-owned and
untouched. Crystal-box Step 3 should ingest `artifacts/analyzer-sweep-triage.md`
instead of re-running these tools at this SHA.

## Run parameters

- Commit: `cd7315e` (**dirty tree** — untracked CI workflows + audit artifacts;
  `src/` itself unmodified vs HEAD)
- Tier: `--quick` (static only; no sanitizer/valgrind passes)
- Build: `build-sweep/` Debug + compile_commands, **all 15 default-off
  `SC_ENABLE_*` features ON** (X, SIGNAL, COMPANION, GITEA, CAMERA, X_TOOLS,
  VOICE, CODE_GRAPH, OUTPUT_FILTER, ANALYTICS, DELEGATE, PROJECT_MEMORY,
  SESSION_SEARCH, MOA, XAI_OAUTH; SC_STRICT_SECURITY left at default n).
  Build clean: 0 errors, 0 implicit declarations.
- Scope: `src/` (111 compile units). **Vendored `deps/cJSON`, `deps/sqlite3`
  excluded** from analysis focus.

## Tools

| Tool | Version | Result | Artifact |
|------|---------|--------|----------|
| cppcheck | 2.10 | 23 findings | `artifacts/cppcheck.xml` |
| clang-tidy (`clang-analyzer-*,bugprone-*,cert-*,concurrency-*`) | 14.0.6 | 996 warnings | `artifacts/clang-tidy.log` |
| GCC `-fanalyzer` | 12.2.0 | 42 warnings | `artifacts/gcc-fanalyzer.log` |
| semgrep `p/c` + `p/security-audit` | (see tool-versions) | 25 findings (11 rules, 231 files) | `artifacts/semgrep.sweep.json` |
| CodeQL / Infer | — | **not installed** — covered by `.github/workflows/codeql.yml` on GitHub | — |

Commands + exit codes: `artifacts/commands.sweep.log` (sweep-specific name —
`commands.log` in this dir is crystal-box-owned). Versions:
`artifacts/tool-versions.txt`.

## Verdict counts (after code-site verification)

| Verdict | Count |
|---------|-------|
| REAL | 3 (S-01 host.c null-deref inconsistency, S-03 agent.c realloc leak, S-05 claude.c unchecked calloc) |
| LIKELY | 2 (S-02 web_authorize NULL path, S-04 cron job leak) |
| NEEDS-REVIEW | 2 classes (S-06 session.c error-path leaks ×10, S-07 xdg-open system()) + concurrency-mt-unsafe class (117) |
| FP (verified) | 11 rows incl. all semgrep double-free/UAF hits |
| Bulk noise | ~870 warnings across 9 classes (see triage §Bulk) |

All REAL/LIKELY findings are **Low severity** — OOM paths, guard
inconsistencies, and dead-branch derefs. No new Elevated+ candidates surfaced;
consistent with the crystal-box retest closing SML-001/002/006.

## Deviations & limitations

- `-fanalyzer` as a whole-build pass OOM-killed cc1 on `deps/sqlite3/sqlite3.c`;
  rerun as a per-file pass over src/ units only (deps excluded by design anyway).
- clang-tidy restricted to `src/.*` (vendored SQLite would dominate runtime and
  findings). Vendored code is therefore **unswept** — upstream-tracked.
- Quick tier: no dynamic evidence. The 117 `concurrency-mt-unsafe` hits and
  S-06 leak cluster are exactly what the `--full` ASan/TSan ctest passes would
  settle — recommended next run.
- semgrep ran unsandboxed (needs `~/.semgrep` write + registry fetch).

## Build dirs left behind (manual cleanup)

- `build-sweep/` (baseline + compile_commands)
- `build-sweep-fanalyzer/` (partial — failed at sqlite, superseded by per-file pass)
