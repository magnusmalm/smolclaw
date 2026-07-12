# Penetration Test Report (Deep Mode)

**Target:** smolclaw  
**Repository:** `https://github.com/magnusmalm/smolclaw.git`  
**Commit:** `a1135e9c15b393b83bb11421fb3c4d77af662e91`  
**Date:** 2026-07-12  
**Depth:** deep (standard + Semgrep + AFL++ smoke)  
**Prefix:** SML  
**Prior standard report:** `../2026-07-12-a1135e9/REPORT.md`

## Document Properties

| Field | Value |
|-------|-------|
| Engagement | Crystal-box, agent-assisted, ROS-style |
| Semgrep | 1.169.0 (`~/.local/bin/semgrep`, pipx) |
| AFL++ | 5.02c (`~/.local/bin/afl-fuzz`, built from source → `~/.local`) |
| ASAN/UBSAN | Enabled on fuzz harnesses |
| System apt AFL++ | Not installed (sudo password required); user-space build used instead |

---

# 1 Executive Summary

## 1.1 Introduction

Deep mode re-audit of smolclaw after installing **Semgrep** and **AFL++** on this Debian 12 host. Design/default findings from the standard report remain in force. New tooling did **not** surface additional promoted memory-corruption findings in a short smoke window.

## 1.5 Results In A Nutshell

| Source | Result |
|--------|--------|
| Standard review (carried forward) | **2 Elevated, 4 Moderate, 2 Low** (SML-001…008) |
| Semgrep `p/c` + `p/security-audit` on `src/` | **5 raw hits → 0 promoted** (all false positives / style after triage) |
| AFL++ smoke (~40s × 3 harnesses, ASAN+UBSAN) | **0 crashes, 0 hangs**; corpus growth (queue 67 / 48 / 42) |

**Net production grade:** unchanged — fix SML-001–003 first. Tooling confirms no quick ASAN bombs on IRC parse, path validate, or deny-regex matching under short fuzz.

## 1.6 Summary of Findings

### Carried forward (see standard REPORT)

| ID | Level | Title |
|----|-------|--------|
| SML-001 | Elevated | Open DM policy defaults |
| SML-002 | Elevated | Gateway auto-confirm + denylist gaps |
| SML-003 | Moderate | Sandbox apply fail-open |
| SML-004 | Moderate | Web open without bearer |
| SML-005 | Moderate | SSRF range gaps |
| SML-006 | Moderate | MCP unsandboxed |
| SML-007 | Low | working_dir resolve discard |
| SML-008 | Low | Bearer strcmp timing |

### New from deep tooling

| ID | Level | Title | Status |
|----|-------|--------|--------|
| — | — | No new formal findings promoted | n/a |

Semgrep and AFL outputs are documented under Non-Findings.

---

# 2 Methodology

## 2.1 Planning

1. Install Semgrep (pipx) and AFL++ (user-prefix build from AFLplusplus stable).  
2. Reuse standard threat model / findings.  
3. Semgrep scan: `src/` with `p/c` and `p/security-audit`, exclude `deps/`.  
4. Manual triage of every Semgrep hit.  
5. AFL harnesses for IRC line parse, `sc_validate_path`, deny-pattern matching; ASAN+UBSAN; ~40s smoke each.  
6. Document long-campaign instructions.

## 2.3 Known limitations

- Still **not** a multi-day ROS engagement or ~200h fuzz.  
- IRC harness uses a **local copy** of `sc_irc_parse_message` (kept in sync intent with `src/channels/irc.c`); full `irc.c` not linked (OpenSSL/pthread).  
- Semgrep community rules only — not ROS private CodeQL packs.  
- CodeQL not installed.  
- CASR not used (no crashes to cluster).  
- apt `afl++` package not installed (needs sudo); user-space 5.02c used.

---

# 3 Reconnaissance and Fingerprinting

### Tools now present

```
semgrep 1.169.0     → ~/.local/bin/semgrep
afl-fuzz++5.02c     → ~/.local/bin/afl-fuzz
afl-clang-fast      → ~/.local/bin/afl-clang-fast
```

Source tree: `/home/user/.local/src/AFLplusplus`

### Scans run

| Tool | Command / scope | Artifact |
|------|-----------------|----------|
| Semgrep | `p/c` + `p/security-audit` on `src/` (112 files, 11 rules matched run set) | `artifacts/semgrep.json` |
| AFL++ | `fuzz_irc_parse`, `fuzz_path`, `fuzz_deny` | `artifacts/fuzz/` |

---

# 4 Findings

No new formal findings. Full write-ups for SML-001–008 remain in:

`docs/security-audits/2026-07-12-a1135e9/REPORT.md`

---

# 5 Non-Findings

## 5.1 NF-SEM-001 — Semgrep raw hits (triaged false positives)

Scan summary: **5 findings**, rules run 11, 112 targets.

| # | Rule | Location | Triage |
|---|------|----------|--------|
| 1 | `use-after-free` | `channels/manager.c:265` | **FP.** Pattern free-old then assign `ch->allow_list[i] = sc_strdup(...)` on newly allocated array after `free(ch->allow_list)`. Not UAF. |
| 2 | `insecure-use-printf-fn` | `main.c:576` | **FP.** `printf("Stored '%s'\n", argv[3])` — fixed format string; argv is data. |
| 3 | `insecure-use-printf-fn` | `main.c:622` | **FP.** Same for `printf("Removed '%s'\n", argv[3])`. |
| 4 | `insecure-use-string-copy-fn` | `rate_limit.c:67` | **Noise.** `strncpy(b->key, key, KEY_MAX-1)` followed by explicit `b->key[KEY_MAX-1]='\0'`. Acceptable. |
| 5 | `use-after-free` | `tools/registry.c:122` | **FP.** Same free-then-reallocate pattern as #1 for `allowed_tools`. |

No Semgrep hit elevated to SML-*.

## 5.2 NF-AFL-001 — Fuzz smoke results

Harnesses: `artifacts/harness/`  
Build/smoke script: `artifacts/harness/build_and_smoke.sh`  
`SMOKE_SECS=40`, `AFL_SKIP_CPUFREQ=1`, ASAN+UBSAN.

| Target | Crashes | Hangs | Queue (approx) |
|--------|--------:|------:|---------------:|
| IRC parse | 0 | 0 | 67 |
| Path validate | 0 | 0 | 48 |
| Deny patterns | 0 | 0 | 42 |

Deterministic seed smoke also clean under ASAN.

**Interpretation:** No immediate memory-safety bugs in these three surfaces under short fuzz. Does **not** prove absence of bugs; corpus is young.

## 5.3 NF-AFL-002 — How to run longer campaigns

```bash
export PATH="$HOME/.local/bin:$PATH"
export AFL_SKIP_CPUFREQ=1
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0

H=docs/security-audits/2026-07-12-a1135e9-deep/artifacts
# rebuild
SMOKE_SECS=0 bash $H/harness/build_and_smoke.sh   # or compile steps only

# overnight example (one target)
afl-fuzz -i $H/fuzz/seeds_irc -o $H/fuzz/out_irc_long -V 28800 \
  -- $H/harness/build/fuzz_irc_parse @@
```

Optional: install CASR for crash clustering if crashes appear.

## 5.4 Threat model

Unchanged from standard report. Deep tooling strengthens confidence on **parser memory safety** only; **agent trust-boundary** findings (SML-001/002) dominate residual risk.

---

# 6 Future Work

- Overnight AFL on IRC/path/deny + new harnesses: config JSON load, websocket frames, cJSON tool-arg paths.  
- Install CodeQL CLI + `bear` compile DB for dataflow queries.  
- `sudo apt install afl++` if system packages preferred over `~/.local`.  
- Expand Semgrep with custom rules for `gateway_auto_confirm`, `dm_policy` defaults, `sh -c` exec.  
- Retest SML-* after hardening.

---

# 7 Conclusion

Deep mode successfully stood up a **ROS-closer tool stack** (Semgrep + AFL++/ASAN) on this host without root (AFL via user prefix). Automated tools:

- Did **not** overturn or replace the standard elevated findings.  
- Did **not** find new crash bugs in short fuzz.  
- Did produce a reusable harness kit for continuous fuzzing.

**Still prioritize:** SML-001 (DM defaults), SML-002 (gateway/denylist), SML-003 (sandbox fail-closed).

---

# Appendix A — Install notes (this host)

### Semgrep

```bash
pipx install semgrep   # → ~/.local/bin/semgrep 1.169.0
```

### AFL++

`sudo apt install afl++` failed here (password required). Instead:

```bash
git clone --depth 1 --branch stable \
  https://github.com/AFLplusplus/AFLplusplus.git ~/.local/src/AFLplusplus
cd ~/.local/src/AFLplusplus
make -j$(nproc) source-only
PREFIX=$HOME/.local make install
# afl-fuzz, afl-clang-fast in ~/.local/bin
```

Optional nyx/gcc_plugin modes failed (missing capsone static / gcc-plugin-dev) — not required for LLVM mode.

### PATH

```bash
export PATH="$HOME/.local/bin:$PATH"
```

# Appendix B — Artifact index

| Path | Description |
|------|-------------|
| `artifacts/semgrep.json` | Full Semgrep JSON |
| `artifacts/semgrep-summary.txt` | Short list |
| `artifacts/harness/*.c` | Fuzz harness sources |
| `artifacts/harness/build_and_smoke.sh` | Build + smoke driver |
| `artifacts/harness/build/*` | Instrumented binaries |
| `artifacts/fuzz/out_*/` | AFL output (short run) |
| `artifacts/fuzz/smoke-run.log` | Console log |
| `../2026-07-12-a1135e9/REPORT.md` | Standard findings (authoritative for SML-*) |
