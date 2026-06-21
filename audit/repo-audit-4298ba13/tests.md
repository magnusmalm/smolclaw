# Test Coverage Audit — smolclaw

**Audit ID:** repo-audit-4298ba13  
**Date:** 2026-06-21  
**Scope:** Full repository (read-only source review + test execution)

---

## Test inventory

### Entrypoints

| Entrypoint | Location | Notes |
|------------|----------|-------|
| **CMake + ctest** (primary) | `CMakeLists.txt:484–648` | `enable_testing()`; per-module executables from `tests/test_*.c`; `test_e2e` standalone |
| **CI** | `.gitea/workflows/ci.yml` | Matrix: gcc/clang × full/minimal; `ctest --test-dir build --output-on-failure` |
| **Release build** | `scripts/release-build.sh:86–88` | Runs ctest with `-E test_e2e` (e2e excluded intentionally) |
| **Build matrix** | `scripts/test_matrix.sh` | Tiered full/minimal/musl/cross-compile; native ctest per build dir |
| **Docker** | `Dockerfile:24` | `ctest --output-on-failure` in image build |
| **Manual security suite** | `tests/test_security_prod.c` | Built via `add_executable(test_security_prod …)` but **EXCLUDE_FROM_ALL** and **not registered in ctest** (`CMakeLists.txt:645–648`) |
| **Docs / README** | `README.md:79`, `docs/RELEASING.md:27` | Standard `ctest --test-dir build` |

### Test file inventory (43 sources)

**Core (always compiled):** `test_str`, `test_glob`, `test_config`, `test_session`, `test_tools`, `test_schema_validate`, `test_providers`, `test_pairing`, `test_agent`, `test_sandbox`, `test_memory_tools`, `test_memory_namespaced`, `test_context_isolation`, `test_session_isolation`, `test_gateway_routing`, `test_curl_common`, `test_cost`

**Feature-gated (CMake `if(SC_ENABLE_*)`):** `test_web_isolation`, `test_sse`, `test_telegram`, `test_discord`, `test_voice`, `test_background`, `test_irc`, `test_mcp`, `test_web`, `test_cron`, `test_heartbeat`, `test_memory_search`, `test_mcp_server`, `test_code_graph`, `test_vault`, `test_updater`, `test_tee`, `test_output_filter`, `test_analytics`, `test_x`, `test_delegate`, `test_camera`

**Outside ctest:** `test_security_prod.c` (~177 `test_*` functions)

**Harness:** `tests/test_main.h` (custom ASSERT/RUN_TEST macros), `tests/mock_http.h` (HTTP mocking for providers/channels)

### Suites run

| Build dir | Command | Result | Tests | Wall time |
|-----------|---------|--------|-------|-----------|
| `build/` (existing dev tree) | `ctest --test-dir build --output-on-failure -j4` | **PASSED** | **23/23** | 5.5s |
| `build-audit/` (fresh configure) | `cmake -B build-audit -S . && cmake --build build-audit -j4 && ctest --test-dir build-audit --output-on-failure -j4` | **PASSED** | **27/27** | 6.6s |

**Note:** Test count varies by Kconfig feature flags. Current `.config` disables many features (e.g. `WEB_TOOLS`, `GIT`, `SPAWN`, `TELEGRAM`). CI full profile uses default cmake (no `defconfig.minimal`); minimal profile copies `configs/defconfig.minimal` and runs a smaller subset (~17 core tests).

### Critical-path coverage map

| Area | Source | Test file(s) | CI coverage |
|------|--------|--------------|-------------|
| **Sandbox (Landlock + seccomp)** | `src/util/sandbox.c`, `src/tools/shell.c` | `test_sandbox.c` (8 cases: etc write, workspace, home, mount, disabled) | ✅ core |
| **Gateway routing** | `src/gateway_route.h`, `src/main.c:gateway_process_message` | `test_gateway_routing.c` (decision helper + bus round-trip + `run_repo_dir` safety) | ✅ core; **full gateway handler untested** |
| **Session isolation** | `src/agent.c`, `src/session.c`, `src/context.c` | `test_session_isolation.c`, `test_context_isolation.c`, `test_web_isolation.c` | ✅ core (+ web if enabled) |
| **Tool registry / filesystem / exec** | `src/tools/*` | `test_tools.c` (130+ assertions; secrets, allowlist, audit, conditional git/spawn) | ✅ core |
| **Prompt injection guard** | `src/util/prompt_guard.c` (used in `agent_turn.c`, `memory_tools.c`, `scratchpad.c`) | **Only** `test_security_prod.c` | ❌ not in ctest |
| **SSRF / web_fetch** | `src/tools/web.c` | `test_web.c` | ❌ gated on `SC_ENABLE_WEB_TOOLS` (off in current `.config`) |
| **Secrets redaction** | `src/util/secrets.c` | `test_tools.c` (basic); extensive cases in `test_security_prod.c` | ⚠️ partial in CI |
| **Pairing / auth** | `src/pairing.c` | `test_pairing.c` | ✅ core |
| **Providers / HTTP** | `src/providers/*` | `test_providers.c` (JSON + mock HTTP integration) | ✅ core |
| **Vault encryption** | `src/util/vault.c` | `test_vault.c` | ⚠️ feature-gated |
| **E2E CLI** | `src/main.c` | `test_e2e.c` | ⚠️ hardcoded `./build/smolclaw` path |
| **Gitea / worktree / notify / skill / host tools** | `src/tools/gitea.c`, `worktree.c`, `notify.c`, `skill_tool.c`, `host.c` | **None** | ❌ |
| **Channel manager** | `src/channels/manager.c` | **None** (individual channels tested) | ❌ |
| **Agent turn loop** | `src/agent_turn.c` | Indirect via `test_agent.c` (`sc_agent_process_direct`) | ⚠️ no prompt_guard path in CI tests |

### Test quality observations

- **Mock-heavy but appropriate:** Provider/channel tests use `mock_http.h` for real libcurl round-trips to a local mock server — good integration balance.
- **Agent tests bypass gateway:** `test_agent.c` and `test_session_isolation.c` call `sc_agent_process_direct` / `sc_agent_process_isolated` directly; the `gateway_process_message` wiring in `src/main.c:1763` is never exercised end-to-end (documented gap that motivated `test_gateway_routing.c`).
- **Flaky patterns (timing):** `test_tee.c` (`usleep(1100000)`), `test_cost.c` (`sleep(2)`), `test_memory_namespaced.c` (`sleep(1)`), `test_background.c` (`usleep(200000)`), `test_agent.c` (`usleep(10000)`). No seeded RNG issues found.
- **Environment assumptions:** `test_sandbox.c` asserts Landlock+seccomp on "Linux 6.1"; no cross-arch (aarch64/arm) sandbox filter tests despite arch-specific seccomp code in `src/util/sandbox.c:34–40`.

### CI assessment

`.gitea/workflows/ci.yml` runs ctest on every push/PR to `master` across 4 matrix cells (gcc/clang × full/minimal). **Gaps:**

1. `test_security_prod` never runs in CI.
2. Minimal profile skips all feature-gated suites (web, channels, vault, etc.).
3. `test_e2e` may exercise a **stale binary** when build dir ≠ `build/` (see gap below).
4. No musl/cross-compile in CI (only in `scripts/test_matrix.sh` locally).

---

## Coverage gaps (prioritized)

### 1. Production security suite excluded from automated CI

- **Severity:** critical
- **Untested behavior in CI:** ~177 security integration tests covering prompt injection (`sc_prompt_guard_*`), SSRF, tool allowlist/denylist with prod config, rate limiting, exec sandbox with real config, memory-write guards, pairing enforcement, and cross-layer policy checks.
- **Location:** `tests/test_security_prod.c`; `CMakeLists.txt:645–648` (`EXCLUDE_FROM_ALL`, no `add_test`)
- **Recommended test:** Register a CI-safe subset (e.g. prompt_guard, secrets, allowlist, SSRF) as standalone ctest targets that use fixture configs under `tests/fixtures/` instead of `~/.smolclaw/config.json`; run full `test_security_prod` as optional nightly job.
- **Status:** open

### 2. Prompt injection guard has zero ctest coverage

- **Severity:** critical
- **Untested behavior:** `sc_prompt_guard_scan` / `sc_prompt_guard_scan_high` integration in `agent_turn.c:599–611`, `agent_session.c:148`, `memory_tools.c:145–210`, `scratchpad.c:84` — injection blocking on inbound content and memory writes.
- **Location:** `src/util/prompt_guard.c`; only tested in `test_security_prod.c` (manual)
- **Recommended test:** Port the 10+ prompt_guard unit tests from `test_security_prod.c` into a new `test_prompt_guard.c` (always in `TEST_SOURCES`) with evasion cases (whitespace, tabs, control tokens).
- **Status:** open

### 3. Web tools / SSRF suite not built in default or minimal configs

- **Severity:** high
- **Untested behavior:** `web_fetch` HTML/JSON parsing, truncation, SSRF blocks for CGNAT/reserved ranges, `sc_web_set_ssrf_bypass` guard — all in `test_web.c`.
- **Location:** `src/tools/web.c`; `tests/test_web.c` (requires `SC_ENABLE_WEB_TOOLS`)
- **Recommended test:** Enable `WEB_TOOLS` in at least one CI matrix cell (full profile should turn it on by default, or add explicit `CONFIG_SC_ENABLE_WEB_TOOLS=y` in CI configure step); add regression test for each newly discovered SSRF bypass class.
- **Status:** open

### 4. Gateway handler (`gateway_process_message`) lacks integration test

- **Severity:** high
- **Untested behavior:** Full dispatch path in `src/main.c:1763` — workspace swap on `run_repo_dir`, tool-registry mutation, choice between `sc_agent_process_isolated` vs `sc_agent_process_channel`, typing-thread side effects. Regression that motivated `test_gateway_routing.c` (commit 7226204) bypassed unit tests because they called isolated path directly.
- **Location:** `src/main.c:1763–1812`; `tests/test_gateway_routing.c` (helper only)
- **Recommended test:** Integration test that publishes inbound messages on `sc_bus`, invokes a test-visible gateway callback (or extracts `gateway_process_message` to a testable module), and asserts the correct agent entrypoint is called with preserved `namespace_id` and workspace.
- **Status:** open

### 5. E2E test hardcodes `./build/smolclaw` binary path

- **Severity:** high
- **Untested behavior:** When ctest runs from `build-audit/`, `build-release-*`, or any non-`build/` directory, `test_e2e.c:13` still invokes `./build/smolclaw` — potentially a **different/stale binary** than the one just compiled. Release script works around this with `-E test_e2e`.
- **Location:** `tests/test_e2e.c:13`; `scripts/release-build.sh:87–88`
- **Recommended test:** Pass binary path via CMake `target_compile_definitions(test_e2e PRIVATE SC_TEST_BINARY="$<TARGET_FILE:smolclaw>")` or environment variable set in `add_test` `ENVIRONMENT` property; assert e2e runs the same binary as the current build.
- **Status:** open

### 6. Git tool security tests feature-gated off

- **Severity:** high
- **Untested behavior:** Blocking of dangerous git flags (`-c`, `--config`), push deny-by-default, allowlist enforcement — `test_git_blocks_config_flag`, `test_git_push_deny_by_default` in `test_tools.c`.
- **Location:** `tests/test_tools.c:1428–1567` (`#if SC_ENABLE_GIT`); `src/tools/git.c`
- **Recommended test:** Enable `SC_ENABLE_GIT` in CI full profile; keep security-flag tests in unconditional core tests or a dedicated `test_git.c`.
- **Status:** open

### 7. Gitea, worktree, notify, skill, and host tools untested

- **Severity:** medium
- **Untested behavior:** Tool creation, parameter validation, path/command restrictions for `src/tools/gitea.c`, `worktree.c`, `notify.c`, `skill_tool.c`, `host.c`.
- **Location:** `src/tools/gitea.c`, `worktree.c`, `notify.c`, `skill_tool.c`, `host.c` — no matching `tests/test_*`
- **Recommended test:** Mirror `test_git_blocks_config_flag` pattern: schema validation, deny dangerous args, workspace boundary checks per tool.
- **Status:** open

### 8. Sandbox tests lack cross-architecture and fallback coverage

- **Severity:** medium
- **Untested behavior:** seccomp BPF filter arch mapping (`SC_AUDIT_ARCH` for x86_64/aarch64/arm in `src/util/sandbox.c:34–40`); graceful degradation when Landlock/seccomp unavailable (CI runs only on Linux 6.1+ with both available).
- **Location:** `src/util/sandbox.c`; `tests/test_sandbox.c:49–54`
- **Recommended test:** Run `test_sandbox` under QEMU aarch64 in `test_matrix.sh` Tier 3; add test with `sandbox_enabled=0` simulating unsupported kernel (mock `sc_sandbox_available` return).
- **Status:** open

### 9. Spawn tool depth/recursion limits lightly tested

- **Severity:** medium
- **Untested behavior:** `test_spawn_tool` only validates schema and missing-agent error (`test_tools.c:1389–1425`); real spawn execution and depth limits tested only in `test_agent.c` (mocked) and `test_security_prod.c` (manual).
- **Location:** `src/tools/spawn.c`; `tests/test_tools.c`, `tests/test_agent.c:546`
- **Recommended test:** Unit test spawn depth counter exhaustion and parent-child agent isolation without full LLM mock stack.
- **Status:** open

### 10. Timing-sensitive tests may flake on slow CI runners

- **Severity:** low
- **Untested behavior:** N/A — existing tests may **fail intermittently** on overloaded runners.
- **Location:** `tests/test_tee.c:109`, `tests/test_cost.c:141`, `tests/test_memory_namespaced.c:378`
- **Recommended test:** Replace wall-clock sleeps with injected clock interfaces or widen tolerances; mark `@slow` and run in dedicated CI job.
- **Status:** open

---

## Module → test mapping summary

| `src/` module | Test coverage |
|---------------|---------------|
| `util/sandbox.c` | `test_sandbox.c` ✅ |
| `util/secrets.c` | `test_tools.c` ✅ (basic) |
| `util/prompt_guard.c` | `test_security_prod.c` only ❌ |
| `util/vault.c` | `test_vault.c` (gated) |
| `gateway_route.h` / `main.c` gateway | `test_gateway_routing.c` ⚠️ partial |
| `tools/shell.c`, `filesystem.c` | `test_tools.c` ✅ |
| `tools/web.c` | `test_web.c` (gated) |
| `tools/git.c` | `test_tools.c` (gated) |
| `tools/gitea.c`, `worktree.c`, `notify.c`, `skill_tool.c`, `host.c` | ❌ none |
| `tools/spawn.c` | `test_tools.c` + `test_agent.c` (gated/partial) |
| `agent.c`, `agent_turn.c`, `agent_session.c` | `test_agent.c`, `test_session_isolation.c` ⚠️ |
| `channels/web.c` | `test_web_isolation.c` (gated) |
| `channels/telegram.c`, `discord.c`, `irc.c`, `x.c` | respective `test_*.c` (gated) |
| `channels/manager.c`, `slack.c` | ❌ none |
| `providers/*` | `test_providers.c` ✅ |
| `mcp/client.c`, `mcp/server.c` | `test_mcp.c`, `test_mcp_server.c` (gated) |
| `pairing.c`, `config.c`, `session.c` | `test_pairing.c`, `test_config.c`, `test_session.c` ✅ |
| `memory.c`, `memory_compact.c` | `test_memory_tools.c`, `test_memory_namespaced.c` ⚠️ (no compact) |
| `backup.c` | `test_config.c:test_config_backup` ⚠️ partial |

---

## Summary (3 lines)

**43 test sources / 17–40+ ctest targets** depending on Kconfig; **23/23** (`build/`) and **27/27** (`build-audit/`) passed in this audit. Coverage is strong for core agent, sandbox exec, session isolation, and provider parsing, but **critical security paths (prompt_guard, prod security suite, SSRF/web_fetch, git flag blocking) are absent from routine CI** due to feature flags and `test_security_prod` exclusion. Top risks: undetected prompt-injection regressions, stale e2e binary testing, and no integration test for `gateway_process_message`.