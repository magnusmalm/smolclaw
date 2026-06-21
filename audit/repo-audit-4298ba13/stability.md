# Stability Audit Report — smolclaw

**Agent:** stability  
**Scope:** Full repo (prioritized: `src/`, `tests/`, `scripts/`; excluded: `build*/`, `deps/`)  
**Date:** 2026-06-21  
**Status:** Partial audit (time/tool budget); findings are open unless noted.

## Executive Summary

Smolclaw's gateway bus, exec/sandbox path, and SQLite FTS memory index are the highest-risk stability surfaces. The most serious correctness issue is **unsynchronized concurrent use of a single `sqlite3` connection and its prepared statements** when read-only tools run in parallel (`agent_turn.c`). Exec safety has a **deny-pattern compile failure path** that can leave `regex_t` objects in an undefined state yet still consulted by `regexec`. Sandbox Landlock setup **silently skips failed path rules**, allowing children to run with weaker filesystem isolation than intended. Gateway message bus drops inbound/outbound traffic at depth 1024 with only a log line.

| Severity | Count |
|----------|-------|
| critical | 0 |
| high     | 3 |
| medium   | 10 |
| low      | 5 |
| **Total**| **18** |

---

## Findings

### Parallel read-only tools race on shared SQLite index
- Severity: high
- Location: src/agent_turn.c:1336-1373, src/memory_index.c:272-320, src/tools/memory_search.c:60-61, src/tools/context_tools.c:62
- Description: `agent_turn.c` batches consecutive read-only tools (`memory_search`, `context_search`, etc.) and executes them in parallel via `pthread_create`. All of these share one `sc_memory_index_t` per agent, backed by a single `sqlite3 *db` and reused `sqlite3_stmt *` handles. SQLite requires external serialization when one connection is used across threads; prepared statements must not be reset/stepped concurrently.
- Failure mode: Concurrent `sqlite3_reset`/`sqlite3_bind_*`/`sqlite3_step` on `stmt_search`, `stmt_search_recency`, `stmt_search_prefix`, or write statements causes `SQLITE_MISUSE`, assertion failures (debug builds), wrong search results, or database corruption. Same connection is also written via `memory_index_cb` during memory append/consolidation and host inventory indexing.
- Suggested fix: Serialize all `sc_memory_index_*` access behind a mutex (or use `sqlite3_open` per thread with WAL). Disable parallel execution for any tool touching `memory_index` until guarded. Alternatively open a read-only duplicate connection for searches.
- Status: open

### Deny-pattern regcomp failures leave undefined regex state
- Severity: high
- Location: src/tools/exec_common.c:49-62, src/tools/exec_common.c:75-81
- Description: `sc_deny_list_init` logs a warning when `regcomp` fails but still returns 0. Failed slots remain zero-initialized `regex_t` values that were never compiled. `sc_deny_list_matches` calls `regexec` on every pattern unconditionally.
- Failure mode: Undefined behavior or false negatives on `regexec` → dangerous shell commands pass the deny guard. Security regression is silent (init reports success).
- Suggested fix: On any `regcomp` failure, free compiled patterns, return -1 from init, and refuse to register exec/shell tools. Track per-pattern `compiled` flags and skip or fail closed on errors.
- Status: open

### Landlock path-rule failures are silently ignored
- Severity: high
- Location: src/util/sandbox.c:134-147, src/util/sandbox.c:187-224
- Description: `ll_add_path_rule` returns 0 when `open(O_PATH)` fails (expected) **and** does not propagate failures from `ll_add_rule`. `apply_landlock` never checks return values from any `ll_add_path_rule` call; only `ll_restrict_self` failure aborts Landlock.
- Failure mode: Workspace, `/etc`, `/proc`, or capability paths may be missing from the ruleset while `restrict_self` still succeeds. Sandboxed exec children gain broader filesystem access than configured; failures are invisible in logs.
- Suggested fix: Return and propagate `ll_add_rule` errors for required paths (workspace, capability paths). Log warnings for optional system paths. Fail closed (refuse exec) if mandatory rules cannot be added.
- Status: open

### SQLite statement preparation errors not checked at index open
- Severity: medium
- Location: src/memory_index.c:192-247
- Description: `sc_memory_index_new` calls `sqlite3_prepare_v2` repeatedly without checking return codes. A schema/migration failure after partial prepare can leave `idx` with NULL or stale statement pointers while still returning a live handle (migration failure path closes db; prepare failures do not).
- Failure mode: Later `sc_memory_index_put` or `sc_memory_index_search` dereferences NULL statements → segfault, or steps invalid handles → `SQLITE_MISUSE`.
- Suggested fix: Check every `sqlite3_prepare_v2` result; on failure finalize prepared statements, close db, free idx, return NULL.
- Status: open

### Message bus drops inbound/outbound messages at queue depth 1024
- Severity: medium
- Location: src/bus.c:27-38, src/bus.c:194-201, src/bus.c:238-245
- Description: `queue_push` returns -1 when `count >= SC_BUS_MAX_QUEUE_DEPTH`. Publishers free the message after a WARN log.
- Failure mode: Under burst load (multi-channel gateway, slow agent turns), user messages and outbound replies are dropped with no backpressure to channels. Callers see success from publish APIs but messages never arrive.
- Suggested fix: Block producers with a condition variable (with timeout), surface drop metrics to channels, or apply per-channel fair queuing. Return error to channel layer for retry/NAK.
- Status: open

### Bus pipe notification write failures can desync consumer
- Severity: medium
- Location: src/bus.c:95-101, src/bus.c:206-219
- Description: `notify_pipe` ignores all `write` errors except `EINTR` retry. If the pipe write end is closed or returns `EPIPE`/`EBADF` during shutdown races, a queued message has no corresponding pipe byte.
- Failure mode: `sc_bus_consume_inbound` blocks forever on `read` despite messages in the queue (CLI/agent loop stall). `sc_bus_try_consume_inbound` may read a byte but is less affected.
- Suggested fix: After failed `notify_pipe`, log error and consider waking consumers another way. On shutdown, drain inbound queue explicitly before closing pipes.
- Status: open

### Sandbox tmpdir falls back to shared `/tmp` when mkdtemp fails
- Severity: medium
- Location: src/tools/exec_common.c:250-276
- Description: Per-process sandbox temp dir uses `mkdtemp(proc_tmp)`; on failure `tmpdir` is set to `"/tmp"` and Landlock grants read-write on that path.
- Failure mode: Child processes share global `/tmp` with other users/processes, weakening isolation and enabling tmp-based symlink or quota attacks.
- Suggested fix: Treat `mkdtemp` failure like sandbox apply failure (`_exit(126)`). Optionally use `workspace/.tmp/<pid>` as fallback inside Landlock workspace.
- Status: open

### Exec child ignores chdir failure
- Severity: medium
- Location: src/tools/exec_common.c:278-279
- Description: `chdir(working_dir)` failure is explicitly ignored with comment `/* ignore */`.
- Failure mode: Command runs in unexpected CWD (inherited from parent fork). Relative paths in agent commands read/write wrong locations; workspace restriction semantics diverge from validated `working_dir`.
- Suggested fix: On `chdir` failure, write error to stderr and `_exit(126)`.
- Status: open

### Safe envp construction silently drops variables on malloc failure
- Severity: medium
- Location: src/tools/exec_common.c:28-44
- Description: `sc_exec_build_safe_envp` skips env entries when `malloc` for `key=value` fails, without aborting or logging.
- Failure mode: Child runs with subset of expected environment (e.g. missing `PATH` or `HOME`), causing subtle tool failures or wrong binary resolution inside sandbox.
- Suggested fix: Fail closed: if any required key cannot be allocated, `_exit(126)` in child or abort envp build before fork.
- Status: open

### Chunked memory index rebuild can leave partial index on OOM
- Severity: medium
- Location: src/memory_index.c:358-371
- Description: In `sc_memory_index_put_chunked`, `malloc` failure for a chunk buffer `break`s the loop without rolling back already-indexed chunks for that source.
- Failure mode: FTS index contains subset of chunks; searches return incomplete snippets with no error surfaced to callers. Hash table may disagree with FTS content.
- Suggested fix: On chunk allocation/index failure, call `sc_memory_index_remove_chunked` for the source and return -1.
- Status: open

### Memory index rebuild reads files without size cap
- Severity: medium
- Location: src/memory_index.c:85-101, src/memory_index.c:550-554
- Description: `read_file` in `memory_index.c` loads entire file based on `ftell` with no maximum. Contrast `memory.c` which caps at 256 KB (`MAX_MEMORY_FILE_SIZE`).
- Failure mode: Large or corrupt file sizes during `sc_memory_index_rebuild` cause multi-GB `malloc` attempts → OOM kill or severe memory pressure at gateway startup.
- Suggested fix: Reuse `MAX_MEMORY_FILE_SIZE` cap; skip or truncate oversized files with WARN log.
- Status: open

### Gateway config reload mutates agent state without turn synchronization
- Severity: medium
- Location: src/main.c:2002-2010, src/agent.c:1204-1238
- Description: SIGHUP reload in the gateway loop calls `sc_agent_reload_config` and `sc_channel_manager_reload_config` while a message may be mid-flight in `gateway_process_message` (agent turn, parallel tools, narrowed workspace).
- Failure mode: Limits (`max_tool_calls_per_turn`, allowlists, timeouts) change mid-turn → inconsistent enforcement, surprise tool denial/allow, or truncated turns without clean error to user.
- Suggested fix: Defer reload until no active turn (flag + apply between messages), or snapshot config per turn at `gateway_process_message` entry.
- Status: open

### State and memory directory creation ignores mkdir errors
- Severity: medium
- Location: src/state.c:80-84, src/memory.c:195, src/memory.c:225-235, src/memory.c:142-153
- Description: Multiple `mkdir(..., 0755)` calls ignore return values. `ensure_parent_dir` in memory.c likewise ignores failures.
- Failure mode: Subsequent `state.json` save or memory file writes fail later with ENOENT; errors surface far from root cause. `sc_state_set_last_channel` returns save failure but startup already proceeded without durable state dir.
- Suggested fix: Check `mkdir`/`mkdir` recursive helper; log ERROR and fail `sc_state_new` / `sc_memory_new` if workspace subdirs cannot be created.
- Status: open

### Isolated memory long-term write silently succeeds as no-op
- Severity: low
- Location: src/memory.c:261-268
- Description: `sc_memory_write_long_term` returns 0 for namespaced memory without writing (`/* isolated: silently drop */`).
- Failure mode: Callers interpret return 0 as success; long-term memory never persisted with no log. Agent state diverges from operator expectation in isolated sessions.
- Suggested fix: Return -1 or a distinct code; log at DEBUG/WARN when dropping.
- Status: open

### sqlite3 intermediate steps in put/remove ignore error codes
- Severity: low
- Location: src/memory_index.c:277-300, src/memory_index.c:310-317
- Description: Delete/hash update steps in `sc_memory_index_put` and `sc_memory_index_remove` do not check `sqlite3_step` return values; only the final insert is validated.
- Failure mode: Stale FTS rows or hash metadata after failed DELETE; incremental rebuild skips reindex (`needs_reindex` thinks file unchanged). Search quality degrades silently.
- Suggested fix: Check all `sqlite3_step` results; wrap put/remove in explicit transactions.
- Status: open

### Discord heartbeat thread creation failure proceeds without heartbeat
- Severity: low
- Location: src/channels/discord.c:500-503
- Description: On `GW_HELLO`, if `pthread_create` for heartbeat fails, gateway still calls `gw_identify` with only an implicit log from pthread (none here).
- Failure mode: Connection identified without heartbeats → server closes socket → reconnect loop; extra churn, missed messages during flap.
- Suggested fix: Log ERROR and treat as reconnect-worthy; do not identify until heartbeat thread is running.
- Status: open

### Audit log write/fflush errors ignored
- Severity: low
- Location: src/audit.c:175-201, src/audit.c:244-251
- Description: `fputs`/`fprintf`/`fflush` on audit file have no error checking.
- Failure mode: Disk full or permission errors leave operators without compliance trail, believing tools were audited.
- Suggested fix: Check `fflush`/`ferror`; rotate/disable with explicit ERROR log.
- Status: open

### pthread mutex init return values unchecked in bus and channels
- Severity: low
- Location: src/bus.c:23, src/channels/web.c:1450, src/channels/base.c:21, src/rate_limit.c:39
- Description: `pthread_mutex_init(..., NULL)` return codes are not checked (ENOMEM, EPERM).
- Failure mode: Subsequent `pthread_mutex_lock` on uninitialized mutex → undefined behavior or deadlock.
- Suggested fix: Check init return; fail channel/bus creation on error.
- Status: open

### Seccomp wrong-arch syscall bail allows all syscalls
- Severity: low
- Location: src/util/sandbox.c:283-285
- Description: Documented limitation: BPF filter returns `SECCOMP_RET_ALLOW` when `arch != SC_AUDIT_ARCH` (e.g. QEMU user emulation).
- Failure mode: Denylist bypass under cross-arch execution; mount/ptrace-class syscalls permitted.
- Suggested fix: Accept as documented risk or switch to `SECCOMP_RET_KILL` for arch mismatch in hardened profiles.
- Status: open

---

## Areas Reviewed (no issue filed)

- **Gateway routing decision** (`src/gateway_route.h`): `sc_gateway_should_isolate` and `sc_gateway_run_repo_dir_safe` are well-guarded; covered by `tests/test_gateway_routing.c`.
- **Exec refusal on sandbox apply failure** (`src/tools/exec_common.c:268-273`): Child exits 126 if `sc_sandbox_apply` returns non-zero — good fail-closed behavior.
- **Shell timeout handling** (`src/tools/shell.c:264-271`): Process group kill + `waitpid` is correct.
- **Bus queue mutex**: Inbound/outbound queues are mutex-protected; drops are due to depth policy, not races.
- **Discord reconnect heartbeat join** (`src/channels/discord.c:599-603`): Heartbeat thread joined between reconnects within gateway thread loop.

---

## Recommended Next Steps (priority order)

1. Add mutex around `sc_memory_index_t` (or disable parallel search tools) — fixes highest crash/corruption risk.
2. Harden `sc_deny_list_init` to fail closed on `regcomp` errors.
3. Propagate Landlock `ll_add_rule` failures for mandatory paths; add integration test for partial rule failure.
4. Cap `memory_index.c` `read_file` and check SQLite prepare/step return codes.
5. Add gateway queue backpressure or explicit drop signaling to channels.

---

## Audit Metadata

- **Tool calls used:** ~35 (at budget limit)
- **Files deeply traced:** `util/sandbox.c`, `tools/exec_common.c`, `tools/shell.c`, `tools/background.c`, `bus.c`, `memory_index.c`, `memory.c`, `state.c`, `agent_turn.c`, `main.c` (gateway), `gateway_route.h`, `channels/discord.c`, `channels/web.c`, `tools/registry.c`
- **Tests noted:** `tests/test_sandbox.c`, `tests/test_gateway_routing.c` — good coverage for sandbox happy path and routing; gaps around SQLite concurrency and deny-list init failure.