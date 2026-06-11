# Zed Patterns — Actionable Items for smolclaw

Extracted from an internal cross-codebase analysis of the Zed editor's agent patterns (not tracked in this repo).

**Date**: 2026-03-31

---

## Summary

Six patterns from Zed's architecture are directly applicable to smolclaw. Three address known bugs from the code-analysis-report, two improve architecture, one is a low-effort quality-of-life improvement.

---

## Task 1: Arena Allocation for Agent Turn Processing

**Priority**: High
**Effort**: Medium
**Addresses**: H-1, H-2, H-3, H-4, H-11 (unchecked malloc/calloc in provider and SSE code)

### Background

Zed's GPUI framework allocates its entire per-frame element tree in a thread-local arena allocator, then clears the arena after painting. This eliminates individual malloc/free calls for short-lived objects and makes allocation failure a single check point rather than dozens of scattered ones.

### What to Do

1. **Implement `sc_arena_t`** — a bump allocator in `src/util/`:
   ```c
   typedef struct {
       char *base;
       size_t used;
       size_t cap;
   } sc_arena_t;

   sc_arena_t *sc_arena_new(size_t initial_cap);  // e.g., 64KB
   void       *sc_arena_alloc(sc_arena_t *a, size_t n);
   char       *sc_arena_strdup(sc_arena_t *a, const char *s);
   void        sc_arena_reset(sc_arena_t *a);      // Reuse without free
   void        sc_arena_free(sc_arena_t *a);
   ```

2. **Thread the arena through `sc_agent_process_turn()`**:
   - Initialize arena at turn start (or reset a persistent one)
   - Pass arena to `sc_provider_chat()` / `sc_provider_chat_stream()` for response parsing
   - Pass arena to tool result assembly in `agent_turn.c`
   - Pass arena to context builder for intermediate string concatenation
   - Reset arena at turn end

3. **Convert provider code** (`provider_common.c`, `http_provider.c`):
   - Replace `malloc`/`calloc` for response chunks, header parsing, SSE line buffers with `sc_arena_alloc()`
   - The arena check is a single `if (a->used + n > a->cap)` — one place to handle OOM instead of dozens

4. **Keep long-lived allocations on the heap**: Session data, config, tool registry — these outlive a single turn and stay as regular malloc.

### Acceptance Criteria

- [ ] `sc_arena_t` implemented and tested
- [ ] `sc_agent_process_turn()` uses arena for all per-turn allocations
- [ ] Provider response parsing uses arena (fixes H-1, H-2, H-3, H-11)
- [ ] SSE streaming buffer uses arena (fixes H-4)
- [ ] OOM from arena triggers a single clean error path, not undefined behavior
- [ ] No performance regression (arena should be faster than malloc)

---

## Task 2: Structured Task Model with Cancellation

**Priority**: High
**Effort**: Low
**Addresses**: M-8 (summarization thread may not join on shutdown)

### Background

Zed's `Task<R>` type provides structured async work: spawn returns a handle, handle can be polled, awaited, or cancelled. Dropping the handle cancels the work. All outstanding tasks are joined on shutdown.

### What to Do

1. **Implement `sc_task_t`** in `src/util/`:
   ```c
   typedef void *(*sc_task_fn)(void *arg, volatile int *cancel);

   typedef struct sc_task {
       pthread_t thread;
       _Atomic int done;
       _Atomic int cancel;
       void *result;
       void (*cleanup)(void *result);
   } sc_task_t;

   sc_task_t *sc_task_spawn(sc_task_fn work, void *arg);
   bool       sc_task_poll(sc_task_t *t);
   void      *sc_task_join(sc_task_t *t);
   void       sc_task_cancel(sc_task_t *t);
   void       sc_task_free(sc_task_t *t);
   ```

2. **Refactor `sc_agent_session_run_summarization()`**:
   - Return `sc_task_t *` instead of detaching pthread
   - Store task handle in agent struct
   - Check `t->cancel` in summarization loop to support early exit
   - On agent shutdown, call `sc_task_cancel()` then `sc_task_join()` with timeout

3. **Track all outstanding tasks** in agent:
   ```c
   struct sc_agent {
       // ...
       sc_task_t *summarization_task;
       sc_task_t *background_tasks[8];
       int n_background_tasks;
   };
   ```

4. **On `sc_agent_shutdown()`**: iterate all tasks, cancel, join with 5s timeout, then free.

### Acceptance Criteria

- [ ] `sc_task_t` implemented with spawn/poll/join/cancel/free
- [ ] Summarization refactored to use `sc_task_t`
- [ ] Agent shutdown joins all tasks (fixes M-8)
- [ ] Task work function receives cancel flag and checks it periodically
- [ ] No orphaned threads on rapid shutdown

---

## Task 3: Capability-Based MCP Security

**Priority**: High
**Effort**: Medium
**Addresses**: Hardening MCP bridge security beyond current Landlock blanket

### Background

Zed's WASM extensions declare required capabilities in their manifest. The host checks capabilities at load time and enforces them via the sandbox. This is more precise than "sandbox everything with the same rules."

### What to Do

1. **Extend MCP server config** with a `capabilities` field:
   ```json
   {
     "mcp": {
       "servers": {
         "x": {
           "command": ["node", "x-mcp/index.js"],
           "capabilities": {
             "network": ["https://*.x.com", "https://api.x.com"],
             "fs_read": ["~/.config/x-mcp/"],
             "fs_write": [],
             "process": []
           }
         }
       }
     }
   }
   ```

2. **Parse capabilities in `sc_mcp_bridge_start()`**:
   - Validate capability declarations against a known set
   - Log effective permissions at startup

3. **Translate to Landlock rules** per server:
   - `fs_read` → `LANDLOCK_ACCESS_FS_READ_FILE` on listed paths
   - `fs_write` → `LANDLOCK_ACCESS_FS_WRITE_FILE` on listed paths
   - `network` → URL pattern matching (or Landlock net rules on Linux 6.8+)
   - Empty array = deny that class entirely

4. **Translate to seccomp filters** where applicable:
   - `process: []` → deny `execve`, `fork`, `clone` for the subprocess
   - Network restrictions via `connect()` filtering if Landlock net not available

5. **Default behavior**: If no `capabilities` field, fall back to current blanket sandbox (backward compatible).

### Acceptance Criteria

- [ ] Config schema extended with `capabilities` (with JSON schema update)
- [ ] Capability parsing and validation in bridge startup
- [ ] Per-server Landlock rules derived from declared capabilities
- [ ] Seccomp filtering for process execution when `process: []`
- [ ] Backward compatible — missing capabilities field uses existing blanket sandbox
- [ ] Test: MCP server with `fs_read: ["/tmp/test"]` cannot read `/etc/passwd`
- [ ] Documentation updated

---

## Task 4: Layered Context Pipeline

**Priority**: Medium
**Effort**: Medium

### Background

Zed's Display Map transforms text through composable layers: `Buffer → InlayMap → FoldMap → TabMap → WrapMap → BlockMap`. Each layer only knows about the layer below, has independent state, and can be swapped or disabled.

### What to Do

1. **Define a context stage interface**:
   ```c
   typedef struct sc_context_stage {
       const char *name;
       int token_budget;     // Max tokens this stage may consume
       int (*transform)(sc_context_stage_t *self,
                        sc_context_t *input,
                        sc_context_t *output,
                        sc_arena_t *arena);
       void *state;
   } sc_context_stage_t;
   ```

2. **Implement standard stages**:
   - `system_prompt_stage` — Injects system prompt (fixed budget)
   - `memory_stage` — Injects relevant memory entries (budget-capped)
   - `session_history_stage` — Adds conversation history (fills remaining budget)
   - `tool_schema_stage` — Adds tool definitions (can drop low-priority tools if over budget)
   - `mcp_tool_merger_stage` — Merges external MCP tool schemas
   - `token_budget_trimmer_stage` — Final trim pass, drops oldest messages if over total budget

3. **Replace flat context builder** in `sc_context_builder_t`:
   ```c
   sc_context_pipeline_t *pipe = sc_context_pipeline_new(arena);
   sc_context_pipeline_add(pipe, &system_prompt_stage);
   sc_context_pipeline_add(pipe, &memory_stage);
   sc_context_pipeline_add(pipe, &session_history_stage);
   sc_context_pipeline_add(pipe, &tool_schema_stage);
   sc_context_pipeline_add(pipe, &mcp_tool_merger_stage);
   sc_context_pipeline_add(pipe, &token_budget_trimmer_stage);
   sc_context_t *ctx = sc_context_pipeline_execute(pipe);
   ```

4. **Per-stage token accounting**: Each stage reports how many tokens it consumed. Pipeline tracks total. Final trimmer has visibility into all budgets.

### Acceptance Criteria

- [ ] Context stage interface defined
- [ ] At least 4 stages implemented (system prompt, memory, history, tools)
- [ ] Pipeline replaces current flat context builder
- [ ] Token budget enforced per-stage and globally
- [ ] Easy to add/remove/reorder stages
- [ ] Works with arena allocator (Task 1)

---

## Task 5: Session Index with Aggregate Summaries

**Priority**: Medium
**Effort**: High

### Background

Zed's `SumTree<T>` is a B-tree where each node carries aggregate summaries. This enables O(log n) lookups by any summary dimension — byte offset, line count, character count.

### What to Do

1. **Build an in-memory index** over session JSONL nodes:
   ```c
   typedef struct {
       uint32_t node_id;
       uint32_t parent_id;
       uint32_t file_offset;     // Byte offset into JSONL file
       uint16_t depth;
       uint16_t token_count;     // Tokens in this message
       uint32_t subtree_tokens;  // Aggregate: all tokens below this node
   } sc_session_index_entry_t;
   ```

2. **Populate on session load**: Scan JSONL once, build index in sorted array (by node_id). Subtree token counts calculated bottom-up.

3. **Replace linear scans**:
   - `sc_session_branch(node_id)` → binary search in index, then walk parent pointers
   - `sc_session_truncate(n)` → walk active branch from leaf, count messages
   - Token budget calculation → read `subtree_tokens` from branch root

4. **Keep index in sync**: On `sc_session_add_message()`, append to index and update subtree totals up the parent chain.

5. **Optional: persist index** alongside JSONL file (e.g., `.session.idx`) to avoid rebuild on load.

### Acceptance Criteria

- [ ] Index built from JSONL on session load
- [ ] Branch/truncate operations use index (O(log n) instead of O(n))
- [ ] Token budget queries use aggregate summaries
- [ ] Index stays in sync with JSONL writes
- [ ] No regression for sessions under 100 messages (overhead justified for large sessions)

---

## Task 6: Provider Health Tracking for Faster Fallback

**Priority**: Low
**Effort**: Low

### Background

Zed's `LanguageModelRegistry` tracks provider availability and authentication state. Health informs model selection without waiting for timeouts.

### What to Do

1. **Add health state to provider factory**:
   ```c
   typedef struct {
       const char *name;
       enum { SC_PROVIDER_HEALTHY, SC_PROVIDER_RATE_LIMITED,
              SC_PROVIDER_AUTH_EXPIRED, SC_PROVIDER_UNREACHABLE } status;
       time_t status_since;
       time_t retry_after;      // 0 = retry immediately
   } sc_provider_health_t;
   ```

2. **Update health on API responses**:
   - HTTP 429 → `RATE_LIMITED`, set `retry_after` from header or default 60s
   - HTTP 401/403 → `AUTH_EXPIRED`
   - Connection timeout / DNS failure → `UNREACHABLE`, retry after 120s
   - HTTP 200 → `HEALTHY`

3. **Check health before attempting provider** in fallback chain:
   ```c
   // In sc_provider_factory_create() or fallback logic:
   if (health->status != SC_PROVIDER_HEALTHY && time(NULL) < health->retry_after)
       continue;  // Skip to next provider
   ```

4. **Expose in analytics/cost command** so user can see provider health history.

### Acceptance Criteria

- [ ] Provider health struct tracked per-provider in factory
- [ ] HTTP response codes update health state
- [ ] Fallback chain skips unhealthy providers (until retry_after)
- [ ] Health state visible in `smolclaw analytics` or logs
