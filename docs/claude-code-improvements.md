# smolclaw: Improvements Inspired by Claude Code CLI

**Date:** 2026-03-31
**Source analysis:** internal cross-codebase comparison vs the Claude Code CLI (not tracked in this repo)
**Claude Code source:** `instructkr/claude-code` (Anthropic CLI, ~512K LOC TypeScript)

This document extracts the recommendations from the cross-codebase comparison
that apply specifically to smolclaw, adapted to its C11 architecture and
existing patterns.

---

## What smolclaw already does better than Claude Code

Before the improvement list, it's worth noting where smolclaw is ahead:

- **OS-level sandboxing** (Landlock + seccomp-bpf) — Claude Code has none
- **Multiplexed tool results** (for_llm / for_user / silent / async / error)
  — Claude Code's tool results are flat text
- **Pre/post tool hooks** on the registry — more composable than Claude Code's
  separate permission system
- **Message bus** decouples channels from the agent — Claude Code's engine is
  tightly coupled
- **Branching session tree** with `branch()` / `active_leaf()` — Claude Code
  has linear history only
- **Prompt injection scanning** (`prompt_guard.h`) — Claude Code mentions it
  in the system prompt but has no dedicated detection layer
- **Static binary, zero deps** — Claude Code requires Bun + npm
- **Kconfig feature selection** — build exactly what you need

---

## Improvements

### P0 — High Impact

#### 1. Tool Result Size Management

**Ref:** Comparison doc R1

**Problem:** When `shell` or `file_read` returns a large output (e.g., a
full log file), the entire result enters the LLM context. This wastes tokens
and can blow out the context window. The existing `max_output_chars` config
field truncates the result, but the truncated portion is lost — the LLM
can't access it.

**Claude Code approach:** Cap tool results at 50K chars per tool and 200K
aggregate per turn. Oversized results are written to disk and replaced with
a truncated preview plus a file path. The LLM can then use `file_read` on
the saved file to access specific sections.

**Implementation in smolclaw:**

Touch points: `src/tools/registry.c` (`sc_tool_registry_execute`)

After `tool->execute()` returns, check result size. If oversized, persist
and replace:

```c
#define SC_MAX_RESULT_CHARS  50000
#define SC_RESULT_PREVIEW    2000

// In sc_tool_registry_execute(), after execute() and post-hooks:
if (result->for_llm && strlen(result->for_llm) > SC_MAX_RESULT_CHARS) {
    // 1. Build output path
    char path[512];
    snprintf(path, sizeof(path), "%s/tool_outputs/%s_%ld.txt",
             workspace, name, (long)time(NULL));
    sc_mkdir_p(dirname_copy(path));  // ensure dir exists

    // 2. Write full output
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(result->for_llm, f);
        fclose(f);
    }

    // 3. Replace for_llm with preview + path reference
    size_t full_len = strlen(result->for_llm);
    char *preview = sc_strndup(result->for_llm, SC_RESULT_PREVIEW);
    free(result->for_llm);
    sc_strbuf_t buf = {0};
    sc_strbuf_init(&buf);
    sc_strbuf_appendf(&buf,
        "[Truncated: %zu chars total. Full output saved to %s. "
        "Use file_read to access specific sections.]\n%s...",
        full_len, path, preview);
    result->for_llm = sc_strbuf_finish(&buf);
    free(preview);
}
```

Also add an aggregate per-turn cap. In `agent_turn.c`, track cumulative
`for_llm` size across tool calls in a turn. If it exceeds 200K chars, skip
remaining tool calls and tell the LLM to break the task into smaller steps.

**Testing:** Run `shell` with `cat /var/log/syslog` or similar large output.
Verify the file is saved to `workspace/tool_outputs/`, the preview is under
2KB, and the LLM can `file_read` the full output.

---

#### 2. Token-Aware Auto-Compaction

**Ref:** Comparison doc R2

**Problem:** Session summarization is triggered by `session_summary_threshold`
(a fixed message count). This means:
- Short conversations with large tool results may exceed the context window
  before the threshold is hit
- Long conversations with small messages may summarize prematurely

**Claude Code approach:** Two modes:
1. **Auto-compaction** at 85% of context window — summarize old messages,
   keep recent ones
2. **Reactive compaction** on API context-length error — emergency
   compression, keep only last 2 messages + summary, retry

**Implementation in smolclaw:**

Touch points: `src/agent_turn.c`, `src/providers/types.h`

**Step 1: Track cumulative token usage.**

The `sc_usage_info_t` from each LLM response already has `prompt_tokens`.
Use this as the ground truth for context size rather than estimating from
character counts.

```c
// In agent_turn.c, after provider->chat_stream() returns:
int last_prompt_tokens = response->usage.prompt_tokens;
```

**Step 2: Pre-call compaction check.**

Before building the next LLM call, check if the last known prompt token
count is approaching the limit:

```c
// Before the next provider call:
if (last_prompt_tokens > agent->context_window * 85 / 100) {
    LOG_INFO("Auto-compacting: %d tokens / %d window",
             last_prompt_tokens, agent->context_window);
    // Synchronous summarization (not async):
    sc_session_summarize_sync(agent, session_key);
    // Rebuild messages from the now-shorter history
    msgs = sc_context_build_messages(...);
}
```

**Step 3: Reactive compaction on error.**

If the API returns a context-length error (HTTP 400 with "context_length"
in the error body, or provider-specific equivalents):

```c
if (response->http_status == 400 &&
    strstr(response->content, "context_length")) {
    LOG_WARN("Context overflow — reactive compaction");
    sc_session_truncate(agent->sessions, session_key, 2);
    // Re-summarize everything except last 2 messages
    sc_session_summarize_sync(agent, session_key);
    // Retry
    continue;
}
```

**Interaction with existing code:** The existing `session_summary_threshold`
still works as a fallback for providers that don't report token usage. The
token-aware check takes precedence when usage data is available.

---

### P1 — Medium Impact

#### 3. Tool Availability Matrices for Subagents

**Ref:** Comparison doc R3

**Problem:** Subagents spawned via the `spawn` tool inherit the full tool
set. A depth-2 subagent can spawn more subagents (up to depth limit 3),
and all subagents have access to dangerous tools like `cron` and `delegate`.

**Claude Code approach:** Explicit tool restriction per execution context:
- Coordinator: only orchestration tools (AgentTool, SendMessage)
- Workers: no AgentTool, no AskUserQuestion
- Async agents: no interactive tools at all

**Implementation in smolclaw:**

Touch points: `src/tools/spawn.c`, `src/tools/registry.h`

When `spawn` creates a child agent, apply depth-based restrictions:

```c
// In spawn tool execute(), after creating child agent:
static const char *depth1_deny[] = {"spawn", "delegate", "cron"};
static const char *depth2_deny[] = {"spawn", "delegate", "cron",
                                     "notify", "converse", "background"};

int depth = get_spawn_depth(ctx);  // from parent chain
const char **deny = (depth >= 2) ? depth2_deny : depth1_deny;
int deny_count = (depth >= 2) ? 6 : 3;

// Filter the child's tool allowlist
sc_tool_registry_deny(child_agent->tools, deny, deny_count);
```

Also: in `sc_register_tools_standalone()` (MCP server mode), only register
read-only tools (file_read, memory_read, memory_search) plus explicitly
configured tool allowlists.

---

#### 4. Prompt Caching for Anthropic Provider

**Ref:** Comparison doc R4

**Problem:** The system prompt is rebuilt every turn via
`sc_context_build_system_prompt()`. When using the Anthropic provider, which
supports prompt caching, this means the entire system prompt is re-tokenized
on every turn — wasting API costs.

**Claude Code approach:** Split the system prompt at a boundary marker. Content
above the boundary is cached across turns (identity, instructions, tool
descriptions). Content below (memory, session summary, dynamic context) is
recomputed. Date strings are memoized to avoid midnight cache busts.

**Implementation in smolclaw:**

Touch points: `src/providers/claude.c`, `src/context.c`,
`src/providers/types.h`

**Step 1:** Add a `cache_control` field to `sc_llm_message_t`:

```c
typedef struct {
    char *role;
    char *content;
    // ... existing fields ...
    int cache_control;  // 0 = none, 1 = ephemeral (cache breakpoint)
} sc_llm_message_t;
```

**Step 2:** In `sc_context_build_messages()`, split the system prompt into
two messages: a cached static part (identity + instructions + tool summaries)
and an uncached dynamic part (memory, bootstrap, session summary). Set
`cache_control = 1` on the static part.

**Step 3:** In `claude.c`, when building the API request, emit the
`cache_control` annotation on system messages that have it set:

```json
{
  "role": "system",
  "content": [
    {"type": "text", "text": "..static content..", "cache_control": {"type": "ephemeral"}},
    {"type": "text", "text": "..dynamic content.."}
  ]
}
```

**Cost savings:** For a typical 8K-token system prompt, caching saves ~7K
input tokens per turn after the first. Over a 20-turn conversation, this is
~140K tokens saved (at Sonnet pricing: ~$0.04 saved per conversation).

---

#### 5. Model Fallback with Exponential Backoff

**Ref:** Comparison doc R5

**Problem:** The `fallback_providers` and `fallback_models` arrays exist in
`sc_agent_t`, and `retry_after_secs` is parsed from LLM responses. But the
retry logic may not use exponential backoff or honor the Retry-After header.

**Claude Code approach:** `withRetry.ts` — exponential backoff (1s, 4s, 16s),
then model fallback. Parses `Retry-After` header. After 3 failures on the
primary model, falls back to next in chain.

**Implementation in smolclaw:**

Touch points: `src/agent_turn.c` (the LLM call site)

```c
// Retry loop around provider->chat_stream():
int max_retries = 3;
int backoff_ms = 1000;

for (int attempt = 0; attempt <= max_retries; attempt++) {
    sc_llm_response_t *resp = provider->chat_stream(provider, ...);

    if (resp->http_status == 200)
        break;  // success

    if (resp->http_status == 429 || resp->http_status == 529) {
        int wait = resp->retry_after_secs > 0
                   ? resp->retry_after_secs * 1000
                   : backoff_ms;
        LOG_WARN("Rate limited (HTTP %d), waiting %dms (attempt %d/%d)",
                 resp->http_status, wait, attempt + 1, max_retries);
        usleep(wait * 1000);
        backoff_ms *= 4;  // exponential
        sc_llm_response_free(resp);
        continue;
    }

    // Non-retryable error
    break;
}

// If all retries exhausted, try fallback chain:
if (resp->http_status != 200 && agent->fallback_count > 0) {
    LOG_WARN("Primary model failed, falling back");
    for (int i = 0; i < agent->fallback_count; i++) {
        resp = agent->fallback_providers[i]->chat_stream(
            agent->fallback_providers[i], msgs, msg_count, tools, tool_count,
            agent->fallback_models[i], options, stream_cb, stream_ctx);
        if (resp->http_status == 200)
            break;
    }
}
```

**Verify:** Check if this logic already exists in `agent_turn.c`. If so,
ensure it uses exponential backoff and honors `retry_after_secs`.

---

#### 6. Context Transform for Old Tool Result Compression

**Ref:** Comparison doc R6

**Problem:** Large tool results from earlier turns remain at full size in the
message history, consuming context even when the LLM no longer needs the
details.

**Claude Code approach:** Tool result summarization generates compact
summaries of older tool results.

**Implementation in smolclaw:**

Touch points: `src/agent.c` (transform registration), new file
`src/tools/context_compress.c`

Register a context transform that runs before each LLM call:

```c
// In sc_agent_new(), after other setup:
sc_agent_add_transform(agent, "compress_old_results",
                       compress_old_tool_results, NULL);

// The transform callback:
static int compress_old_tool_results(sc_context_snap_t *snap, void *userdata)
{
    (void)userdata;
    int count = *snap->msg_count;
    // Only compress results older than the last 4 messages
    int cutoff = count > 4 ? count - 4 : 0;

    for (int i = 0; i < cutoff; i++) {
        sc_llm_message_t *msg = &(*snap->msgs)[i];
        if (strcmp(msg->role, "tool") != 0) continue;
        if (!msg->content || strlen(msg->content) < 10000) continue;

        // Replace with truncated version
        char *summary = sc_strndup(msg->content, 500);
        char *replacement;
        asprintf(&replacement, "[Compressed tool result — %zu chars. "
                 "First 500 chars:]\n%s", strlen(msg->content), summary);
        free(msg->content);
        msg->content = replacement;
        free(summary);
    }
    return 0;
}
```

This is a natural fit for the existing `sc_agent_add_transform()` mechanism.
It compresses context incrementally without requiring a full summarization
LLM call.

---

### P2 — Lower Impact

#### 7. Deferred Tool Loading (ToolSearch Pattern)

**Ref:** Comparison doc R7

**Problem:** When many MCP servers are configured, all their tool schemas are
included in every LLM call. This inflates prompt size proportionally to the
number of MCP tools.

**Claude Code approach:** `ToolSearchTool` sends only tool names and one-line
descriptions initially. When the LLM needs a specific tool, it calls
`ToolSearch` to fetch the full schema, and the call is retried with the
schema included.

**When to implement:** Only relevant when total tool count exceeds ~30 (likely
with 3+ MCP servers). Not needed today but worth keeping in mind as MCP
adoption grows.

**Sketch:** Add a `deferred` flag to `sc_tool_t`. Deferred tools are listed
in a `tool_search` tool's output but not included in the `tools` array sent
to the provider. When the LLM calls `tool_search`, return the full schema
for the requested tool and re-inject it into the next provider call.

---

#### 8. Structured Telemetry with Correlation IDs

**Ref:** Comparison doc R16 (cross-cutting)

**Problem:** smolclaw has `analytics.c` and publishes events to smolchat, but
events from different parts of the stack (smolswarm orchestration -> smolclaw
agent execution -> smolchat message log) have no correlation IDs. Debugging
a multi-agent task requires manually searching across multiple log sources.

**Implementation:** Add a `correlation_id` field to:
- `sc_inbound_msg_t` (set by smolswarm's orchestrate endpoint or the
  delegate tool)
- `sc_tool_result_t` (propagated through tool execution)
- smolchat messages (sent via the `/api/send` payload)

Generate a UUID at task start (in the delegate tool or via smolswarm's
`/api/orchestrate`). Pass it through the entire execution chain. smolchat's
search then supports filtering by correlation ID.

---

## Files to Touch (Summary)

| Change | Files | New code est. |
|--------|-------|---------------|
| Tool result size mgmt | `src/tools/registry.c` | ~40 lines |
| Auto-compaction | `src/agent_turn.c` | ~30 lines |
| Reactive compaction | `src/agent_turn.c` | ~20 lines |
| Tool availability matrices | `src/tools/spawn.c`, `src/tools/registry.h` | ~25 lines |
| Prompt caching | `src/providers/claude.c`, `src/context.c`, `src/providers/types.h` | ~60 lines |
| Model fallback + backoff | `src/agent_turn.c` | ~35 lines |
| Old result compression | new `src/tools/context_compress.c` + `src/agent.c` | ~40 lines |
| Deferred tool loading | `src/tools/registry.c`, new tool | ~100 lines |
| Correlation IDs | `src/bus.h`, `src/tools/types.h`, `src/tools/delegate.c` | ~30 lines |

Total: ~380 lines of new code across 7 recommendations.
