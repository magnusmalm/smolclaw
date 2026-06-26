# Plan: Checkpoint & Rewind for Agent Turn Recovery

> **Status: IMPLEMENTED (verified 2026-06-26).** This design has shipped.
> `sc_checkpoint_t`, the 2-slot ring buffer (`SC_MAX_CHECKPOINTS`), per-turn
> `rewind_count` cap, and the restore-on-stuck path live in
> `src/agent_internal.h` and `src/agent_turn.c`. This document is retained as
> the design record. Phase 0 task 0.6 is therefore **verify-only** — confirm
> coverage with a repeated-tool-error integration test; do not re-implement.

## Problem

When a model digs itself into a bad conversation state (accumulated error
messages, confused tool outputs), injecting hints into the polluted context
often doesn't help — the model keeps making the same category of mistake.
Options 1-3 (error budget, per-tool-name tracking, model escalation)
mitigate this, but the escalated model still inherits the polluted context.

## Goal

Save conversation state checkpoints after successful tool calls. On stuck
detection or error budget exhaustion, rewind to the last good checkpoint
and retry with a clean context + "previous approach failed" hint.

## Design

### Checkpoint Structure

```c
typedef struct {
    sc_llm_message_t *msgs;   /* Deep copy of message array */
    int msgs_len;
    int iteration;            /* Which iteration this was captured at */
    int tool_calls_so_far;    /* For resuming counters */
} sc_checkpoint_t;
```

### When to Checkpoint

After each **successful** tool execution (result is not an error):
- Deep-copy `tc.msgs` array into a checkpoint slot
- Keep only the last 2 checkpoints (ring buffer) to bound memory

### When to Rewind

Triggered when:
- Error budget hits 3 (the warning threshold) — rewind to last checkpoint
- Per-tool-name error count hits 3 — rewind to last checkpoint
- Model escalation triggers — rewind before retrying with fallback model

### Rewind Behavior

1. Free current `tc.msgs` array
2. Restore from checkpoint (deep copy back)
3. Reset error counters (`tool_error_count`, `tool_name_*`, `recent_calls`)
4. Inject rewind hint message: "Your previous approach failed after N
   attempts. The conversation has been rewound to the last successful
   state. Try a different approach."
5. Continue the iteration loop

### Interaction with Model Escalation (Option 1)

Current flow:
```
error budget exhausted → escalate model → continue with polluted context
```

With checkpoint + rewind:
```
error budget exhausted → rewind to checkpoint → escalate model → continue with clean context
```

The escalated model gets a clean conversation without the failed attempts,
plus a hint about what went wrong. Much higher chance of success.

### Memory Considerations

- Each checkpoint is a deep copy of the message array
- With max 50 iterations and ~4KB average per message, worst case ~200KB per checkpoint
- Keeping only 2 checkpoints bounds this to ~400KB
- Freed at turn end (same lifecycle as `tc.msgs`)

### Implementation

**Files to modify:**
- `src/agent_internal.h` — add `sc_checkpoint_t` struct and fields to `sc_turn_ctx_t`
- `src/agent_turn.c` — checkpoint after successful tools, rewind on errors

**Estimated effort:** ~100 lines of code. The deep-copy infrastructure
(`sc_llm_message_clone`) already exists.

### Risks

- **Infinite rewind loop**: If the model keeps hitting the same error after
  rewind, it could rewind forever. Mitigation: limit rewinds to 2 per turn.
  After that, fall through to error budget hard-stop.
- **Lost progress**: Rewinding discards any partially successful work from
  the failed segment. Acceptable — the model was stuck anyway.
- **Memory spikes**: Deep-copying large message arrays. Mitigated by the
  2-checkpoint ring buffer and existing message array size limits.
