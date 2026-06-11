# Design: Session Isolation for smolclaw

**Status**: Design Complete — Implementation Not Started
**Author**: 2026-05-24 design session
**Last Updated**: 2026-05-24
**Related**: `src/agent_session.c`, `src/context.c`, `src/memory.c`, `src/channels/web.c`

---

## 1. Summary

A single smolclaw agent process (e.g. the smolswarm `researcher`) is shared by many independent callers — different smolswarm tasks, IRC users, MCP clients. Today, every turn the agent runs reads from and writes to a single workspace-wide memory store and a single workspace scratchpad. Consolidated content from one caller's turn leaks into the system prompt of the next caller's turn, and the model continues the prior caller's narrative regardless of the new prompt.

This document specifies **session isolation**: a mechanism by which channels can mark inbound messages as ephemeral, and the agent responds by running them in a per-session memory namespace that neither reads from nor writes to the shared workspace memory.

The design is backwards-compatible (opt-in via web-channel config), preserves the agent's "long-running self" for non-isolated use cases (heartbeat, CLI, direct IRC), and is the smolclaw-side fix for the original v2 plan's Phase 4 ("Ephemeral Research Scratchpad + Memory Hygiene").

---

## 2. Motivation

### 2.1 The contamination class

During multi-workflow reliability testing, two consecutive research runs failed with a distinctive symptom: the researcher's `research_outline` and `research_progress` for one task contained content from an *unrelated earlier caller's* research topic.

Tracing the agent journal showed back-to-back memory consolidations from different workflow sessions sharing the same web-channel token hash:

```
01:53:44  Consolidated memory from session web:<token-hash>:wf-researcher-<id1>
02:04:14  Consolidated memory from session web:<token-hash>:wf-researcher-<id2>
```

Earlier the same day, an unrelated caller had run a research turn under the same web-channel token (the middle component is a hash of the bearer token, shared across all web callers). After that turn finished, smolclaw consolidated its memory and appended to the day's workspace memory file. When the next turn began, the agent's prompt builder loaded the same workspace memory back out, and the LLM — presented with new task instructions plus a heavy load of the prior caller's context (a ~4–5x larger prompt than a clean run) — continued the prior research narrative instead of honoring the new prompt.

Reliability runs that "passed" earlier did so because their workspace memory was already aligned with their own topic from immediately-prior runs. The measured number was an artifact of memory alignment, not of architectural correctness.

### 2.2 Why this matters

Smolclaw was originally designed as a *single-user companion agent*. In that mode, workspace-wide memory is a feature: the agent remembers preferences, file paths, and ongoing decisions across sessions. The smolswarm fleet uses smolclaw differently — a single agent process is *delegated to* by many independent workflows, each with its own task and its own scope. The single-user assumption breaks the fleet's research correctness guarantees.

The fix needs to honor both modes: a CLI user or a heartbeat tick should keep behaving exactly as before, while a delegate call from a workflow should run with a clean slate.

---

## 3. Goals

- **G1**: A delegate call from a workflow must not see content from any prior unrelated session.
- **G2**: Consolidated memory and scratchpad content from a delegate call must not leak into the shared workspace memory.
- **G3**: Within a single delegate session that spans multiple turns (e.g., a multi-turn dialogue with the same `session` name), the session retains its own continuity — its consolidated memory and scratchpad are visible to its own subsequent turns.
- **G4**: Existing non-isolated callers (CLI, heartbeat, direct IRC) are unaffected. No data migration required.
- **G5**: The behavior is opt-in via configuration; default install is unchanged.
- **G6**: Test coverage proves the leak prevention and the back-compat.
- **G7**: Per-session memory directories are reaped after a configurable TTL so isolated sessions don't accumulate disk forever.

## 4. Non-Goals

- **NG1**: Authentication / per-session bearer tokens. The web channel already namespaces sessions by hashed bearer token; this design layers isolation on top, not authentication.
- **NG2**: Reworking smolswarm's delegate protocol. The plumbing only requires the web channel to recognize the existing `wf-*` session-name convention.
- **NG3**: Per-tool sandboxing. Tools already use `restrict_to_workspace`. Isolation here is about memory and prompt context, not filesystem access.
- **NG4**: Persistence beyond the TTL. Isolated sessions are by design ephemeral.

---

## 5. Architecture

### 5.1 Current contamination model (problem)

```
                       workspace/memory/
                         YYYYMM/YYYYMMDD.md  ← do_consolidate appends here
                         MEMORY.md
                       workspace/state/scratchpad.md

  caller A → web channel → agent.run_agent_loop
    → context.build_system_prompt  ← reads workspace/memory/ (LEAK IN)
    → LLM turn ...
    → agent_session.do_consolidate ← writes workspace/memory/ (LEAK OUT)

  caller B → web channel → agent.run_agent_loop
    → context.build_system_prompt  ← reads A's content (CONTAMINATION)
```

Every caller shares the same `workspace/memory/` namespace. Session keys differ per turn (`web:<token>:<session_name>`) but the *memory store* is global to the workspace.

### 5.2 Isolated session model (fix)

```
                       workspace/memory/
                         YYYYMM/YYYYMMDD.md  ← shared (non-isolated only)
                         MEMORY.md
                       workspace/memory/_sessions/<ns>/
                         today.md            ← per-isolated-session consolidation
                         scratchpad.md       ← per-isolated-session compact re-injection

  caller A (wf-foo) → web ch detects pattern → inbound.isolated=true
    → run_agent_loop with isolated context_builder
    → context.build_system_prompt  ← SKIPS workspace/memory/ block (no leak in)
    → LLM turn ...
    → agent_session.do_consolidate → workspace/memory/_sessions/<ns>/today.md
                                     (writes per-session, not shared)

  caller B (wf-bar) → web ch detects pattern → inbound.isolated=true
    → independent <ns> = sha8("web:<token>:wf-bar")
    → cannot read A's _sessions/<ns_A>/ content

  caller C (CLI, "default") → not isolated
    → unchanged behavior: reads/writes workspace/memory/ as before
```

`<ns>` is `sha8(session_key)` — first 16 hex digits of SHA-256 over the full session_key. This guarantees:
- Distinct session_keys map to distinct namespaces (one-way and collision-resistant in the relevant size).
- Same session_key (same caller, same `session` field) maps to the same namespace across turns — preserving G3.
- The namespace value is opaque on disk; operators can map it back via the audit log, which records session_key + ns together.

### 5.3 Channel responsibility split

| Channel | Default isolation behavior | Configurable via |
|---|---|---|
| `web` | Pattern-based: session-name matches `isolation_pattern` ⇒ isolated. Default pattern: `wf-*`. | `channels.web.isolation_pattern` |
| `irc`, `discord`, `telegram`, `slack`, `x`, `cli` | Always non-isolated (unchanged) | — (no config) |

For now only the web channel needs to set isolation, because only the web channel receives smolswarm delegate calls. Other channels keep their existing semantics. The `sc_inbound_msg_t.isolated` flag is wired through generically, so future channels can opt in.

To explicitly disable isolation at the web channel (return to today's behavior), set `isolation_pattern: ""`.

---

## 6. API and configuration

### 6.1 Wire-level: `sc_inbound_msg_t`

`src/bus.h`:

```c
typedef struct {
    /* ...existing fields... */
    int isolated;   /* 0 = shared workspace memory (default); 1 = per-session ns */
} sc_inbound_msg_t;
```

`sc_inbound_msg_new()` gains a trailing `int isolated` parameter. Existing call sites pass `0` (no behavior change). The web channel passes `1` when its pattern matches.

### 6.2 Memory layer: `sc_memory_t`

`src/memory.h`:

```c
/* Existing constructor — unchanged. Returns workspace-wide memory. */
sc_memory_t *sc_memory_new(const char *workspace);

/* New: namespaced (isolated) memory. Writes/reads go under
 * <workspace>/memory/_sessions/<namespace_id>/. The namespace_id
 * is opaque to memory.c — caller-supplied (channel computes it from
 * session_key). Long-term memory reads (sc_memory_read_long_term,
 * sc_memory_get_context) return empty for namespaced instances. */
sc_memory_t *sc_memory_new_namespaced(const char *workspace,
                                       const char *namespace_id);

/* New: best-effort cleanup of per-session memory dirs older than
 * max_age_secs. Returns count of dirs removed. Safe to call from
 * a periodic tick (heartbeat). */
int sc_memory_cleanup_sessions(const char *workspace, int max_age_secs);
```

Internally, `sc_memory_t` gains a `char *namespace_id` (NULL for shared). `today_path()` and `long_term_path()` switch on it.

`sc_memory_get_context()` for a namespaced instance returns the **per-session** today/recent notes only — no shared workspace content. For a shared instance, behavior is unchanged.

### 6.3 Context builder: `sc_context_builder_t`

`src/context.h`:

```c
typedef struct sc_context_builder {
    /* ...existing fields... */
    int is_isolated;   /* 0 = include workspace memory in system prompt (default);
                          1 = skip the workspace memory block entirely */
} sc_context_builder_t;
```

`sc_context_build_system_prompt()` is modified at the `cb->memory` block (`context.c:187-205`): when `cb->is_isolated` is set, the entire `# Memory` section is omitted. The system prompt still includes identity, bootstrap files (`AGENTS.md`, `SOUL.md`), skills, and deferred-tool listings — those are intentionally part of the agent's "self" and survive isolation. Memory specifically is the per-turn-recent context, which is the contamination vector.

### 6.4 Channel config: web

`src/config.h` — `sc_channel_web_config_t`:

```c
typedef struct {
    /* ...existing fields... */
    char *isolation_pattern;   /* glob; default "wf-*"; "" or NULL disables */
} sc_channel_web_config_t;
```

`src/config.c` defaults set `isolation_pattern` to `"wf-*"`. The JSON parser reads `channels.web.isolation_pattern`. The env override is `SMOLCLAW_CHANNELS_WEB_ISOLATION_PATTERN`.

### 6.5 Web channel matching logic

`src/channels/web.c::handle_message_post()` after session_key construction:

```c
const char *iso_pat = wd->isolation_pattern;
int isolated = 0;
if (iso_pat && iso_pat[0] && sess_name) {
    isolated = sc_glob_match(iso_pat, sess_name);
}

sc_inbound_msg_t *inbound = sc_inbound_msg_new(
    SC_CHANNEL_WEB, "web", request_id,
    full_message ? full_message : message, session_key,
    response_format, isolated);
```

`sc_glob_match()` is a small new helper in `src/util/glob.c` supporting `*` and `?` (no character classes — kept minimal to avoid dependency growth). If a more capable matcher is needed later, swap in `fnmatch(3)` behind the same signature.

### 6.6 Plumbing through the agent

`agent.c::run_agent_loop()` accepts an `int isolated` parameter (sourced from `msg->isolated`). It:

- Constructs the per-turn `sc_context_builder_t` with `is_isolated = isolated`.
- Allocates the `sc_memory_t` used by the context builder via `sc_memory_new_namespaced(workspace, ns)` when isolated, else `sc_memory_new(workspace)`.
- Passes `isolated` down to `sc_summarize_args_t` so `do_consolidate` uses the right memory store.
- For the post-compact re-injection: when isolated, the workspace scratchpad path (`workspace/state/scratchpad.md`) is replaced with `workspace/memory/_sessions/<ns>/scratchpad.md`. Same write/read pattern, per-session location.

The `<ns>` value is computed once per turn from `session_key` via SHA-256 (existing dependency, used elsewhere in the codebase including web channel's token hashing).

### 6.7 Cleanup

Heartbeat already runs periodic ticks. A new hook in `src/heartbeat/` (or wherever the periodic ticker lives — confirm during implementation) calls `sc_memory_cleanup_sessions(workspace, 86400)` once an hour. The TTL (24h default) is hardcoded for now; a config knob can come later if needed.

---

## 7. File layout on disk

Before (current):

```
workspace/
  memory/
    202605/
      20260524.md          ← shared, all callers append here
    MEMORY.md              ← long-term, all callers read
    search.db              ← memory search index (touched later)
  state/
    scratchpad.md          ← shared
```

After (with isolation enabled and at least one isolated session that ran):

```
workspace/
  memory/
    202605/
      20260524.md          ← still shared; only non-isolated callers append
    MEMORY.md              ← still shared; isolated callers DO NOT read
    search.db              ← unchanged
    _sessions/
      a3f17b9e2c8d4f10/    ← namespace_id (sha8 of session_key)
        today.md           ← isolated session's consolidated notes
        scratchpad.md      ← isolated session's compact re-injection notes
        last_access        ← unix epoch text; for cleanup TTL
      b71e0c5a3d49f823/
        today.md
        ...
  state/
    scratchpad.md          ← unchanged; only non-isolated callers touch
```

The `_sessions/` prefix is chosen to sort visibly distinct from date-folders (`202605/`). The trailing underscore guarantees it doesn't collide with any real `YYYYMM` directory.

`last_access` is a single-line UNIX-epoch timestamp updated on every read/write through the namespaced memory. Cleanup reads it and removes dirs whose `last_access` is older than the TTL.

---

## 8. Implementation plan (staged)

Each stage is its own commit. CI must pass at each stage. Hard rule from the user: no half-baked stages — each commit must build, test, and document the slice it lands.

### Stage 0 — Plan doc commit (this file)
- One commit landing this design doc.

### Stage 1 — Glob helper + tests
- New: `src/util/glob.h`, `src/util/glob.c` (≤80 LOC) — `sc_glob_match(pattern, str)` supporting `*` and `?`.
- New: `tests/test_glob.c` covering match/no-match, edge cases (empty pattern, trailing `*`, etc.).
- Wire into `tests/CMakeLists.txt`.

### Stage 2 — Namespaced memory + tests
- `src/memory.h` / `src/memory.c`: add `sc_memory_new_namespaced()`, internal `namespace_id` field, `last_access` touch on every public call, path-switching helpers, `sc_memory_cleanup_sessions()`.
- Behavior contract: namespaced instance's `sc_memory_read_long_term()` returns NULL/empty; `sc_memory_get_context()` returns only per-session content; `sc_memory_append_today()` writes to per-session today.md.
- New: `tests/test_memory_namespaced.c`. Cases:
  - `test_namespaced_writes_isolated_from_shared` — append in ns A; assert shared YYYYMMDD.md unchanged and ns A's today.md updated.
  - `test_namespaced_read_does_not_leak_shared` — write to shared today; namespaced reader does not see it.
  - `test_two_namespaces_isolated` — A and B both write; neither reads the other.
  - `test_namespaced_self_continuity` — same ns, two writes, second read sees both.
  - `test_long_term_blocked_for_namespaced` — `sc_memory_read_long_term()` returns NULL.
  - `test_cleanup_removes_old_dirs` — fake `last_access` older than TTL; cleanup removes; fresh ones stay.
  - `test_cleanup_idempotent` — second call is a no-op.

### Stage 3 — Context builder isolation + tests
- `src/context.h` / `src/context.c`: add `is_isolated` to `sc_context_builder_t`; modify `sc_context_build_system_prompt()` to skip the memory block when set.
- Existing tests must still pass. Add:
  - `test_context_isolated_skips_memory` — when builder is isolated, system prompt does not contain `# Memory`.
  - `test_context_non_isolated_includes_memory` — back-compat.
- Append to existing `tests/test_agent.c` (or a new `tests/test_context_isolation.c` if cleaner).

### Stage 4 — Wire isolation through inbound msg + run_agent_loop
- `src/bus.h`: add `int isolated` to `sc_inbound_msg_t`; update `sc_inbound_msg_new()`.
- `src/bus.c`: propagate field through clone/free.
- `src/agent.c`: `run_agent_loop()` accepts isolated, builds the right memory + context_builder.
- `src/agent_session.c`: `sc_summarize_args_t` gains `isolated` + `namespace_id`; `do_consolidate` and `do_summarize` post-compact re-injection branch on it.
- All existing callers of `sc_inbound_msg_new()` updated to pass `0` (no behavior change). Each channel file (`channels/*.c`) gets a `0` arg in the call.
- New integration test `tests/test_session_isolation.c`:
  - `test_isolated_consolidation_does_not_leak` — run a fake isolated turn that triggers do_consolidate; assert shared today.md unchanged and namespaced today.md written.
  - `test_non_isolated_unchanged` — same scenario without isolation; shared today.md gets the append (back-compat).
  - `test_isolated_post_compact_uses_session_scratchpad` — trigger the re-injection path; assert per-session scratchpad path used.

### Stage 5 — Web channel pattern matching + config
- `src/config.h` / `src/config.c`: add `isolation_pattern` to `sc_channel_web_config_t`, default `"wf-*"`, JSON load/save, env override.
- `src/channels/web.c`: compute `isolated` from `sc_glob_match(wd->isolation_pattern, sess_name)`; pass to `sc_inbound_msg_new()`.
- `src/channels/web.h`: store `isolation_pattern` in the channel struct.
- New: `tests/test_web_isolation.c` (or extend `tests/test_e2e.c`):
  - `test_web_session_wf_pattern_matches` — POST with session "wf-researcher-x"; assert inbound msg has isolated=1.
  - `test_web_session_non_wf_no_match` — POST with session "chat-1"; isolated=0.
  - `test_web_empty_pattern_disables` — config empty pattern, all sessions non-isolated.
  - `test_web_custom_pattern` — `"task-*"` pattern; matches `task-foo`, not `wf-foo`.

### Stage 6 — Cleanup hook
- Find the existing heartbeat/periodic ticker.
- Hook in `sc_memory_cleanup_sessions(workspace, SC_ISOLATION_CLEANUP_SECS)`.
- `SC_ISOLATION_CLEANUP_SECS` constant in `src/constants_limits.h`, default 86400 (24h).
- Test: synthesize a stale namespaced dir, trigger the hook, assert dir removed.

### Stage 7 — Operator docs
- New: `docs/operations/session-isolation.md` — operator guide (how to enable / disable, where to find a session's content, cleanup behavior).
- Update: `docs/channels/web-channel.md` (if missing, create) — section on isolation.
- Update: top-level `README.md` — one-line pointer.
- Update: `RELEASE_NOTES.md` — feature entry.

### Stage 8 — Acceptance: run the contamination scenario clean
- After all stages land, validate end-to-end in a real fleet:
  - Reset researcher's workspace memory (back it up first).
  - Manually trigger a smolchat retention turn via the researcher web channel (e.g., curl); confirm it consolidated.
  - Run the smolswarm smoke against the same researcher; assert the smoke's Outline is about smolswarm README, not retention.
- Document the result in `docs/acceptance-tests/session-isolation-2026-XX-XX.md`.

Each stage is small enough to review on its own; the build/test/doc requirement applies per-stage.

---

## 9. Tests summary

| File | Stage | What it proves |
|---|---|---|
| `tests/test_glob.c` | 1 | Glob helper correctness |
| `tests/test_memory_namespaced.c` | 2 | Memory layer enforces namespace boundaries |
| `tests/test_context_isolation.c` (or extension) | 3 | System prompt omits memory when isolated |
| `tests/test_session_isolation.c` | 4 | Consolidation honors isolation; post-compact uses per-session scratchpad |
| `tests/test_web_isolation.c` (or extension) | 5 | Web channel sets the flag based on pattern + config |
| Cleanup test | 6 | TTL-based reaper works |
| `docs/acceptance-tests/session-isolation-*.md` | 8 | End-to-end contamination scenario produces clean output |

CI (`ctest --test-dir build`) must pass at every stage. No skipped tests, no `xfail`.

---

## 10. Backwards compatibility

- **Disk**: no files moved or renamed. New `_sessions/` subdirectory under `workspace/memory/` is only created when an isolated session runs. Operators with no isolated sessions never see it.
- **Config**: `isolation_pattern` defaults to `"wf-*"`. Sites whose web sessions never use that prefix (e.g. CLI-only setups) get no behavior change. Sites that do use `wf-*` but want today's behavior set `isolation_pattern: ""` in their config.
- **API**: `sc_inbound_msg_new()` gains a trailing parameter; every existing caller in the codebase is updated in the same commit (Stage 4) to pass `0`. External callers (none expected — bus is internal) would break, but the bus API is documented as internal.
- **Memory**: existing workspace memory remains intact. Non-isolated sessions continue to see and update it.

The user-visible config knob is documented and the default is conservative (only `wf-*` triggers isolation).

---

## 11. Risks & open questions

### 11.1 Risks

- **R1: Isolation breaks a use case that depended on memory leakage.** Unlikely for the documented use cases, but worth flagging. Mitigation: opt-out via empty pattern.
- **R2: `<ns>` collision.** SHA-256 truncated to 16 hex digits = 64 bits. Collision probability is negligible for the realistic session-key population. If two distinct callers somehow happened to use the same session-key (e.g. same bearer token + same session name), they'd share a namespace — but in that case they're already the same logical session, which is by design.
- **R3: Disk usage from accumulated `_sessions/` dirs before the cleanup ticker fires.** Mitigated by the 1h cleanup cadence. Each per-session dir is small (today.md + scratchpad.md + last_access ≈ <50KB typical).
- **R4: `sc_glob_match` is custom code.** Kept ≤80 LOC, tested directly, and `fnmatch(3)` is available as a drop-in replacement if requirements grow.

### 11.2 Open questions

- **Q1: Should isolated sessions be allowed to read `MEMORY.md` (the long-term file)?**
  Resolved (user-decided 2026-05-24): **No.** Isolated means isolated. Durable knowledge must come from delegate prompts or bootstrap files. This is captured in §6.2.
- **Q2: Should the namespace_id be derivable by operators from session_key, or fully opaque?**
  Tentative: opaque on disk. Operators map ns→session_key via `audit.log` (every turn already logs its `session_key`; we'll add the `ns` to the same record). No reverse lookup needed offline.
- **Q3: TTL value?**
  Tentative: 24h. Aggressive enough to keep disk clean, conservative enough that a long-running smolswarm workflow can span the gap. Make it a `SC_ISOLATION_CLEANUP_SECS` constant; tune later if needed.
- **Q4: Future channels (Slack, Discord) — should they default to isolation for bot-like callers?**
  Out of scope here. The plumbing supports it; future channel-specific PRs decide.

---

## 12. Acceptance criteria

The feature is "done" when:

1. All stages land in master with passing CI.
2. The end-to-end contamination scenario in Stage 8 produces clean output.
3. The fleet reliability smoke test, run after a deliberate cross-task contamination attempt, passes ≥3 consecutive times — meaning the prior cross-task content does not appear in the Outline/Drill-down/Synthesis of the new task.
4. Validation results are recorded in acceptance-test notes.
5. `docs/operations/session-isolation.md` is published.

After validation, the post-isolation reliability number replaces the pre-isolation baseline as the first statistically meaningful number for the architecture.

---

## 13. Related work

- The original fleet-plan framing was scratchpad-only ("Ephemeral Research Scratchpad + Memory Hygiene"); this design covers the broader memory contamination vector that was discovered during diagnosis.
- 330s `max_turn_secs` fix (smolclaw `constants_limits.h:35`): independent of this work, already validated.
