# Simplicity audit — smolclaw (DRY / KISS)

**Scope:** Full repo; prioritized `src/` (C). Excluded `build*/`, `deps/`.  
**Context:** C11 agent binary, Kconfig feature flags, 320 KB stripped size budget.  
**Mantra:** work > right > fast (per `CLAUDE.md`; no project override).

## Summary

The codebase is feature-dense but mostly honest: Kconfig gates are pervasive, recent splits (`agent_turn.c`, `curl_common`, `constants_*.h`) show intentional simplification. Real maintenance risk concentrates in **three god files** (`main.c`, `config.c`, `agent.c`+`agent_turn.c`) and **one divergent curl path** (`tools/notify.c`). Most channel/config repetition is copy-paste with identical shape — risky when adding channels or secrets, but not worth a framework rewrite while the project is still proving correctness on embedded targets.

**Line-count hotspots (>1k LOC in `src/`):**

| File | LOC | Role |
|------|-----|------|
| `main.c` | 2241 | CLI + gateway runtime + doctor + vault |
| `agent_turn.c` | 1972 | LLM iteration / tool execution |
| `tools/host.c` | 1948 | Host introspection + metrics |
| `config.c` | 1927 | JSON load/save/env/vault |
| `agent.c` | 1874 | Agent lifecycle + tool registration + turn setup |
| `channels/web.c` | 1467 | HTTP API + embedded UI |
| `tools/web.c` | 1204 | Web search/fetch tools |

---

## Findings

### main.c is a CLI + gateway + diagnostics god file
- Severity: **high**
- Location: `src/main.c` (2241 lines, ~58 `static` helpers)
- Problem: One translation unit owns signal handlers, `gateway` event loop, `doctor`/`selftest` checks (~400 LOC), vault sub-CLI (~300 LOC), pairing/onboard/agent/cost/analytics/update commands, and `main()` dispatch. Any CLI or gateway change requires navigating unrelated code; merge conflicts and review fatigue are likely as features land.
- Simpler alternative: Extract by command family without changing behavior — e.g. `gateway_main.c` (gateway_* + handlers), `doctor.c` (doctor_check_* + run_doctor_checks), `vault_cli.c` (vault_cmd_*). Keep `main.c` as thin dispatch + shared `load_config_or_exit`.
- Mantra phase note: **right** — behavior is largely proven (gateway ships on Pi); incremental file splits reduce risk vs. one big refactor. Defer until a touch in that area, not as a standalone project.
- Status: open

### config.c channel/secret resolution has parallel edit surfaces
- Severity: **medium**
- Location: `src/config.c` — `load_channels` (~932–1035), env overrides (~572–615), `resolve_secret_field` (~234–260), `resolve_vault_field` (~361–370), defaults/free/serialize mirrors
- Problem: Each new channel or secret token requires coordinated edits in 4–6 places (parse, serialize, env, workspace secrets, vault, manager init). The `dm_policy` + `allow_from` + `tools` triple is copy-pasted per channel with only field names differing. This is the same class of drift as documented KC-1 (Kconfig `FEATURE_SYMS`): one missed list entry silently misconfigures runtime.
- Simpler alternative: Small shared helpers only — e.g. `parse_channel_security(cJSON *obj, char **dm_policy, char ***allow_from, int *count, char ***tools, int *tool_count)` and a macro/table for env var name → field pointer. Avoid a generic config framework; keep per-channel unique fields explicit.
- Mantra phase note: **right** — safe to add helpers when the *next* channel lands; a preemptive table-driven rewrite is premature.
- Status: open

### tools/notify.c bypasses centralized curl initialization
- Severity: **medium**
- Location: `src/tools/notify.c:123` (`curl_easy_init()` in `http_post_json`)
- Problem: `util/curl_common.h` documents that all handles must use `sc_curl_init()` for CA bundle and protocol restrictions. `notify.c` is the sole outlier in `src/`. On embedded/minimal builds this can mean failed TLS, wrong CA behavior, or protocol policy divergence vs. every other HTTP client — a real bug-fixed-in-one-place-only risk.
- Simpler alternative: Replace `curl_easy_init()` with `sc_curl_init()` (and `sc_curl_apply_defaults` if reset). One-line behavioral alignment.
- Mantra phase note: **work** — correctness/safety fix; do now, not deferred.
- Status: open

### agent.c still hosts massive tool registration and turn preamble
- Severity: **medium**
- Location: `src/agent.c` — `sc_register_tools_standalone` (~209–400+), `run_agent_loop` (~1551–1735)
- Problem: M-15 moved LLM iteration to `agent_turn.c`, but `agent.c` remains 1874 LOC: 66 `sc_tool_registry_register` calls, duplicated standalone vs. full-agent registration paths, and ~180 lines of turn setup (isolation, history, model override) before calling `sc_run_llm_iteration`. Tool additions touch a wall of `#if SC_ENABLE_*` blocks.
- Simpler alternative: Move `sc_register_tools_standalone` body to `tools/register_all.c` (or split by domain: fs/shell/web/memory). Leave `run_agent_loop` preamble in `agent.c` — it is readable orchestration, not iteration complexity.
- Mantra phase note: **right** — helpful when adding tools; not blocking **work** unless registration duplication has already caused a bug.
- Status: open

### Partial agent split leaves agent_turn.c as second god file
- Severity: **medium**
- Location: `src/agent_turn.c` (1972 lines), `src/agent_internal.h`
- Problem: `agent_turn.c` bundles hourly rate limits, provider health, stuck-loop detection, parallel tool execution, cost reporting, checkpoint rewind, and LLM fallback — all `static` in one file. Understandable for a single-threaded loop, but hard to test or change one concern without reading the whole file.
- Simpler alternative: Only extract if a subsystem needs isolated tests — e.g. `turn_limits.c` (hourly + stuck loop), `turn_provider.c` (retry/health/fallback). No further split until a concrete change demands it.
- Mantra phase note: **right** — further split is optional; current structure matches "clarity beats DRY" if the team navigates it. Premature micro-modules would obscure the turn flow.
- Status: open

### Duplicated FNV-1a hash (acknowledged, low divergence risk)
- Severity: **low**
- Location: `src/agent_turn.c:62`, `src/memory_index.c:70` (comment: "same as agent_turn.c")
- Problem: Identical `fnv1a_str` in two files. Low bug risk today because implementations match and comments cross-reference.
- Simpler alternative: `util/hash.h` with `sc_fnv1a_str` — only if a third copy appears or hash semantics must change globally.
- Mantra phase note: **fast** defer — no measured maintenance pain; extraction adds flash for minimal builds.
- Status: open

### tools/host.c remains large after metrics gate
- Severity: **low**
- Location: `src/tools/host.c` (1948 lines)
- Problem: SQLite/metrics correctly gated behind `SC_ENABLE_HOST_METRICS` (2026-06-11 size-budget fix). File still mixes `/proc` parsing, inventory JSON/MD, DB sampling, and tool handlers — high LOC but cohesive "host diagnostics" domain.
- Simpler alternative: Split `host_metrics.c` only if metrics features grow; keep inventory + status together for embedded builds.
- Mantra phase note: **fast** — size already addressed via Kconfig; structural split is optional **right** work.
- Status: open

### channels/web.c embeds full HTTP server + UI in channel layer
- Severity: **low**
- Location: `src/channels/web.c` (1467 lines)
- Problem: REST API, TLS, media, progress SSE, and chat UI live in the channel module. Large, but feature-coherent; splitting UI from API would add indirection without clear win for a Kconfig-gated optional channel.
- Simpler alternative: Document section boundaries in file header; extract `web_ui.c` only if UI churn conflicts with API review.
- Mantra phase note: **right** defer — web channel is actively evolving; avoid refactor during feature velocity.
- Status: open

### Minor: UTF-8 truncation logic duplicated in two places
- Severity: **low**
- Location: `src/agent_session.c:583`, `src/channels/discord.c:659`
- Problem: Same "walk back past UTF-8 continuation bytes" pattern for message chunking. Two copies, same algorithm; unlikely to diverge unless one path changes chunk limits.
- Simpler alternative: `util/utf8.h` — `sc_utf8_prev_char_boundary(const char *s, size_t len)` — only if a third caller appears.
- Mantra phase note: **right** defer — clarity of inline comment may beat another util for two call sites.
- Status: open

### Not flagged (acceptable complexity)
- **`channels/base.c` security helpers** — shared allowlist/DM policy; channels differ by transport, not security model.
- **`state.c` vs `session.c` vs `agent_session.c`** — names overlap conceptually but roles are distinct (last-channel persistence vs. JSONL history vs. summarize/compact). No action.
- **`manager_add_channel` `__attribute__((unused))`** — silences warnings when all channel features are compiled out; not dead code.
- **Constants split (`constants_*.h`)** — umbrella `constants.h` preserves includes; good KISS compromise.
- **`tools/registry.c`** — appropriate abstraction for tool execution; not over-layered.

---

## Premature refactor guard (mantra)

Recent progress (`docs/progress-2026-06-11.md`) shows active **work**-phase delivery: session isolation, camera agent, CI size budget, cost-path correctness. Recommend:

| Action | Phase | Now? |
|--------|-------|------|
| Fix `notify.c` → `sc_curl_init` | work | **Yes** |
| Add config helper when next channel ships | right | On demand |
| Split `main.c` by command family | right | On next gateway/doctor touch |
| Move tool registration out of `agent.c` | right | On next major tool addition |
| Extract `util/hash.c` / `util/utf8.h` | right/fast | Defer |
| Framework-level config or channel abstraction | — | **No** — obscures behavior |

**Mantra: work ✓ | right — | fast —**

---

## Top 3 issues (actionable)

1. **`main.c` god file** — 2241 LOC mixing gateway, doctor, vault CLI, and all commands; highest cognitive load and conflict risk.
2. **`config.c` parallel edit surfaces** — channel/secret/env/vault lists must stay in sync; real drift risk when extending channels.
3. **`tools/notify.c` curl bypass** — diverges from `sc_curl_init` policy; quick correctness fix.