# Phase 3 Landing Note: Smolclaw Research Primitives (`code_graph` + `symbol_lookup`)

**Date**: 2026-05-18  
**Agent**: Agent 2 (Smolclaw Research Primitives)  
**Reference**: `phase3-pre-execution-plan-2026-05-17.md`, `the-one-final-plan-2026-05-16.md`, `codex-final-action-plan-2026-05-16.md`

## Executive Summary

Phase 3 delivers lightweight, pure-C static analysis primitives that let Drill-down researchers replace expensive `read_file` loops with precise, bounded, citable symbol queries (`symbol_lookup("set_retention")` or `code_graph action=symbols` + filters). All functionality lives behind the existing `SC_ENABLE_CODE_GRAPH` Kconfig flag (default: y) and follows established smolclaw tool patterns (vtable + workspace restriction + cJSON schema).

The work was performed exclusively in `/home/magnus/devel/smolclaw` (baseline `code_graph.c/.h` + `test_code_graph.c` were already present in the canonical tree).

## Scope Delivered

- **`code_graph` tool extensions** (`src/tools/code_graph.c` / `.h`):
  - New `"symbols"` action: regex-based extraction of C/C++ symbols (`func`, `define`, `struct`; `typedef`/`enum` in schema for future).
  - `cg_symbol_t` record + `extract_c_symbols()` + `scan_symbols_tree()` + `compile_symbol_patterns()`.
  - `kinds` post-filter (comma-separated, e.g. `"func,define,struct"`).
  - `set_workspace` vtable hook (mirrors `git.c` / `filesystem.c`).
  - Researcher-friendly output: `kind: name at path:line (signature)\n  context: ...` with truncation and filter notes.

- **Thin `symbol_lookup` wrapper** (new `src/tools/symbol_lookup.c` / `.h`):
  - Convenience tool name for prompts.
  - Internally delegates to a temporary `code_graph` instance with `action="symbols"`.
  - Friendly defaults: `max_results=30`.
  - Full `name` / `path` / `max_results` / `kinds` passthrough + `set_workspace` support.
  - Reuses 100% of the core implementation with zero duplication.

- **Registration & Build**:
  - Added to both registration sites in `src/agent.c`.
  - Wired in `CMakeLists.txt` under the existing `SC_ENABLE_CODE_GRAPH` block.
  - Kconfig help text lightly refreshed.

- **Tests** (`tests/test_code_graph.c`):
  - 17 tests under the guard (legacy + extensive Phase 3 coverage).
  - Covers: basic symbols, `name_filter`, `max_results` + truncation, `path` restriction, `kinds` combinations, `symbol_lookup` wrapper (basic + with kinds), `set_workspace` on both tools + cross-workspace verification, edge cases (non-C, binary, empty results, unsupported kinds, filter-to-nothing).
  - All pass (`ctest --test-dir build` / direct `./build/test_code_graph`).

- **Documentation**:
  - New `docs/tools/code_graph.md` (full schema, usage examples, Drill-down "strong hint" language, limitations, output shape).
  - Provisional output format **TODO** prominently documented in both the source (`action_symbols` + `kind_matches`) and the docs (may evolve to bullets/JSON envelope later).

## Key Decisions & Rationale

- **Hybrid API**: Primary power tool = `code_graph` with `action` (preserves existing contract). Ergonomic alias = thin `symbol_lookup` wrapper (researcher-friendly defaults, direct "name" param). Matches pre-plan recommendation.
- **Post-filter for `kinds`**: Cheap in-place filter after extraction (no change to scanner). Supports the documented set; absent/empty = all (backward compat).
- **Provisional output format**: Kept the proven `"kind: name at path:line (sig)\n  context: ..."` shape (highly greppable and citable). Explicit TODO left in code + docs for future refinement once more usage data exists.
- **set_workspace vtable**: Added to both tools for dynamic workspace correctness (e.g., per-task subdirs) following the established pattern.
- **No smolswarm / prompt changes**: Strictly smolclaw + tests + docs (Phase 5 owns profile `allowed_tools` + `research-phase.md` updates).

## Before / After for the Researcher (Drill-down)

**Before (pre-Phase 3)**:  
Outline produces candidate files → Drill-down researcher falls back to repeated bounded `read_file` calls or broad greps, leading to context bloat, long runtimes, and weak citations.

**After**:
```
# Preferred pattern (no prior "build" step required)
symbol_lookup with name is set_retention path is src max_results is 20 kinds is func,define

# Or via the power tool
code_graph with action is symbols path is src name_filter is ret kinds is func,define max_results is 20
```

Output is immediately usable:
```
func: set_retention at src/memory.c:142 (void set_retention(uint32_t secs))
  context: void set_retention(uint32_t secs) { ...
```

Findings are appended to scratchpad with precise `path:line` citations. The staged Outline → Drill-down → Synthesis flow (see `docs/tools/code_graph.md`) now has a first-class primitive instead of raw file traversal.

## Test & Validation Summary

- Full `test_code_graph` suite passes (17 tests when `SC_ENABLE_CODE_GRAPH` is enabled).
- Manual smoke via `smolclaw` binary confirms both tool names appear and function.
- Edge coverage includes workspace switching, filter combinations, truncation under `kinds`, unsupported kinds, binary/non-C files, and wrapper passthrough.

## Known Limitations & Follow-ups

- **Regex-based scanner** (best-effort on clean modern C used in smol* projects). May miss K&R, complex macros, `#ifdef`-hidden symbols, pointer-to-function returns, C++ templates, etc. Documented in `code_graph.md`.
- **Supported kinds today**: Strong coverage for `func`/`define`/`struct`; `typedef`/`enum` are accepted by the filter and schema but have limited positive extraction (future extractor work can improve).
- **Output format is provisional** (explicit TODO in `src/tools/code_graph.c:action_symbols` and `docs/tools/code_graph.md`). May be refined (e.g., more structured bullets or optional JSON envelope) after real usage data.
- **No profile / prompt changes yet**: `symbol_lookup` and `code_graph` must be added to researcher `allowed_tools` lists and `research-phase.md` (Phase 5 / Agent 4 coordination).
- **Future**: Possible dedicated `symbol_lookup` caching, richer extraction, or integration with `scratchpad` auto-capture.

## References & Artifacts

- Primary docs: `docs/tools/code_graph.md`
- Pre-plan: `docs/implementation-notes/phase3-pre-execution-plan-2026-05-17.md`
- Code: `src/tools/code_graph.{c,h}`, `src/tools/symbol_lookup.{c,h}`
- Tests: `tests/test_code_graph.c` (especially `test_symbols_*` and `test_symbol_lookup_*` families)
- Provisional format TODO: `src/tools/code_graph.c` (near `action_symbols` and `kind_matches`)

**Phase 3 is complete and ready for Phase 5 profile enablement and researcher workflow integration.**

---

*Prepared by Agent 2. Next step: commit + handoff to Agent 4 (fleet templates) and Agent 3 (research-phase.md).*