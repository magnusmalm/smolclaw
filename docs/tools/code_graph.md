# `code_graph` Tool

Lightweight, pure-C static analysis tool for import dependency graphs (multiple languages) and C/C++ symbol lookup (for researcher Drill-down).

Registered behind `SC_ENABLE_CODE_GRAPH` (default: y). Does not require external parsers or processes.

## Actions

- `build` — Scan a directory, build in-memory import graph (supports JS/TS, Python, C/C++, Go, Rust). Required before `query`/`stats`/`cycles`.
- `query` — For a built file: show its imports + reverse (who imports it).
- `stats` — File counts, language breakdown, top imported files.
- `cycles` — Detect circular import cycles (best-effort).
- `symbols` — **Primary for Drill-down research**. Lightweight regex-based extraction of C/C++ symbols from `.c`/`.h` (and C++ variants). Returns structured, bounded, citable records without full `read_file`.

The `symbols` action (and future thin `symbol_lookup` wrapper) replaces expensive broad `read_file` loops in the Outline → Drill-down → Synthesis flow.

## Parameters (JSON schema)

All actions require `"action"`.

Common/optional:

- `directory` / `path`: Target to scan (relative to workspace). For `build`/`symbols`.
- `file`: For `query`.
- For `symbols`:
  - `path`: Directory or single `.c`/`.h` file (default: `.`).
  - `name_filter`: Case-insensitive substring (e.g. `"ret"` matches `set_retention`, `MAX_RETENTION`, `retention_info`).
  - `max_results`: 1–256 (default 50). Hard cap for LLM context safety.
  - `kinds`: Optional comma-separated list of kinds to keep after extraction (post-filter). Supported: `func,define,struct,typedef,enum` (e.g. `"func,define"` or `"struct"`). Default: all kinds returned. Cheap and optional.

## `symbols` Output Shape (Researcher-Friendly)

Plain text, deliberately greppable and citable:

```
code_graph symbols under 'src': 12 results (scanned 5 C files; capped at 50)

func: extract_c_symbols at src/tools/code_graph.c:341 (int extract_c_symbols(code_graph_t *g, const char *content, ...))
  context: static int extract_c_symbols(code_graph_t *g, const char *content,

struct: cg_symbol_t at src/tools/code_graph.c:42 (typedef struct { ... } cg_symbol_t;)
  context: typedef struct {

define: MAX_SYMBOL_RESULTS at src/tools/code_graph.c:33 (#define MAX_SYMBOL_RESULTS 256)
  context: #define MAX_SYMBOL_RESULTS 256

...
... (truncated at max_results=50 — use name_filter or narrower path for Drill-down)
```

Fields always include `kind: name at path:line (signature)` + short `context` line for immediate use in reasoning/scratchpad. Path:line enables precise citation back to source.

**TODO (provisional v1 format)**: The exact text layout (including optional `(kinds='...')` in the header when the filter is used) is provisional. It is effective for LLM parsing/grepping in Drill-down and for direct citation. It may still be refined (e.g. bullets or stricter layout) in the future. `kinds` filtering and the `symbol_lookup` wrapper are now implemented. See the TODO in `src/tools/code_graph.c:action_symbols` (and the kind_matches helper).

## Usage in Drill-Down (Strong Hint for Researcher)

In staged research profiles (e.g. `implement_feature.json` Drill-down task):

> "You are in Drill-down. Use the manifest + `code_graph` (action=`symbols`) + `read_file` (bounded) to investigate hypotheses from Outline. 
> Prefer `code_graph` with `action=symbols` + `name_filter` over repeated full-file reads for locating definitions of `set_retention`, `register_default_tools`, `extract_c_symbols`, etc.
> Append findings (with path:line citations) to scratchpad. Do not explore unrelated files."

This directly mitigates context bloat and long runtimes from naive `read_file` loops.

Example researcher call (inside tool request):
```
code_graph with action is symbols path is src name_filter is ret max_results is 20
```

Then parse the returned text for symbols touching retention logic, cross-reference with manifest, etc.

## Limitations (Documented for Researchers)

- **Approximate only** (no AST, no tree-sitter, no preprocessor). 
  - Good on clean modern C used in smol* (static funcs, simple structs, #defines).
  - May miss: K&R declarations, complex pointer-to-function returns, macros that hide decls, `#ifdef`-guarded symbols, C++ templates/ctors, some typedef variants.
- `symbols` only scans C/C++ (`.c`, `.h`, `.cpp` etc.). Other languages only via the import-graph actions.
- Traversal respects `.gitignore`-style skips (build/, .git/, etc.) + 1MB file cap.
- Workspace-restricted (never escapes the tool's root).
- Best-effort line numbers and signatures (context is the definition line).
- `name_filter` is substring (powerful but can over-match; refine iteratively).

For production symbols, consider a full LSP later; this primitive is intentionally lightweight and always-available for local-model researchers.

## Building & Enabling

- Kconfig: `SC_ENABLE_CODE_GRAPH=y` (under Tools).
- CMake wires sources + tests automatically.
- Appears in `tools` list when enabled (see agent registration).

Tests: `test_code_graph` (including new `test_symbols_action` covering filter, caps, paths).

## Examples (Real smolclaw Symbols)

Running `symbols` on the smolclaw `src/` tree itself yields (among others):

- `func: sc_tool_code_graph_new at src/tools/code_graph.c:1043 (...)`
- `func: extract_c_symbols at src/tools/code_graph.c:341 (...)`
- `func: action_symbols at src/tools/code_graph.c:833 (...)`
- `define: MAX_SYMBOL_RESULTS at src/tools/code_graph.c:33`
- `struct: cg_symbol_t at src/tools/code_graph.c:42`

Use `name_filter=extract` or `path=src/tools` for targeted Drill-down on the tool itself.

## Future / Related

- `symbol_lookup` thin wrapper tool (planned next) — convenience alias with good defaults for `action=symbols`.
- `kinds` post-filter.
- `set_workspace` support for dynamic workspace switching.
- Integration notes will appear in `docs/workflows/research-phase.md` (Phase 2/5 coordination).

---

**See also**: `tests/test_code_graph.c`, source of `src/tools/code_graph.c` (the `extract_c_symbols` + regex patterns), pre-execution plan, and Drill-down task templates.