# smolclaw release notes

A C11 lightweight AI agent framework.

## Unreleased

### Breaking / behavior changes

- **`git push` is now deny-by-default** — the `git` tool refuses `push`
  unless the remote matches an explicit `git.push_allowed_remotes`
  allowlist. Previously, an *unconfigured* agent could push anywhere the
  ambient credentials allowed. Add your remotes to the allowlist to
  restore push access.
- **`SC_ENABLE_VOICE` and `SC_ENABLE_CODE_GRAPH` now default off** —
  enable explicitly (menuconfig, defconfig, or `-DSC_ENABLE_...=ON`) if
  you rely on voice transcription or the code-graph tools.
- **Exec hygiene** — commands that have dedicated tools are blocked from
  raw `exec`; channel tool allowlists are enforced at execution time;
  the exec allowlist handles redirects and absolute paths.
- **Cost estimation no longer invents spend** — unknown models warn and
  report $0 instead of a paid per-token fallback; provider-reported
  actual USD is captured as ground truth when available.
- Home directory permissions are forced to 0700 on onboard and gateway
  startup.

### Added

- **Camera tool** (`SC_ENABLE_CAMERA`, default n) — capture stills via a
  configurable snap command, list motion-daemon event captures, and
  describe images through a remote ollama-compatible vision endpoint.
  Workspace-confined; vision call is tool-internal (the agent's own
  provider stays text-only).
- **Web channel UI/API** — inline image attachments (`/api/media`),
  live progress feed (`/api/progress`), optional live-stream embed
  (`channels.web.embed_stream_url`, served via authed `/api/ui-config`),
  request timeout derived from `max_turn_secs`, per-turn
  `run_repo_dir` tool-workspace narrowing.
- **Host introspection tools** — `host_status`/`host_inventory`/
  `host_trend`; SQLite trend recording gated behind new
  `SC_ENABLE_HOST_METRICS` so the minimal build stays smol.
- **CI size budget** — `scripts/check_size_budget.sh` enforces the
  SCOPE.md budget (minimal dynamic ≤ 320 KB stripped) on every CI run;
  third-party GitHub Actions pinned to commit SHAs.
- **Research primitives** (`SC_ENABLE_CODE_GRAPH`) — `code_graph`
  symbol extraction with kind filters, `symbol_lookup`, `set_workspace`.
- **Agent infrastructure** — skills registry + slash commands, deferred
  tool schemas + `tool_search`, structured LLM output with JSON-schema
  enforcement, checkpoint/rewind for turn recovery, per-turn arena
  allocator, microcompact context management, compaction-amnesia
  countermeasures (action log, scratchpad, observation masking),
  delegate context passing + stuck-loop escalation, git worktree
  isolation tools, Gitea API tool, notify tool, converse tool,
  cross-agent memory + memory compaction.
- **Providers** — custom named providers, fallback routing through the
  active custom provider, Anthropic prompt caching, adaptive timeout for
  transient failures, `summary_model` for cheaper summarization.
- **Cost tracking** — dated exact-match rate table, per-record
  `last_updated_ts`, top-level recompute, single pricing path shared by
  all reporting.
- **Hardening** — config integrity verification + audit API endpoint,
  per-server capability-based MCP sandbox, tool-output pipeline
  hardening, `sprintf` → `snprintf` sweep, secret redaction in the
  action log, `selftest` command, extended `doctor` checks, gateway
  health endpoint.

### Fixed

- **Session isolation for delegate calls** — fixes a cross-session memory
  contamination class where a long-running agent shared by multiple
  callers (e.g. a smolswarm fleet) could leak one delegate's consolidated
  memory into another delegate's system prompt. Web channel sessions
  matching a configurable glob (`channels.web.isolation_pattern`,
  default `"wf-*"`) now run in a per-session memory namespace under
  `{workspace}/memory/_sessions/<id>/` and skip the shared "# Memory"
  block in the system prompt. Background cleanup reaps namespaces idle
  longer than 24 h. See
  [`docs/operations/session-isolation.md`](docs/operations/session-isolation.md)
  and [`docs/design/session-isolation-plan.md`](docs/design/session-isolation-plan.md).
- **code_graph regex fix** — POSIX ERE patterns in the Phase 3 symbol
  extractor used PCRE-only `(?:...)` non-capturing groups; `regcomp`
  silently failed and `extract_c_symbols` returned 0 symbols. Replaced
  with capturing groups + updated capture-group indices. The matching
  test_code_graph suite (broken since landing) now runs and is green.

## 0.9.1 — first stable release

### Highlights

- **7 channels**: CLI, Telegram, Discord, IRC, Slack (Socket Mode), Web (REST + embedded chat UI), X/Twitter
- **10 LLM providers**: Anthropic, OpenAI, OpenRouter, Groq, Gemini, DeepSeek, xAI, Zhipu, vLLM, Ollama
- **Built-in tools**: filesystem (read/write/edit/append/list), shell, git, gitea, web search/fetch, memory (read/write/log/search), code graph, message, cron, spawn, delegate, converse, notify, scratchpad, camera, background processes
- **Long-term memory**: Markdown files, daily notes, auto-consolidation, full-text search (SQLite FTS5)
- **SSE streaming**, MCP client (JSON-RPC 2.0), model fallback chain, in-prompt model override
- **28 Kconfig feature flags** — build exactly what you need
- **Self-contained static binaries**: 4.6 MB (musl, x86_64), zero runtime dependencies

### Security

- ~90 deny patterns for shell execution
- SSRF protection with DNS pinning (`CURLOPT_RESOLVE`)
- OS sandbox: Landlock filesystem + seccomp-bpf syscall filter
- Encrypted API key vault (AES-256-GCM, PBKDF2 600K iterations)
- Prompt injection defense (CDATA wrapping, prompt guard)
- Secret redaction (13 patterns) on tool output, sessions, and responses

### Binary sizes

| Build               | Size   |
|---------------------|--------|
| Dynamic minimal     | 280 KB |
| Dynamic full        | 1.9 MB |
| Musl static minimal | 4.6 MB |
| Musl static full    | 6.2 MB |

Peak RSS: 672 KB (musl-static)

### Installation

Download a binary from the assets below, or build from source:

```bash
git clone https://github.com/magnusmalm/smolclaw.git
cd smolclaw
cmake -B build && cmake --build build -j$(nproc)
./build/smolclaw onboard
```

See [README.md](https://github.com/magnusmalm/smolclaw/blob/master/README.md) for full documentation.
