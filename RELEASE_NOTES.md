First stable release of smolclaw — a C11 lightweight AI agent framework.

## Unreleased

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

## Highlights

- **6 channels**: CLI, Telegram, Discord, IRC, Slack (Socket Mode), Web (REST + embedded chat UI)
- **10 LLM providers**: Anthropic, OpenAI, OpenRouter, Groq, Gemini, DeepSeek, xAI, Zhipu, vLLM, Ollama
- **19 built-in tools**: filesystem, shell, git, web search/fetch, memory, message, cron, spawn, background processes
- **Long-term memory**: Markdown files, daily notes, auto-consolidation, full-text search (SQLite FTS5)
- **SSE streaming**, MCP client (JSON-RPC 2.0), model fallback chain, in-prompt model override
- **16 Kconfig feature flags** — build exactly what you need
- **Self-contained static binaries**: 4.6 MB (musl, x86_64), zero runtime dependencies

## Security

- ~83 deny patterns for shell execution
- SSRF protection with DNS pinning (`CURLOPT_RESOLVE`)
- OS sandbox: Landlock filesystem + seccomp-bpf syscall filter
- Encrypted API key vault (AES-256-GCM, PBKDF2 600K iterations)
- Prompt injection defense (CDATA wrapping, prompt guard)
- Secret redaction (13 patterns) on tool output, sessions, and responses

## Binary sizes

| Build               |  Size  |
|---------------------|--------|
| Dynamic minimal     | 280 KB |
| Dynamic full        | 1.9 MB |
| Musl static minimal | 4.6 MB |
| Musl static full    | 6.2 MB |

Peak RSS: 672 KB (musl-static)

## Installation

Download a binary from the assets below, or build from source:

```bash
git clone https://github.com/magnusmalm/smolclaw.git
cd smolclaw
cmake -B build && cmake --build build -j$(nproc)
./build/smolclaw onboard
```

See [README.md](https://github.com/magnusmalm/smolclaw/blob/master/README.md) for full documentation.
