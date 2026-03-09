First stable release of smolclaw — a C11 lightweight AI agent framework.

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
