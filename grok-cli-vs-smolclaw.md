# grok-cli vs smolclaw — Comparative Analysis

## At a Glance

| Dimension | **grok-cli** | **smolclaw** |
|-----------|-------------|-------------|
| **Language** | TypeScript (Bun runtime) | C11 (zero runtime) |
| **Binary size** | ~100+ MB (node_modules) | 280 KB dynamic / 4.6 MB static |
| **Peak RSS** | Not documented (Node-class) | 672 KB (musl-static) |
| **LOC** | ~11K TS | ~34K C |
| **Source files** | ~59 modules | ~161 files |
| **License** | MIT | Private (Gitea) |
| **Target** | Developer desktops | Edge devices to servers |

## Architecture

| | **grok-cli** | **smolclaw** |
|---|---|---|
| **Core loop** | Vercel AI SDK `streamText()` -> tool calls -> iterate | Custom C loop: context build -> LLM call -> tool exec -> iterate |
| **Concurrency** | Single-threaded (Bun event loop) | Single-threaded agent + channel threads + async summarization thread |
| **Message bus** | Direct function calls | Thread-safe pipe-based bus (libevent) |
| **Abstraction style** | TypeScript modules + Zod schemas | C vtables (`sc_tool_t`, `sc_provider_t`, `sc_channel_t`) |
| **Error recovery** | Basic retry | 2-level rewind with checkpoints, exponential backoff, fallback provider chain |

grok-cli leans on the Vercel AI SDK to abstract the agent loop — clean but coupled to that framework. smolclaw owns the entire stack from socket to tool execution, giving it fine-grained control over retry, rate limiting, and error budgets.

## LLM Providers

| | **grok-cli** | **smolclaw** |
|---|---|---|
| **Providers** | 1 (xAI Grok only) | 9+ (Anthropic, OpenAI, OpenRouter, Groq, Gemini, DeepSeek, xAI, Zhipu, vLLM/Ollama) |
| **Models** | 11 Grok models | Any model behind supported providers |
| **Fallback chain** | None | Configurable fallback sequence |
| **Streaming** | Yes (AI SDK streams) | Yes (SSE callbacks) |
| **Model routing** | CLI flag / config | Inline (`Use opus: message`), per-channel, per-agent, config, env |

smolclaw is provider-agnostic by design. grok-cli is locked to xAI — it's a Grok-specific product, not a general agent framework.

## Channels (User Interfaces)

| | **grok-cli** | **smolclaw** |
|---|---|---|
| **Interactive TUI** | React + OpenTUI (rich) | readline CLI (minimal) |
| **Headless** | `--prompt` + JSONL output | `-m "message"` single-turn |
| **Telegram** | Yes (long-polling bot) | Yes (long-polling) |
| **Discord** | No | Yes (WebSocket gateway) |
| **IRC** | No | Yes (TLS) |
| **Slack** | No | Yes (Socket Mode) |
| **Web** | No | Yes (HTTP + WebSocket, port 8080) |
| **X/Twitter** | No (has search tool, not channel) | Yes (full channel) |
| **Gateway mode** | No | Yes — all channels + services in one process |

smolclaw has 7 channels vs grok-cli's 2 (TUI + Telegram). smolclaw's gateway mode runs everything in a single process — a proper multi-channel agent server. grok-cli is firmly a single-user desktop tool.

## Tools

| | **grok-cli** | **smolclaw** |
|---|---|---|
| **Built-in count** | ~12 | 23 |
| **Filesystem** | read/write/edit | read/write/edit/list/append |
| **Shell** | bash (bg processes) | exec (fork+exec, deny patterns, Landlock, seccomp) |
| **Web** | search_web, search_x (Grok Responses API) | web_search (Brave/SearXNG/DDG), web_fetch (SSRF-protected) |
| **Git** | No dedicated tool | Yes (safe subcommand allowlist) |
| **Memory** | No (session persistence only) | memory_read/write/log/search (FTS5) |
| **Messaging** | No | message (cross-channel), notify (Apprise) |
| **Sub-agents** | task + delegate | spawn + delegate + converse (multi-agent debate) |
| **Background** | Yes (child process fork) | exec_background + bg_poll + bg_kill |
| **Media** | image + video generation | No |
| **Code analysis** | No | code_graph (dependency analysis) |
| **Cron** | Yes (schedule tool + daemon) | Yes (cron tool) |
| **MCP** | Client only | Client + Server (bidirectional) |

grok-cli has media generation (images/video) that smolclaw lacks. smolclaw has memory, git, code_graph, cross-channel messaging, notify, and multi-agent debate that grok-cli lacks.

## Security

| | **grok-cli** | **smolclaw** |
|---|---|---|
| **Sandbox** | Shuru microVM (macOS Apple Silicon only) | Landlock + seccomp-bpf (Linux kernel) |
| **Command filtering** | None | ~90 deny patterns + allowlist/denylist modes |
| **Prompt injection defense** | None visible | CDATA wrapping, prompt guard, output filtering |
| **SSRF protection** | None visible | Yes (web_fetch) |
| **Secret management** | `.env` files | Encrypted vault (`vault://` references) |
| **Audit logging** | None | Per-day JSONL audit log of all tool calls |
| **Rate limiting** | None | Per-turn (50 calls), per-hour (configurable), per-minute (gateway) |

This is the widest gap. smolclaw treats security as a first-class concern with defense-in-depth. grok-cli delegates to an optional macOS-only sandbox and has no visible prompt injection or command injection defenses.

## Persistence & Memory

| | **grok-cli** | **smolclaw** |
|---|---|---|
| **Sessions** | SQLite per workspace | JSONL trees with branching |
| **Long-term memory** | None | Markdown files + FTS5 full-text search |
| **Memory consolidation** | Context compaction (summarize old turns) | LLM-curated consolidation (recent 3 days kept, older compressed) |
| **Daily notes** | No | Yes (`YYYY-MM-DD.md`) |
| **Analytics** | Usage tracking in SQLite | Full analytics (by model, channel, day/week/month) |
| **State** | Session metadata | Dedicated state tracker + audit log |

grok-cli has in-session compaction. smolclaw has a full cross-session memory system with search, consolidation, and daily journaling.

## Build & Distribution

| | **grok-cli** | **smolclaw** |
|---|---|---|
| **Build tool** | tsc + Bun | CMake 3.14+ |
| **Distribution** | npm (`npm i -g grok-dev`) | Static binary (scp/curl) |
| **Feature flags** | None | 25 Kconfig flags |
| **Cross-compile** | N/A (JS) | x86_64, aarch64, armv7l |
| **Minimal build** | Full only | `defconfig.minimal` -> 280 KB |
| **Self-update** | npm update | Built-in updater (check/apply/rollback) |
| **Tests** | Vitest | ctest (per-module) |

## Design Philosophy

**grok-cli** is a **product** — a polished TUI experience for Grok users. Rich React UI, media generation, clean npm install. It optimizes for developer experience on modern desktops.

**smolclaw** is a **framework** — a composable agent runtime that runs anywhere from a Raspberry Pi to a server. It optimizes for footprint, security, operational resilience, and multi-channel deployment.

## What smolclaw Could Borrow

1. **Rich TUI** — grok-cli's React+OpenTUI interface is far more polished than readline. A lightweight TUI (maybe via ncurses) could improve smolclaw's interactive experience.
2. **Media generation tools** — image/video gen via API would be straightforward to add.
3. **Context compaction heuristics** — grok-cli's token-aware summarization trigger could inform smolclaw's truncation strategy.

## What grok-cli Could Borrow

1. **Security model** — deny patterns, Landlock, seccomp, SSRF protection, prompt guard, audit logging. grok-cli has almost none of this.
2. **Long-term memory** — smolclaw's Markdown + FTS5 memory system is a major capability gap.
3. **Multi-provider support** — being locked to one provider is fragile.
4. **Multi-channel gateway** — Discord, IRC, Slack, Web channels would expand reach.
5. **Error recovery** — checkpoint/rewind, fallback chains, error budgets.
6. **Self-update + analytics** — operational maturity features.

## Verdict

These are fundamentally different tools solving adjacent problems. grok-cli is a single-user desktop AI assistant with a great TUI; smolclaw is a multi-channel agent platform built for resilience and constrained environments. smolclaw is ~3x the codebase but covers ~5x the surface area (7 channels, 9 providers, 23 tools, defense-in-depth security, long-term memory, analytics). grok-cli wins on immediate user experience (the React TUI is genuinely nice) and media generation capabilities.
