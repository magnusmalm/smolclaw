# grok-cli vs smolclaw — Comparative Analysis

## At a Glance

| Dimension        | **grok-cli**                | **smolclaw**                   |
|------------------|-----------------------------|--------------------------------|
| **Language**     | TypeScript (Bun runtime)    | C11 (zero runtime)             |
| **Binary size**  | ~100+ MB (node_modules)     | 280 KB dynamic / 4.6 MB static |
| **Peak RSS**     | Not documented (Node-class) | 672 KB (musl-static)           |
| **LOC**          | ~11K TS                     | ~34K C                         |
| **Source files** | ~59 modules                 | ~161 files                     |
| **License**      | MIT                         | Private (Gitea)                |
| **Target**       | Developer desktops          | Edge devices to servers        |

## Architecture

- **Core loop** — grok-cli: Vercel AI SDK `streamText()` -> tool calls -> iterate; smolclaw: Custom
  C loop: context build -> LLM call -> tool exec -> iterate
- **Concurrency** — grok-cli: Single-threaded (Bun event loop); smolclaw: Single-threaded agent +
  channel threads + async summarization thread
- **Message bus** — grok-cli: Direct function calls; smolclaw: Thread-safe pipe-based bus (libevent)
- **Abstraction style** — grok-cli: TypeScript modules + Zod schemas; smolclaw: C vtables
  (`sc_tool_t`, `sc_provider_t`, `sc_channel_t`)
- **Error recovery** — grok-cli: Basic retry; smolclaw: 2-level rewind with checkpoints, exponential
  backoff, fallback provider chain

grok-cli leans on the Vercel AI SDK to abstract the agent loop — clean but coupled to that framework. smolclaw owns the entire stack from socket to tool execution, giving it fine-grained control over retry, rate limiting, and error budgets.

## LLM Providers

- **Providers** — grok-cli: 1 (xAI Grok only); smolclaw: 9+ (Anthropic, OpenAI, OpenRouter, Groq,
  Gemini, DeepSeek, xAI, Zhipu, vLLM/Ollama)
- **Models** — grok-cli: 11 Grok models; smolclaw: Any model behind supported providers
- **Fallback chain** — grok-cli: None; smolclaw: Configurable fallback sequence
- **Streaming** — grok-cli: Yes (AI SDK streams); smolclaw: Yes (SSE callbacks)
- **Model routing** — grok-cli: CLI flag / config; smolclaw: Inline (`Use opus: message`),
  per-channel, per-agent, config, env

smolclaw is provider-agnostic by design. grok-cli is locked to xAI — it's a Grok-specific product, not a general agent framework.

## Channels (User Interfaces)

- **Interactive TUI** — grok-cli: React + OpenTUI (rich); smolclaw: readline CLI (minimal)
- **Headless** — grok-cli: `--prompt` + JSONL output; smolclaw: `-m "message"` single-turn
- **Telegram** — grok-cli: Yes (long-polling bot); smolclaw: Yes (long-polling)
- **Discord** — grok-cli: No; smolclaw: Yes (WebSocket gateway)
- **IRC** — grok-cli: No; smolclaw: Yes (TLS)
- **Slack** — grok-cli: No; smolclaw: Yes (Socket Mode)
- **Web** — grok-cli: No; smolclaw: Yes (HTTP + WebSocket, port 8080)
- **X/Twitter** — grok-cli: No (has search tool, not channel); smolclaw: Yes (full channel)
- **Gateway mode** — grok-cli: No; smolclaw: Yes — all channels + services in one process

smolclaw has 7 channels vs grok-cli's 2 (TUI + Telegram). smolclaw's gateway mode runs everything in a single process — a proper multi-channel agent server. grok-cli is firmly a single-user desktop tool.

## Tools

- **Built-in count** — grok-cli: ~12; smolclaw: 23
- **Filesystem** — grok-cli: read/write/edit; smolclaw: read/write/edit/list/append
- **Shell** — grok-cli: bash (bg processes); smolclaw: exec (fork+exec, deny patterns, Landlock,
  seccomp)
- **Web** — grok-cli: search_web, search_x (Grok Responses API); smolclaw: web_search
  (Brave/SearXNG/DDG), web_fetch (SSRF-protected)
- **Git** — grok-cli: No dedicated tool; smolclaw: Yes (safe subcommand allowlist)
- **Memory** — grok-cli: No (session persistence only); smolclaw: memory_read/write/log/search
  (FTS5)
- **Messaging** — grok-cli: No; smolclaw: message (cross-channel), notify (Apprise)
- **Sub-agents** — grok-cli: task + delegate; smolclaw: spawn + delegate + converse (multi-agent
  debate)
- **Background** — grok-cli: Yes (child process fork); smolclaw: exec_background + bg_poll + bg_kill
- **Media** — grok-cli: image + video generation; smolclaw: No
- **Code analysis** — grok-cli: No; smolclaw: code_graph (dependency analysis)
- **Cron** — grok-cli: Yes (schedule tool + daemon); smolclaw: Yes (cron tool)
- **MCP** — grok-cli: Client only; smolclaw: Client + Server (bidirectional)

grok-cli has media generation (images/video) that smolclaw lacks. smolclaw has memory, git, code_graph, cross-channel messaging, notify, and multi-agent debate that grok-cli lacks.

## Security

- **Sandbox** — grok-cli: Shuru microVM (macOS Apple Silicon only); smolclaw: Landlock + seccomp-bpf
  (Linux kernel)
- **Command filtering** — grok-cli: None; smolclaw: ~90 deny patterns + allowlist/denylist modes
- **Prompt injection defense** — grok-cli: None visible; smolclaw: CDATA wrapping, prompt guard,
  output filtering
- **SSRF protection** — grok-cli: None visible; smolclaw: Yes (web_fetch)
- **Secret management** — grok-cli: `.env` files; smolclaw: Encrypted vault (`vault://` references)
- **Audit logging** — grok-cli: None; smolclaw: Per-day JSONL audit log of all tool calls
- **Rate limiting** — grok-cli: None; smolclaw: Per-turn (50 calls), per-hour (configurable),
  per-minute (gateway)

This is the widest gap. smolclaw treats security as a first-class concern with defense-in-depth. grok-cli delegates to an optional macOS-only sandbox and has no visible prompt injection or command injection defenses.

## Persistence & Memory

- **Sessions** — grok-cli: SQLite per workspace; smolclaw: JSONL trees with branching
- **Long-term memory** — grok-cli: None; smolclaw: Markdown files + FTS5 full-text search
- **Memory consolidation** — grok-cli: Context compaction (summarize old turns); smolclaw:
  LLM-curated consolidation (recent 3 days kept, older compressed)
- **Daily notes** — grok-cli: No; smolclaw: Yes (`YYYY-MM-DD.md`)
- **Analytics** — grok-cli: Usage tracking in SQLite; smolclaw: Full analytics (by model, channel,
  day/week/month)
- **State** — grok-cli: Session metadata; smolclaw: Dedicated state tracker + audit log

grok-cli has in-session compaction. smolclaw has a full cross-session memory system with search, consolidation, and daily journaling.

## Build & Distribution

|                   | **grok-cli**              | **smolclaw**                            |
|-------------------|---------------------------|-----------------------------------------|
| **Build tool**    | tsc + Bun                 | CMake 3.14+                             |
| **Distribution**  | npm (`npm i -g grok-dev`) | Static binary (scp/curl)                |
| **Feature flags** | None                      | 28 Kconfig flags                        |
| **Cross-compile** | N/A (JS)                  | x86_64, aarch64, armv7l                 |
| **Minimal build** | Full only                 | `defconfig.minimal` -> 280 KB           |
| **Self-update**   | npm update                | Built-in updater (check/apply/rollback) |
| **Tests**         | Vitest                    | ctest (per-module)                      |

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
