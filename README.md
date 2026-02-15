# smolclaw

**C11 lightweight AI agent framework**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A minimal, self-contained AI agent with multi-channel support, tool execution, long-term memory, and streaming — all in a single static binary.

## Highlights

- **280 KB** dynamic-minimal binary, **4.6 MB** fully static (musl, zero runtime deps)
- **672 KB** peak RSS (musl-static)
- **16** compile-time feature flags via Kconfig — build exactly what you need
- C11 strict, zero warnings, no garbage collector, no runtime

## Features

| Category | Features |
|----------|----------|
| **Channels** | CLI, Telegram, Discord, IRC, Slack (Socket Mode), Web (REST API + embedded chat UI) |
| **Providers** | Anthropic (Claude), OpenAI, OpenRouter, Groq, Gemini, DeepSeek, xAI, Zhipu, vLLM, Ollama |
| **Tools** | File read/write/edit/list, shell exec, git, web search/fetch, memory read/write/log/search, message, cron, spawn, background processes (19 built-in) |
| **Memory** | Long-term memory (Markdown files), daily notes, auto-consolidation from session summaries, full-text search (SQLite FTS5) |
| **Security** | ~83 deny patterns, SSRF protection, OS sandbox (Landlock + seccomp-bpf), tool confirmation, secret redaction, encrypted vault (AES-256-GCM), prompt injection defense |
| **Integration** | SSE streaming, MCP client (JSON-RPC 2.0), model fallback chain, in-prompt model override, typing indicators |
| **Services** | Cron scheduling, heartbeat, subagent spawning |

## Quickstart

```bash
# Build
git clone https://github.com/magnusmalm/smolclaw.git
cd smolclaw
cmake -B build && cmake --build build -j$(nproc)

# Initialize config and workspace
./build/smolclaw onboard

# Add your API key to ~/.smolclaw/config.json, then:
./build/smolclaw agent -m "Hello!"

# Interactive mode
./build/smolclaw agent

# Start gateway (all channels + services)
./build/smolclaw gateway
```

## Building

### Dynamic (default)

```bash
# Dependencies: libcurl, libevent (dev headers)
cmake -B build
cmake --build build -j$(nproc)
ctest --test-dir build
```

### Static (glibc)

```bash
./scripts/build_static_deps.sh
cmake -B build -DSC_STATIC=ON
cmake --build build -j$(nproc)
```

### Fully static (musl, zero runtime deps)

```bash
./scripts/build_musl_deps.sh
cmake -B build -DSC_MUSL_STATIC=ON -DSC_STRIP=ON
cmake --build build -j$(nproc)
```

### Cross-compile (ARM)

```bash
# aarch64
./scripts/build_musl_deps.sh aarch64
cmake -B build-aarch64 -DSC_MUSL_STATIC=ON -DTARGET_ARCH=aarch64 \
      -DCMAKE_C_COMPILER=deps/musl-toolchain-aarch64/bin/aarch64-linux-musl-gcc
cmake --build build-aarch64 -j$(nproc)

# armv7l (32-bit)
./scripts/build_musl_deps.sh armv7l
cmake -B build-armv7l -DSC_MUSL_STATIC=ON -DTARGET_ARCH=armv7l \
      -DCMAKE_C_COMPILER=deps/musl-toolchain-armv7l/bin/armv7l-linux-musleabihf-gcc
cmake --build build-armv7l -j$(nproc)
```

### Feature flags (Kconfig)

smolclaw uses [Kconfig](https://www.kernel.org/doc/html/latest/kbuild/kconfig-language.html) for compile-time feature selection. All features default to ON.

```bash
# Interactive configuration
cmake --build build --target menuconfig

# Use a minimal profile
cp configs/defconfig.minimal .config
cmake -B build && cmake --build build -j$(nproc)

# CLI override
cmake -B build -DSC_ENABLE_DISCORD=OFF -DSC_ENABLE_IRC=OFF
```

Available flags: `SC_ENABLE_TELEGRAM`, `SC_ENABLE_DISCORD`, `SC_ENABLE_IRC`, `SC_ENABLE_SLACK`, `SC_ENABLE_WEB`, `SC_ENABLE_GIT`, `SC_ENABLE_WEB_TOOLS`, `SC_ENABLE_VOICE`, `SC_ENABLE_STREAMING`, `SC_ENABLE_CRON`, `SC_ENABLE_SPAWN`, `SC_ENABLE_HEARTBEAT`, `SC_ENABLE_BACKGROUND`, `SC_ENABLE_MCP`, `SC_ENABLE_MEMORY_SEARCH`, `SC_ENABLE_VAULT`.

## Architecture

```
User ─── Channel ──┐
                    ├─── Bus ─── Agent Loop ─── LLM Provider
User ─── Channel ──┘         │
                             ├── Tool Registry ─── Tools
                             ├── Session Manager
                             ├── Memory (Markdown + FTS5)
                             └── Services (Cron, Heartbeat)
```

| Component | Location | Purpose |
|-----------|----------|---------|
| Agent | `src/agent.c` | Core loop, model override, CDATA wrapping |
| Bus | `src/bus.c` | Thread-safe message queue (libevent pipes) |
| Providers | `src/providers/` | Claude, HTTP (OpenAI-compat), factory routing |
| Tools | `src/tools/` | Registry + individual tools |
| MCP | `src/mcp/` | External tool servers via JSON-RPC 2.0 |
| Channels | `src/channels/` | CLI, Telegram, Discord, IRC, Slack, Web |
| Memory | `src/memory.c` | Long-term memory + daily notes |
| Sessions | `src/session.c` | Per-conversation JSON, auto-truncation + summarization |
| Context | `src/context.c` | System prompt builder |
| Config | `src/config.c` | JSON config + env var overrides |
| Security | `src/util/` | Sandbox, secrets, prompt guard, path validation |

## Configuration

Config lives at `~/.smolclaw/config.json`. Every field can be overridden via environment variables with `SMOLCLAW_` prefix.

```json
{
  "agents": {
    "defaults": {
      "model": "claude-sonnet-4-5-20250929",
      "provider": "anthropic"
    }
  },
  "providers": {
    "anthropic": { "api_key": "sk-..." }
  },
  "channels": {
    "telegram": { "enabled": true, "token": "..." },
    "discord": { "enabled": true, "token": "..." },
    "slack": { "enabled": true, "bot_token": "xoxb-...", "app_token": "xapp-..." },
    "web": { "enabled": true, "port": 8080, "bearer_token": "..." }
  }
}
```

### Encrypted vault

Store API keys securely with AES-256-GCM encryption:

```bash
smolclaw vault init
smolclaw vault set anthropic_api_key
# Then reference in config: "api_key": "vault://anthropic_api_key"
```

### Commands

```
smolclaw onboard     Initialize configuration and workspace
smolclaw agent       Interactive agent (or -m "message" for single turn)
smolclaw gateway     Start all channels + services
smolclaw pairing     Manage channel trust (list/approve/revoke)
smolclaw vault       Manage encrypted secrets
smolclaw cost        View token usage and costs
smolclaw doctor      Validate configuration and dependencies
smolclaw version     Show version
```

## Security

smolclaw implements defense in depth:

- **Deny patterns**: ~83 POSIX ERE patterns block dangerous shell commands
- **SSRF protection**: DNS resolution + private IP blocking + redirect validation
- **OS sandbox**: Landlock filesystem restrictions + seccomp-bpf syscall filter
- **Tool confirmation**: Side-effect tools require approval (CLI) or pass deny/allow checks (gateway)
- **Secret redaction**: 13 patterns detect and redact secrets in outputs
- **Prompt injection defense**: Tool output wrapped in XML CDATA, injection patterns flagged
- **Encrypted vault**: AES-256-GCM with PBKDF2 key derivation for API keys
- **Path validation**: Symlink-safe, blocks sensitive directories (.ssh, .aws, etc.)
- **Resource limits**: Per-turn tool call cap (50), wall-clock timeout (300s), output cap (500KB)

See [docs/SECURITY.md](docs/SECURITY.md) for full security documentation.

## Docker

```bash
docker build -t smolclaw .
docker run -v ~/.smolclaw:/home/smolclaw/.smolclaw smolclaw gateway
```

## License

[MIT](LICENSE)
