# smolclaw

**C11 lightweight AI agent framework for constrained hardware**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A minimal, self-contained AI agent with multi-channel support, tool execution, long-term memory, and streaming — all in a single static binary.

## Highlights

- **280 KB** dynamic-minimal binary, **4.6 MB** fully static (musl, zero runtime deps)
- **672 KB** peak RSS (musl-static)
- **24** compile-time feature flags via Kconfig — build exactly what you need
- C11 strict, zero warnings, no garbage collector, no runtime

## Features

| Category        | Features                                                                                                                                                  |
|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Channels**    | CLI, Telegram, Discord, IRC, Slack (Socket Mode), Web (REST API + embedded chat UI), X/Twitter (REST polling, OAuth 1.0a)                                                 |
| **Providers**   | Anthropic (Claude), OpenAI, OpenRouter, Groq, Gemini, DeepSeek, xAI, Zhipu, vLLM, Ollama                                                                                 |
| **Tools**       | File read/write/edit/append/list, shell exec, git, web search/fetch, X read tools, memory read/write/log/search, message, cron, spawn, background processes (up to 23 built-in) |
| **Memory**      | Long-term memory (Markdown files), daily notes, auto-consolidation from session summaries, full-text search (SQLite FTS5)                                                  |
| **Security**    | ~90 deny patterns, SSRF protection, OS sandbox (Landlock + seccomp-bpf), tool confirmation, secret redaction, encrypted vault (AES-256-GCM), prompt injection defense      |
| **Integration** | SSE streaming, MCP client (JSON-RPC 2.0), model fallback chain, in-prompt model override, typing indicators                                                               |
| **Services**    | Cron scheduling, heartbeat, subagent spawning, self-update, analytics                                                                                                      |

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

Available flags: `SC_ENABLE_TELEGRAM`, `SC_ENABLE_DISCORD`, `SC_ENABLE_IRC`, `SC_ENABLE_SLACK`, `SC_ENABLE_WEB`, `SC_ENABLE_X`, `SC_ENABLE_X_TOOLS`, `SC_ENABLE_GIT`, `SC_ENABLE_WEB_TOOLS`, `SC_ENABLE_VOICE`, `SC_ENABLE_STREAMING`, `SC_ENABLE_CRON`, `SC_ENABLE_SPAWN`, `SC_ENABLE_HEARTBEAT`, `SC_ENABLE_BACKGROUND`, `SC_ENABLE_MCP`, `SC_ENABLE_MCP_SERVER`, `SC_ENABLE_MEMORY_SEARCH`, `SC_ENABLE_CODE_GRAPH`, `SC_ENABLE_VAULT`, `SC_ENABLE_UPDATER`, `SC_ENABLE_TEE`, `SC_ENABLE_OUTPUT_FILTER`, `SC_ENABLE_ANALYTICS`.

## Architecture

```
User ─── Channel ──┐
                    ├─── Bus ─── Agent Loop ─── LLM Provider
User ─── Channel ──┘         │
                             ├── Tool Registry ─── Tools
                             ├── Session Manager
                             ├── Memory (Markdown + FTS5)
                             └── Services (Cron, Heartbeat, Updater)
```

| Component       | Location                     | Purpose                                         |
|-----------------|------------------------------|--------------------------------------------------|
| Agent           | `src/agent.c`                | Initialization, model routing, tool registration |
| Agent Turn      | `src/agent_turn.c`           | Core loop, retry logic, rate limiting            |
| Agent Session   | `src/agent_session.c`        | Async summarization, memory consolidation        |
| Bus             | `src/bus.c`                  | Thread-safe message queue (libevent pipes)       |
| Providers       | `src/providers/`             | Claude, HTTP (OpenAI-compat), factory routing    |
| Tools           | `src/tools/`                 | Registry + individual tools                      |
| MCP             | `src/mcp/`                   | External tool servers via JSON-RPC 2.0           |
| Channels        | `src/channels/`              | CLI, Telegram, Discord, IRC, Slack, Web, X       |
| Memory          | `src/memory.c`               | Long-term memory + daily notes                   |
| Sessions        | `src/session.c`              | Per-conversation JSON, auto-truncation + summarization |
| Context         | `src/context.c`              | System prompt builder                            |
| Config          | `src/config.c`               | JSON config + env var overrides                  |
| Analytics       | `src/analytics.c`            | Token usage and performance tracking             |
| Tee             | `src/tee.c`                  | Tool output mirroring                            |
| Output Filter   | `src/tools/output_filter.c`  | Tool output sanitization and truncation          |
| Updater         | `src/updater/`               | Transport-agnostic self-update (HTTP built-in)   |
| Security        | `src/util/`                  | Sandbox, secrets, prompt guard, path validation  |

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
    "web": { "enabled": true, "port": 8080, "bearer_token": "..." },
    "x": { "enabled": true, "read_only": true }
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

Non-interactive mode (for scripted provisioning over SSH):

```bash
echo "mypassword" | smolclaw vault init --password-stdin
echo "sk-secret-key" | SMOLCLAW_VAULT_PASSWORD=mypassword smolclaw vault set anthropic_api_key --value-stdin
```

### X (Twitter)

smolclaw supports X/Twitter in three complementary ways:

**1. Built-in X tools** — four read-only tools (`x_get_tweet`, `x_get_thread`, `x_search`, `x_get_user`) compiled directly into the binary. No external dependencies. Supports long tweets (`note_tweet`) and X Articles. Build with `SC_ENABLE_X_TOOLS=ON` and provide OAuth credentials in `channels.x`.

**2. X MCP server** — gives the agent X read/write tools via [x-mcp](https://github.com/magnusmalm/x-mcp), a standalone MCP server for the X API v2. Useful if you need write access (posting, liking, DMs) or want to keep X tools in a separate process.

**3. X channel** — the agent has its own X presence, polling for @mentions and replying as tweets. This is the bot-on-X use case.

You can mix and match. For most read-only use cases, the built-in tools (option 1) are simplest — no Node.js or MCP setup needed.

#### Built-in X tools

Build with `SC_ENABLE_X_TOOLS=ON` (requires OpenSSL for OAuth 1.0a signing). Add credentials to `channels.x` in your config — the tools register automatically when `consumer_key` and `access_token` are present:

```json
{
  "channels": {
    "x": {
      "consumer_key": "vault://x_consumer_key",
      "consumer_secret": "vault://x_consumer_secret",
      "access_token": "vault://x_access_token",
      "access_token_secret": "vault://x_access_token_secret",
      "read_only": true
    }
  }
}
```

The four tools are then available from any channel (IRC, CLI, Web, etc.). Independent of `SC_ENABLE_X` (the channel flag).

#### X MCP server

Add to the `mcp.servers` section of your config. The agent gains tools like `x_get_tweet`, `x_get_thread`, `x_search`, `x_get_user`, and (if not read-only) `x_post_tweet`, `x_like`, etc.

```json
{
  "mcp": {
    "servers": {
      "x": {
        "command": ["node", "/path/to/x-mcp/dist/index.js"],
        "env": {
          "X_CONSUMER_KEY": "vault://x_consumer_key",
          "X_CONSUMER_SECRET": "vault://x_consumer_secret",
          "X_ACCESS_TOKEN": "vault://x_access_token",
          "X_ACCESS_TOKEN_SECRET": "vault://x_access_token_secret",
          "X_READ_ONLY": "true"
        }
      }
    }
  }
}
```

With `X_READ_ONLY=true`, all write tools (post, delete, like, retweet, DM) are blocked server-side. The agent can only read. Set to `false` to allow posting.

Setup:

```bash
git clone https://github.com/magnusmalm/x-mcp.git
cd x-mcp && npm install && npm run build
```

The four OAuth 1.0a credentials come from the [X Developer Portal](https://developer.x.com/). The Free tier cannot read tweets — you need **Pay-Per-Use** or **Basic** minimum.

#### X channel

For running a bot that actively monitors and replies on X. Polls for @mentions and optional DMs, responds as threaded tweets.

**Read-only mode** is on by default — the channel polls and processes inbound mentions, but all outbound tweets and DMs are blocked. This prevents accidental posts from rogue agent behavior. Set `"read_only": false` only when you're confident in your agent's configuration.

```json
{
  "channels": {
    "x": {
      "enabled": true,
      "consumer_key": "vault://x_consumer_key",
      "consumer_secret": "vault://x_consumer_secret",
      "access_token": "vault://x_access_token",
      "access_token_secret": "vault://x_access_token_secret",
      "read_only": true,
      "poll_interval_sec": 60,
      "enable_dms": false,
      "dm_policy": "allowlist",
      "allow_from": ["user_id_1"]
    }
  }
}
```

Env var overrides: `SMOLCLAW_CHANNELS_X_CONSUMER_KEY`, `SMOLCLAW_CHANNELS_X_CONSUMER_SECRET`, `SMOLCLAW_CHANNELS_X_ACCESS_TOKEN`, `SMOLCLAW_CHANNELS_X_ACCESS_TOKEN_SECRET`, `SMOLCLAW_CHANNELS_X_READ_ONLY`, `SMOLCLAW_CHANNELS_X_POLL_INTERVAL`, `SMOLCLAW_CHANNELS_X_ENABLE_DMS`, `SMOLCLAW_CHANNELS_X_DM_POLICY`.

Build with `SC_ENABLE_X=ON` (off by default since it requires paid API access):

```bash
cmake -B build -DSC_ENABLE_X=ON
```

### Self-update

smolclaw includes a transport-agnostic self-update system with SHA-256 verification and atomic binary replacement. HTTP transport is built-in; other transports (TFTP, UART) can be added via a vtable interface.

```bash
# Check for available updates
smolclaw update check

# Download, verify, and apply
smolclaw update apply

# Restore previous binary from .bak backup
smolclaw update rollback
```

Configure in `config.json`:

```json
{
  "updater": {
    "enabled": true,
    "manifest_url": "https://example.com/smolclaw/manifest.json",
    "check_interval_hours": 24,
    "auto_apply": false
  }
}
```

When running as a gateway, update checks happen automatically at the configured interval. Env var overrides: `SMOLCLAW_UPDATER_ENABLED`, `SMOLCLAW_UPDATER_MANIFEST_URL`, `SMOLCLAW_UPDATER_CHECK_INTERVAL`, `SMOLCLAW_UPDATER_AUTO_APPLY`.

### Versioning

Build-time version includes git metadata:

```
$ smolclaw version
🦞 smolclaw 0.9.0 (34938ea4, 2026-03-07T00:00:00Z)
```

The version header (`sc_version.h`) is auto-generated at build time with `SC_VERSION`, `SC_GIT_HASH`, `SC_BUILD_DATE`, and `SC_VERSION_FULL` (e.g. `0.9.0+34938ea4`).

### Commands

```
smolclaw onboard     Initialize configuration and workspace
smolclaw agent       Interactive agent (or -m "message" for single turn)
smolclaw gateway     Start all channels + services
smolclaw pairing     Manage channel trust (list/approve/revoke)
smolclaw vault       Manage encrypted secrets
smolclaw update      Check for and apply updates
smolclaw cost        View token usage and costs
smolclaw analytics   Usage analytics (summary, today, week, month, model, channel)
smolclaw doctor      Validate configuration and dependencies
                     --config <path>  Validate a specific config file
smolclaw version     Show version (includes git hash and build date)
```

## Security

smolclaw implements defense in depth:

- **Deny patterns**: ~90 POSIX ERE patterns block dangerous shell commands
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
