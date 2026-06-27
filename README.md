# smolclaw

**C11 lightweight AI agent framework for constrained hardware**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A minimal, self-contained AI agent with multi-channel support, tool execution, long-term memory, and streaming — all in a single static binary.

## Highlights

- **~257 KB** dynamic-minimal binary (CI-enforced budget: 1 MB), **4.6 MB** fully static (musl, zero runtime deps)
- **672 KB** peak RSS (musl-static)
- **28** compile-time feature flags via Kconfig — build exactly what you need; new features land default-off
- C11, compiled with `-Wall -Wextra -Wpedantic`, no garbage collector, no runtime

## Features

- **Channels** — CLI, Telegram, Discord, IRC, Slack (Socket Mode), Web (REST API + embedded chat
  UI), X/Twitter (REST polling, OAuth 1.0a)
- **Providers** — Anthropic (Claude), OpenAI, OpenRouter, Groq, Gemini, DeepSeek, xAI, Zhipu, vLLM,
  Ollama
- **Tools** — File read/write/edit/append/list, shell exec, git (init/config/push/pull; push is
  deny-by-default without an explicit remote allowlist), gitea (repos/issues/PRs), web search/fetch,
  X read, memory read/write/log/search, context search, code graph, message, note (scratchpad),
  cron, spawn, delegate, converse, notify, background processes, camera (capture stills, list motion
  events, describe images via a remote vision model — `SC_ENABLE_CAMERA`)
- **Memory** — Long-term memory (Markdown files), daily notes, auto-consolidation, full-text search
  (SQLite FTS5), cross-agent memory API, scratchpad (compaction-resilient working notes), automatic
  action log
- **Security** — ~90 deny patterns, SSRF protection, OS sandbox (Landlock + seccomp-bpf), tool
  confirmation, secret redaction, encrypted vault (AES-256-GCM), prompt injection defense, tool
  output sanitization (ANSI/control char stripping + 32KB cap), git push remote allowlist, exec
  blocks commands with dedicated tools, config integrity verification (SHA-256), audit log API
- **Integration** — SSE streaming, MCP client (JSON-RPC 2.0, auto binary path resolution for
  Landlock sandbox), model fallback chain, in-prompt model override, typing indicators, auto cost
  reporting to an external collector (single pricing path via cost.c; local models report $0,
  provider actuals preferred)
- **Web UI** — Embedded single-file chat UI: inline image attachments (`/api/media`), live per-turn
  progress log with provider/model per step (`/api/progress`), optional live-stream embed
  (`channels.web.embed_stream_url`, e.g. a motion-daemon MJPEG feed)
- **Multi-agent** — Subagent spawning (in-process, depth limit 3), remote delegation via REST,
  multi-turn dialogue (converse tool), cross-agent memory search, per-session workspace isolation
  (`workspace_per_session` with auto-prune), per-agent workspaces via `SMOLCLAW_HOME`, [per-session
  memory isolation](docs/operations/session-isolation.md) for delegate sessions
  (`channels.web.isolation_pattern`, default `wf-*`), per-turn tool-workspace narrowing via inbound
  `run_repo_dir` (gateway scopes `read_file`/`list_dir`/`exec`/`git` to `<workspace>/<run_repo_dir>`
  for the duration of one turn — agent-wide memory paths untouched)
- **Services** — Cron scheduling (with AI memory compaction), heartbeat, self-update, analytics

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

### Size-optimized release (MinSizeRel + LTO + gc-sections)

Use this profile for smaller binaries (release tags and the CI size-budget
job). `MinSizeRel` enables LTO (thin when the toolchain supports it),
`-ffunction-sections`/`-fdata-sections`, and `-Wl,--gc-sections` automatically
via `cmake/size_optimize.cmake`.

```bash
cp configs/defconfig .config          # or defconfig.minimal for a lean build
cmake -B build-size -DCMAKE_BUILD_TYPE=MinSizeRel
cmake --build build-size -j$(nproc) --target smolclaw
./scripts/check_size_budget.sh build-size/smolclaw 1024
```

`test_security` (prompt guard, redaction, deny patterns) runs in every profile.
The full `test_security_prod` integration suite runs only in the **full** build
profile (`SC_ENABLE_WEB`); minimal CI skips it by name (`ctest -E
test_security_prod`). Run the security suite alone with `ctest -L security`.

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

smolclaw uses [Kconfig](https://www.kernel.org/doc/html/latest/kbuild/kconfig-language.html) for compile-time feature selection. Most features default ON; newer or optional ones (camera, gitea, X, voice, code graph, analytics, delegate, output filter) default OFF — see `Kconfig` for the authoritative defaults.

```bash
# Interactive configuration
cmake --build build --target menuconfig

# Use a minimal profile
cp configs/defconfig.minimal .config
cmake -B build && cmake --build build -j$(nproc)

# CLI override
cmake -B build -DSC_ENABLE_DISCORD=OFF -DSC_ENABLE_IRC=OFF
```

Available flags: `SC_ENABLE_TELEGRAM`, `SC_ENABLE_DISCORD`, `SC_ENABLE_IRC`, `SC_ENABLE_SLACK`, `SC_ENABLE_WEB`, `SC_ENABLE_X`, `SC_ENABLE_X_TOOLS`, `SC_ENABLE_GIT`, `SC_ENABLE_GITEA`, `SC_ENABLE_WEB_TOOLS`, `SC_ENABLE_VOICE`, `SC_ENABLE_STREAMING`, `SC_ENABLE_CRON`, `SC_ENABLE_SPAWN`, `SC_ENABLE_DELEGATE`, `SC_ENABLE_HEARTBEAT`, `SC_ENABLE_BACKGROUND`, `SC_ENABLE_MCP`, `SC_ENABLE_MCP_SERVER`, `SC_ENABLE_MEMORY_SEARCH`, `SC_ENABLE_CODE_GRAPH`, `SC_ENABLE_CAMERA`, `SC_ENABLE_HOST_METRICS`, `SC_ENABLE_VAULT`, `SC_ENABLE_UPDATER`, `SC_ENABLE_TEE`, `SC_ENABLE_OUTPUT_FILTER`, `SC_ENABLE_ANALYTICS`.

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

| Component     | Location                    | Purpose                                         |
|---------------|-----------------------------|-------------------------------------------------|
| Agent         | `src/agent.c`               | Init, model routing, tool registration          |
| Agent Turn    | `src/agent_turn.c`          | Core loop, retries, rate limiting, action log   |
| Agent Session | `src/agent_session.c`       | Summarization, consolidation, compaction        |
| Bus           | `src/bus.c`                 | Thread-safe message queue (libevent pipes)      |
| Providers     | `src/providers/`            | Claude, HTTP (OpenAI-compat), factory routing   |
| Tools         | `src/tools/`                | Registry + individual tools                     |
| MCP           | `src/mcp/`                  | External tool servers via JSON-RPC 2.0          |
| Channels      | `src/channels/`             | CLI, Telegram, Discord, IRC, Slack, Web, X      |
| Memory        | `src/memory.c`              | Long-term memory + daily notes                  |
| Sessions      | `src/session.c`             | Per-conversation JSON, truncation + summary     |
| Context       | `src/context.c`             | System prompt builder, scratchpad/action log    |
| Config        | `src/config.c`              | JSON config + env var overrides                 |
| Analytics     | `src/analytics.c`           | Token usage and performance tracking            |
| Tee           | `src/tee.c`                 | Tool output mirroring                           |
| Output Filter | `src/tools/output_filter.c` | Tool output sanitization and truncation         |
| Updater       | `src/updater/`              | Transport-agnostic self-update (HTTP built-in)  |
| Security      | `src/util/`                 | Sandbox, secrets, prompt guard, path validation |

## Configuration

Config lives at `~/.smolclaw/config.json`. Override the config directory with `SMOLCLAW_HOME` (e.g., `SMOLCLAW_HOME=/tmp/my-agent` looks for `/tmp/my-agent/config.json`). Every field can be overridden via environment variables with `SMOLCLAW_` prefix.

See **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** for the complete reference — every config key, its type, default, and description — and **[docs/EXAMPLES.md](docs/EXAMPLES.md)** for ready-to-copy scenario configs. The examples below cover the common cases.

```json
{
  "agents": {
    "defaults": {
      "model": "claude-sonnet-4-5-20250929",
      "provider": "anthropic",
      "max_tokens": 8192,
      "context_window": 8192,
      "temperature": 0.7
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

- `max_tokens` — maximum output tokens per LLM response
- `context_window` — provider-level context window size (e.g. Ollama `num_ctx`). Set to 0 or omit to use the provider's default. Useful for controlling VRAM usage with local models.

### Per-channel tool allowlists

Each channel can specify which tools the LLM sees, reducing prompt token overhead:

```json
{
  "channels": {
    "irc": {
      "enabled": true,
      "tools": ["web_search", "memory_read", "memory_write", "exec"]
    },
    "web": {
      "enabled": true,
      "tools": ["web_search", "web_fetch", "file_read", "file_write", "exec", "git"]
    }
  }
}
```

When `tools` is omitted or empty, all registered tools are available (the default). This is particularly useful for local models where each tool definition adds ~150 prompt tokens.

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

### Multi-agent deployment

smolclaw supports multi-agent setups where each agent has its own config, workspace, vault, and sessions. This is managed by setting `SMOLCLAW_HOME` per agent:

```bash
# Each agent gets its own home directory
SMOLCLAW_HOME=~/.smolclaw/agents/coder smolclaw gateway
SMOLCLAW_HOME=~/.smolclaw/agents/researcher smolclaw gateway
```

For fleet deployment, an external orchestration layer can manage multi-agent provisioning — e.g. systemd template units (`smolclaw-agent@<name>.service`), per-agent vault provisioning, and a dispatcher agent that routes tasks to workers via the `delegate` tool. smolclaw provides the config options, CLI parameters (`SMOLCLAW_HOME`, the `delegate`/`converse` tools, the Web REST API), and per-session isolation that such a layer builds on.

#### Delegation

The `delegate` tool sends tasks to remote agents via their Web REST API:

```json
{
  "delegation": {
    "targets": {
      "researcher": {
        "url": "http://192.0.2.10:8082/api/message",
        "bearer_token": "vault://researcher_token",
        "timeout_secs": 120
      }
    }
  }
}
```

Build with `SC_ENABLE_DELEGATE=ON`. The agent can then use the `delegate` tool to send tasks to any configured target and receive the response. Delegation results are automatically logged to the delegating agent's daily notes.

#### Cross-agent memory search

The `delegate` tool supports a `memory_search` action that queries another agent's FTS5 memory index directly, without routing through the target's LLM:

```json
{"name": "delegate", "arguments": {
  "target": "researcher",
  "task": "VRAM optimization techniques",
  "action": "memory_search"
}}
```

This POSTs to the target's `POST /api/memory/search` endpoint and returns ranked results with snippets. Fast, free, no token cost.

#### Multi-turn agent dialogue

The `converse` tool facilitates structured debates between two remote agents:

```json
{"name": "converse", "arguments": {
  "agent_a": "coder",
  "agent_b": "researcher",
  "topic": "Should we use approach X for the migration?",
  "rounds": 3
}}
```

Each round alternates between agents, with session continuity so both agents build on the full conversation. Returns a markdown transcript. Requires two delegation targets.

#### Memory API endpoints

The Web channel exposes two endpoints for cross-agent memory operations:

- `POST /api/memory/log` — Append an entry to the agent's daily notes. Body: `{"content": "..."}`. Used by other agents and orchestration tools to propagate context.
- `POST /api/memory/search` — Query the agent's FTS5 memory index. Body: `{"query": "...", "max_results": 10}`. Returns ranked results with source and snippet. Requires `SC_ENABLE_MEMORY_SEARCH`.

Both endpoints require bearer token authentication.

#### Memory compaction

When scheduled via the cron tool, the agent can compact its MEMORY.md using AI-driven curation. Recent entries (last 3 days) are kept verbatim, older entries are compressed or dropped based on relevance.

Schedule it with a cron job using the `#compact-memory` message prefix:

```json
{"name": "cron", "arguments": {
  "name": "memory-compact",
  "every": "24h",
  "message": "#compact-memory"
}}
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
🦞 smolclaw 0.9.1 (34938ea4, 2026-03-07T00:00:00Z)
```

The version header (`sc_version.h`) is auto-generated at build time with `SC_VERSION`, `SC_GIT_HASH`, `SC_BUILD_DATE`, and `SC_VERSION_FULL` (e.g. `0.9.1+34938ea4`).

### Commands

```
smolclaw onboard      Initialize configuration and workspace
smolclaw agent        Interactive agent (or -m "message" for single turn)
smolclaw gateway      Start all channels + services
smolclaw mcp-server   Run as an MCP server (JSON-RPC over stdio; needs SC_ENABLE_MCP_SERVER)
smolclaw pairing      Manage channel trust (list/approve/revoke)
smolclaw vault        Manage encrypted secrets
smolclaw update       Check for and apply updates
smolclaw backup       Backup and restore state (create/verify/list/restore)
smolclaw session      Maintain stored sessions (compact [--force] [--max-bytes N] [key...]; prune [--keep N] [--yes])
smolclaw cost         View token usage and costs
smolclaw analytics    Usage analytics (summary, today, week, month, model, channel; requires SC_ENABLE_ANALYTICS)
smolclaw host-refresh Refresh host inventory and retained metrics
smolclaw doctor       Validate configuration and dependencies
                      --config <path>  Validate a specific config file
smolclaw selftest     Run doctor checks + an LLM round-trip; exits 0/1
smolclaw version      Show version (includes git hash and build date)
```

### Skills

Skills are reusable prompt templates — a markdown file with YAML frontmatter
followed by the prompt body. They are discovered from two directories (user
skills take precedence over project skills of the same name):

- `~/.smolclaw/skills/` — user skills
- `{workspace}/.claude/skills/` — project skills

Each skill is either `<dir>/<name>/SKILL.md` or a flat `<dir>/<name>.md`.

```markdown
---
name: triage
description: Summarize an incident and propose next steps
when-to-use: when the user pastes logs or an alert
arguments: "<incident text>"
allowed-tools: read_file, web_search   # optional; omit = all tools
model: anthropic/claude-sonnet-4-5     # optional; omit = inherit
context: inline                        # "inline" (default) or "fork" (subagent)
user-invocable: true                   # default true; false hides the /slash
disable-model-invocation: false        # default false; true = user-only
---

Triage the following. $ARGUMENTS

Steps: 1) classify severity 2) summarize 3) propose actions.
```

The body is expanded on use, with `$ARGUMENTS` replaced by the invocation text.

**Invoking a skill:**

- **Slash command** — `/triage <text>` in any channel or the CLI expands the
  skill as a user message (only when `user-invocable` is true). Note the gateway
  reserves `/help`, `/status`, `/reset`, `/new`, `/model`, `/compress`, so avoid
  those as skill names.
- **`skill` tool** — the model calls it by name (unless
  `disable-model-invocation` is set). `context: inline` returns the expanded
  prompt as the tool result; `context: fork` runs it in a subagent.

The frontmatter mirrors the [agentskills.io](https://agentskills.io) /
Claude Code `SKILL.md` format for portability; smolclaw ships no Skills Hub —
drop files in the directories above. To author skills with the agent itself,
see [docs/development/using-grok-implement-skill.md](docs/development/using-grok-implement-skill.md).

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
Operators running `smolclaw gateway` on a network should read
[docs/operations/gateway-threat-model.md](docs/operations/gateway-threat-model.md)
(web bearer token, `auto_confirm`, rate limits).

## Docker

```bash
docker build -t smolclaw .
docker run -v ~/.smolclaw:/home/smolclaw/.smolclaw smolclaw gateway
```

## License

[MIT](LICENSE)
