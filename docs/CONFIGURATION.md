# Configuration reference

smolclaw reads its configuration from `~/.smolclaw/config.json` (override the
home directory with `SMOLCLAW_HOME`). This document lists every option the
config parser understands, with its type, default, and meaning. The README
covers the common cases with worked examples; this is the full reference.

## Conventions

- **Environment overrides.** Many (not all) fields can be overridden by an
  environment variable; names mostly follow `SMOLCLAW_` + the uppercased JSON
  path but several are irregular. See the Environment variable overrides
  section below. Env overrides win over the file.
- **`vault://` references.** Any secret string (API keys, tokens) may be given
  as `vault://<key-name>` to resolve it from the encrypted vault rather than
  storing plaintext. Requires `SC_ENABLE_VAULT`.
- **Secret file references.** A secret string may instead be `file:///abs/path`
  or `@/abs/path`; the file's contents are read in as the value at load time.
- **`config_version`.** Top-level integer (current: `1`), written on save and
  checked on load. A file newer than the binary warns, or refuses to load in
  strict builds.
- **Defaults.** An omitted field takes the default below. Strict builds
  (`SC_STRICT_SECURITY`) tighten a few of them, noted inline.
- **Feature gating.** Options for a compiled-out feature are ignored.

## Environment variable overrides

Many fields support an environment-variable override (env wins over the file),
but **not all do**, and several names do not follow the naive path mapping. The
authoritative list is `apply_env_overrides()` in `src/config.c`.

Irregular names (do **not** match `SMOLCLAW_<PATH>`):

| JSON path                        | Environment variable              |
|----------------------------------|-----------------------------------|
| agents.defaults.announce_on_join | SMOLCLAW_ANNOUNCE_ON_JOIN         |
| channels.web.tls_cert            | SMOLCLAW_WEB_TLS_CERT             |
| channels.web.tls_key             | SMOLCLAW_WEB_TLS_KEY              |
| channels.x.poll_interval_sec     | SMOLCLAW_CHANNELS_X_POLL_INTERVAL |
| updater.check_interval_hours     | SMOLCLAW_UPDATER_CHECK_INTERVAL   |

List/map value formats:

| Environment variable                           | Format                        |
|------------------------------------------------|-------------------------------|
| SMOLCLAW_AGENTS_DEFAULTS_ALLOWED_TOOLS         | comma-separated               |
| SMOLCLAW_AGENTS_DEFAULTS_EXEC_ALLOWED_COMMANDS | comma-separated               |
| SMOLCLAW_AGENTS_DEFAULTS_FALLBACK_MODELS       | comma-separated               |
| SMOLCLAW_AGENTS_DEFAULTS_MODEL_ALIASES         | semicolon-separated key=value |

Not overridable via env (must be set in the file): includes `summary_model`,
`workspace_per_session`, `pricing`, `response_format`, provider `proxy`,
channel `allow_from`/`tools`, `request_timeout_secs`, `embed_stream_url`,
`join_channels`, and all `camera.*`, `git.*`, `delegation.*`, and MCP server
definitions.

`SMOLCLAW_VAULT_PASSWORD` unlocks the vault non-interactively (scripted setup).

## Top-level structure

```json
{
  "config_version": 1,
  "agents":      { "defaults": { ... } },
  "providers":   { "<name>": { ... } },
  "channels":    { "telegram": {}, "discord": {}, "irc": {},
                   "slack": {}, "web": {}, "x": {} },
  "tools":       { "web": { "brave": {}, "searxng": {}, "duckduckgo": {} } },
  "git":         { ... },
  "gitea":       { ... },
  "camera":      { ... },
  "mcp":         { "servers": { ... } },
  "delegation":  { "targets": { ... } },
  "updater":     { ... },
  "heartbeat":   { ... },
  "notify_urls": "..."
}
```

## `agents.defaults` — agent behavior

### Model and provider

| Key             | Type     | Default               | Description                            |
|-----------------|----------|-----------------------|----------------------------------------|
| workspace       | string   | ~/.smolclaw/workspace | Agent working directory.               |
| provider        | string   | (from model)          | Force a provider, else inferred.       |
| model           | string   | claude-sonnet-4-5-... | Primary model (provider/model ok). [1] |
| summary_model   | string   | (primary)             | Cheaper model for summaries.           |
| fallback_models | string[] | []                    | Tried in order when primary fails.     |
| model_aliases   | object   | {}                    | alias -> model for @alias override.    |
| max_tokens      | int      | 8192                  | Max output tokens per response.        |
| context_window  | int      | 0                     | Provider window; 0 = default. [2]      |
| temperature     | float    | 0.7                   | Sampling temperature.                  |
| response_format | object   | (none)                | JSON schema for structured output.     |

- [1] `model` is the full default `claude-sonnet-4-5-20250929`, truncated above.
- [2] Sets the provider context window (e.g. Ollama `num_ctx`); controls local-
  model VRAM. `0` uses the provider's own default.

### Session management

| Key                       | Type | Default | Description                            |
|---------------------------|------|---------|----------------------------------------|
| max_tool_iterations       | int  | 20      | Max tool-call loops within a turn.     |
| session_summary_threshold | int  | 20      | Messages before async summarization.   |
| session_keep_last         | int  | 4       | Recent messages kept verbatim.         |
| summary_max_transcript    | int  | 4000    | Max transcript chars to summarizer.    |
| memory_consolidation      | bool | true    | Extract facts from summaries to notes. |

### Tool output and limits

| Key                  | Type | Default | Description                          |
|----------------------|------|---------|--------------------------------------|
| max_output_chars     | int  | 10000   | Char cap on one tool's output. [1]   |
| max_fetch_chars      | int  | 50000   | Char cap on web_fetch content.       |
| max_background_procs | int  | 8       | Max concurrent background processes. |
| exec_timeout_secs    | int  | 60      | Per-command exec timeout (0 = none). |

- [1] A separate hard 32 KB sanitizer cap also applies per tool result, and
  `max_output_total` caps cumulative output per turn.

### Resource limits (per-turn and cross-turn)

| Key                     | Type | Default | Description                           |
|-------------------------|------|---------|---------------------------------------|
| max_tool_calls_per_turn | int  | 50      | Hard cap on tool calls per turn.      |
| max_turn_secs           | int  | 300     | Wall-clock budget per turn (5 min).   |
| max_output_total        | int  | 500000  | Cumulative tool output/turn (500 KB). |
| max_tool_calls_per_hour | int  | 200     | Cross-turn tool-call rate limit.      |
| max_tokens_per_hour     | int  | 0       | Token budget/hour (0 = unlimited).    |
| rate_limit_per_minute   | int  | 20      | Gateway inbound message rate limit.   |

### Security

| Key                   | Type     | Default  | Description                              |
|-----------------------|----------|----------|------------------------------------------|
| restrict_to_workspace | bool     | true     | Confine file/exec/git to workspace.      |
| workspace_per_session | bool     | false    | Per-session workspace/tasks/ subdir. [1] |
| allowed_tools         | string[] | []       | Global tool allowlist (empty = all).     |
| restrict_message_tool | bool     | false    | Limit message tool recipients.           |
| exec_mode             | string   | denylist | denylist or allowlist. [2]               |
| exec_allowed_commands | string[] | []       | Allowed commands in allowlist mode.      |
| network_scope         | string   | public   | Scope: none/local/public/any.            |
| sandbox               | bool     | true     | Landlock + seccomp for exec children.    |
| auto_confirm          | bool     | false    | Auto-approve tool confirmations.         |

- [1] Runs each session in `workspace/tasks/<id>/` (auto-pruned, last 5 kept).
- [2] `denylist` blocks ~90 dangerous patterns; `allowlist` permits only
  `exec_allowed_commands`. Strict builds default to `allowlist`.

### Cost, logging, diagnostics

| Key              | Type   | Default     | Description                             |
|------------------|--------|-------------|-----------------------------------------|
| pricing          | object | (built-in)  | Per-model $/M token overrides. [1]      |
| log_path         | string | (stderr)    | Persistent log file path.               |
| announce_on_join | bool   | false       | Post version/features on channel join.  |
| verbose          | bool   | false       | Stream progress updates to channel.     |
| tee              | object | (see below) | Mirror full output to disk on truncate. |

- [1] Shape: `{"model": {"prompt": <rate>, "completion": <rate>}}`.

`tee` sub-keys:

| Key           | Type | Default  | Description                             |
|---------------|------|----------|-----------------------------------------|
| enabled       | bool | true     | Save full output to disk on truncation. |
| max_files     | int  | 50       | Maximum tee files retained.             |
| max_file_size | int  | 10485760 | Max bytes per tee file (10 MB).         |

## `providers.<name>` — LLM provider credentials

Known names: `anthropic`, `openai`, `openrouter`, `groq`, `zhipu`, `vllm`,
`gemini`, `deepseek`, `ollama`, `xai`. Any other name is treated as a custom
OpenAI-compatible provider (up to 8), addressable as `customname/model`.

| Key      | Type   | Default            | Description                         |
|----------|--------|--------------------|-------------------------------------|
| api_key  | string | (none)             | Provider API key (vault:// ok).     |
| api_base | string | (provider default) | Override the API base URL.          |
| proxy    | string | (none)             | HTTP/SOCKS proxy for this provider. |

## `channels.*`

All channels share these fields:

| Key        | Type     | Default | Description                               |
|------------|----------|---------|-------------------------------------------|
| enabled    | bool     | false   | Activate the channel in gateway mode.     |
| dm_policy  | string   | open    | open / allowlist / pairing. [1]           |
| allow_from | string[] | []      | Permitted sender IDs (allowlist mode).    |
| tools      | string[] | []      | Per-channel tool allowlist (empty = all). |

- [1] Strict builds default `dm_policy` to `allowlist`.

### `channels.telegram`

| Key      | Type   | Default                  | Description              |
|----------|--------|--------------------------|--------------------------|
| token    | string | (none)                   | Bot token (vault:// ok). |
| api_base | string | https://api.telegram.org | API base override.       |
| proxy    | string | (none)                   | Proxy URL.               |

### `channels.discord`

| Key      | Type   | Default                     | Description        |
|----------|--------|-----------------------------|--------------------|
| token    | string | (none)                      | Bot token.         |
| api_base | string | https://discord.com/api/v10 | API base override. |

### `channels.irc`

| Key           | Type     | Default | Description                       |
|---------------|----------|---------|-----------------------------------|
| hostname      | string   | (none)  | IRC server hostname.              |
| port          | int      | 6667    | Server port (6697 with TLS).      |
| nick          | string   | (none)  | Bot nickname.                     |
| username      | string   | (nick)  | IRC USER field.                   |
| password      | string   | (none)  | Server PASS or NickServ password. |
| join_channels | string[] | []      | Channels to auto-join.            |
| tls           | bool     | false   | Connect over TLS.                 |
| group_trigger | string   | (none)  | Shared trigger word (e.g. claws). |

### `channels.slack`

| Key       | Type   | Default | Description                 |
|-----------|--------|---------|-----------------------------|
| bot_token | string | (none)  | xoxb-... Web API token.     |
| app_token | string | (none)  | xapp-... Socket Mode token. |

### `channels.web`

| Key                  | Type   | Default   | Description                            |
|----------------------|--------|-----------|----------------------------------------|
| bind_addr            | string | 127.0.0.1 | Listen address.                        |
| port                 | int    | 8080      | Listen port.                           |
| auto_port            | bool   | false     | On bind failure, try the next 10 ports. [3] |
| bearer_token         | string | (none)    | Required bearer token for auth.        |
| tls_cert             | string | (none)    | PEM cert path (enables HTTPS).         |
| tls_key              | string | (none)    | PEM private key path.                  |
| request_timeout_secs | int    | 0         | Per-request server timeout. [1]        |
| isolation_pattern    | string | wf-*      | Per-session memory namespace glob. [2] |
| embed_stream_url     | string | (none)    | Live-stream URL embedded in the UI.    |

- [1] `0` derives it from `max_turn_secs` + 30s grace; must be >= `max_turn_secs`.
- [2] Requests whose `session` matches run in an isolated memory namespace;
  empty disables. See [session isolation](operations/session-isolation.md).
- [3] When `false` and the port is taken, the bind error log names the process
  holding the port (resolved via `/proc` on Linux).

### `channels.x` (X / Twitter)

| Key                 | Type   | Default   | Description                     |
|---------------------|--------|-----------|---------------------------------|
| consumer_key        | string | (none)    | OAuth 1.0a API key.             |
| consumer_secret     | string | (none)    | OAuth 1.0a API key secret.      |
| access_token        | string | (none)    | OAuth 1.0a access token.        |
| access_token_secret | string | (none)    | OAuth 1.0a access token secret. |
| api_base            | string | (unwired) | Not read from config today. [1] |
| poll_interval_sec   | int    | 60        | Mention/DM poll interval (s).   |
| read_only           | bool   | true      | Poll only; block all outbound.  |
| enable_dms          | bool   | false     | Process DMs (paid tier).        |

- [1] The struct field exists but `load_channels()` does not parse it; the X
  API base is fixed at `https://api.x.com` at runtime.

## `tools.web` — web search backends

### Brave

| Key         | Type   | Default                      | Description          |
|-------------|--------|------------------------------|----------------------|
| enabled     | bool   | false                        | Enable Brave search. |
| api_key     | string | (none)                       | Brave API key.       |
| base_url    | string | https://api.search.brave.com | API base override.   |
| max_results | int    | 5                            | Results per query.   |

### SearXNG

| Key         | Type   | Default | Description                |
|-------------|--------|---------|----------------------------|
| enabled     | bool   | false   | Enable a SearXNG instance. |
| base_url    | string | (none)  | SearXNG base URL.          |
| max_results | int    | 5       | Results per query.         |

### DuckDuckGo

| Key         | Type | Default | Description                        |
|-------------|------|---------|------------------------------------|
| enabled     | bool | true    | Enable DuckDuckGo (no key needed). |
| max_results | int  | 5       | Results per query.                 |

## `git` — git tool

| Key                  | Type     | Default | Description                          |
|----------------------|----------|---------|--------------------------------------|
| push_allowed_remotes | string[] | []      | URL substrings allowed for push. [1] |

- [1] Empty means **push is denied** (deny-by-default). List remote URL
  substrings to permit pushing to them.

## `gitea` — Gitea API tool (`SC_ENABLE_GITEA`)

| Key         | Type   | Default      | Description                               |
|-------------|--------|--------------|-------------------------------------------|
| url         | string | (none)       | Base URL, e.g. https://gitea.example.com. |
| token       | string | (none)       | Personal access token (vault:// ok).      |
| default_org | string | (user repos) | Default org for repo creation.            |

## `camera` — camera tool (`SC_ENABLE_CAMERA`)

| Key                 | Type   | Default       | Description                            |
|---------------------|--------|---------------|----------------------------------------|
| snap_command        | string | (none)        | argv prefix; JPEG path appended. [1]   |
| events_dir          | string | camera/motion | Motion captures dir (workspace-rel).   |
| vision_url          | string | (none)        | ollama-compatible vision endpoint. [2] |
| vision_model        | string | (none)        | Vision model (e.g. gemma4:e4b).        |
| vision_timeout_secs | int    | 120           | Timeout for a describe call.           |

- [1] Run without a shell; e.g. `rpicam-still -n --width 1280 --height 720 -o`.
- [2] Unset disables the `describe` action.

## `mcp` — Model Context Protocol clients (`SC_ENABLE_MCP`)

| Key     | Type   | Default | Description                             |
|---------|--------|---------|-----------------------------------------|
| enabled | bool   | true    | Enable MCP clients (needs servers). [1] |
| servers | object | {}      | Map of {"<name>": {server}}.            |

- [1] MCP only activates when `enabled` is true **and** `servers` is non-empty.

Each `servers.<name>`:

| Key          | Type     | Default    | Description                        |
|--------------|----------|------------|------------------------------------|
| command      | string[] | (required) | argv to launch the server. [1]     |
| env          | object   | {}         | Env vars (vault:// ok in values).  |
| capabilities | object   | (blanket)  | Fine-grained sandbox override. [2] |

- [1] The binary path is auto-resolved for the Landlock sandbox.
- [2] Overrides the default workspace sandbox; sub-keys below.

`capabilities` sub-keys:

| Key      | Type     | Default   | Description                         |
|----------|----------|-----------|-------------------------------------|
| fs_read  | string[] | []        | Paths granted read-only access.     |
| fs_write | string[] | []        | Paths granted read-write access.    |
| process  | array    | (allowed) | Set to [] to block execve/fork. [1] |

- [1] Only an empty array (`"process": []`) denies process creation in
  seccomp; omitting the key leaves exec/fork allowed.

## `delegation` — remote agent delegation (`SC_ENABLE_DELEGATE`)

`delegation.targets` is an **object map** of `name -> target`. The object key
is the target name used by the `delegate`/`converse` tools — an **array form is
silently ignored**. Each value:

| Key          | Type   | Default    | Description                              |
|--------------|--------|------------|------------------------------------------|
| url          | string | (required) | Target's /api/message endpoint.          |
| bearer_token | string | (none)     | Auth token for the target (vault:// ok). |
| timeout_secs | int    | 120        | Per-delegation request timeout.          |

```json
"delegation": {
  "targets": {
    "researcher": {
      "url": "http://192.0.2.10:8082/api/message",
      "bearer_token": "vault://researcher_token",
      "timeout_secs": 120
    }
  }
}
```

## `updater` — self-update (`SC_ENABLE_UPDATER`)

| Key                  | Type   | Default | Description                          |
|----------------------|--------|---------|--------------------------------------|
| enabled              | bool   | false   | Enable update checks.                |
| manifest_url         | string | (none)  | Update manifest URL.                 |
| check_interval_hours | int    | 24      | Gateway check interval (0 = manual). |
| auto_apply           | bool   | false   | Apply updates after verification.    |

## `heartbeat` — periodic self-prompt (`SC_ENABLE_HEARTBEAT`)

| Key      | Type | Default | Description                    |
|----------|------|---------|--------------------------------|
| enabled  | bool | true    | Enable the heartbeat service.  |
| interval | int  | 30      | Heartbeat interval in minutes. |

## `cron` — scheduled jobs (`SC_ENABLE_CRON`)

Jobs are created at runtime via the `cron` tool (or hand-edited in the cron
job store) and persisted as JSON. Each job has a `schedule` with one of three
`kind`s:

| Kind    | Fields            | Behavior                                          |
|---------|-------------------|---------------------------------------------------|
| `at`    | `atMs`            | Fire once at an absolute unix-ms time, then delete |
| `every` | `everyMs`         | Fire on a fixed interval (ms)                     |
| `cron`  | `expr`, `tz`      | Fire on a 5-field cron schedule                   |

Cron `expr` is the standard `min hour dom month dow` (e.g. `0 9 * * 1` =
Mondays at 09:00). Each field supports `*`, single values, `a-b` ranges,
comma lists, and `*/step`. Day-of-week is `0-6` (Sunday = 0; `7` also = Sunday).
When both day-of-month and day-of-week are restricted, a time matches if
**either** matches (standard Vixie-cron semantics). `tz` is an optional IANA
timezone (e.g. `Europe/Stockholm`); it defaults to the server's local time. An
invalid expression disables the job (it never fires) and logs a warning.

## `notify_urls` — outbound notifications (top-level)

| Key         | Type   | Default | Description                       |
|-------------|--------|---------|-----------------------------------|
| notify_urls | string | (none)  | Comma-separated Apprise URLs. [1] |

- [1] Used by the `notify` tool, e.g. `discord://id/token,tgram://bot/chat`.
