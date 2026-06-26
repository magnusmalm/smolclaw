# CONFIGURATION.md validation report

**Purpose:** Agent-readable audit of `docs/CONFIGURATION.md` against the smolclaw codebase.  
**Validated against:** `src/config.c`, `src/config.h`, `src/constants_limits.h`, `src/providers/factory.c`, `tests/test_config.c`, channel/tool registration in `src/agent.c`.  
**Date:** 2026-06-15

Use this document when:

- Verifying whether a config key, default, or shape is correct before editing user configs
- Writing or reviewing `docs/CONFIGURATION.md`, README examples, or `config/examples/`
- Generating scenario-specific config JSON for deployments

For the authoritative key reference, see [CONFIGURATION.md](CONFIGURATION.md).

---

## Close-out status (re-verified 2026-06-26)

> **RESOLVED — all 5 critical findings are fixed in `CONFIGURATION.md`.** This
> report drove the corrections and is retained as a closed audit record. Re-run
> the checks in "Source file index" before trusting it again.

| # | Critical finding | Status | Evidence in `CONFIGURATION.md` |
|---|------------------|--------|--------------------------------|
| 1 | `delegation.targets` array → object map | ✅ Fixed | object map shown (L73, L367) |
| 2 | `mcp.capabilities` `no_process` → `process: []` | ✅ Fixed | documented as empty array + footnote (L350) |
| 3 | `heartbeat.enabled` / `mcp.enabled` defaults `false`→`true` | ✅ Fixed | both `true` (L326, L390) |
| 4 | `channels.x.api_base` documented but unwired | ✅ Fixed | marked "(unwired) Not read from config today" (L258) |
| 5 | env-override "any field" overstated | ✅ Fixed | softened to "names mostly follow…" (L11) |

The "Minor / clarifying issues" section below was **not** re-verified in this
pass and may still be actionable.

---

## Executive summary

Most keys, types, and defaults in `CONFIGURATION.md` match the implementation. A **small set of errors would cause silent failures** if users copy the doc literally (especially `delegation.targets`). Several useful code features are **undocumented**.

| Status | Count | Action |
|--------|-------|--------|
| Critical doc bugs | 5 | Fix in CONFIGURATION.md and README |
| Minor / clarifying gaps | 8+ | Document or implement |
| Verified correct | ~95% of keys | No change needed |

---

## Critical discrepancies (must fix in CONFIGURATION.md)

### 1. `delegation.targets` — documented as array, code expects object map

**CONFIGURATION.md and README** show an array with a `name` field inside each element.

**Code** (`load_delegation_config` in `src/config.c`) requires an **object** whose keys are target names. `sc_json_get_object` rejects arrays, so an array form is **silently ignored**.

```c
// src/config.c — delegation parsing
const cJSON *targets = sc_json_get_object(deleg, "targets");  // must be object
cJSON_ArrayForEach(tgt, targets) {
    t->name = sc_strdup(tgt->string);  // name from object KEY, not a "name" field
```

**Wrong (do not use):**

```json
"delegation": {
  "targets": [
    {
      "name": "researcher",
      "url": "http://192.0.2.10:8082/api/message"
    }
  ]
}
```

**Correct:**

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

Also fix the top-level structure diagram in CONFIGURATION.md (`"targets": [ ... ]` → `"targets": { ... }`).

---

### 2. `mcp.capabilities.no_process` — documented as bool, code uses `process: []`

CONFIGURATION.md documents `no_process` as a boolean sub-key.

**Code** checks for an empty `process` array:

```c
const cJSON *proc = cJSON_GetObjectItem(caps, "process");
if (proc && cJSON_IsArray(proc) && cJSON_GetArraySize(proc) == 0)
    s->caps.no_process = 1;  /* empty array = deny */
```

**Correct:**

```json
"capabilities": {
  "fs_read": ["/path"],
  "fs_write": ["/path"],
  "process": []
}
```

The `no_process` bool key is **not parsed**.

---

### 3. Wrong defaults: `heartbeat.enabled` and `mcp.enabled`

| Key | CONFIGURATION.md says | Code default (`sc_config_default` + JSON load fallback) |
|-----|----------------------|--------------------------------------------------------|
| `heartbeat.enabled` | `false` | `true` |
| `mcp.enabled` | `false` | `true` |

MCP only activates when `enabled` is true **and** `servers` is non-empty (`src/agent.c`), but the documented default is still wrong.

`config/config.example.json` correctly has `"heartbeat": { "enabled": true }`.

---

### 4. `channels.x.api_base` — documented but not loaded

- Struct field exists in `src/config.h`
- CONFIGURATION.md documents `api_base` with default `https://api.x.com`
- `load_channels()` **never parses** `api_base` for the X channel
- Runtime falls back to `https://api.x.com` in `sc_x_creds_new()` (`src/util/x_api.c`)

**Impact:** Config overrides for `channels.x.api_base` have no effect today. Either implement parsing in `load_channels()` or remove/mark as unwired in the doc.

---

### 5. Environment override convention is overstated

CONFIGURATION.md states: *"Any field can be overridden with an environment variable named `SMOLCLAW_` + uppercased JSON path."*

Only a **subset** is implemented in `apply_env_overrides()` (`src/config.c`). Notable gaps:

| Missing env overrides | Examples |
|----------------------|----------|
| Agent fields | `summary_model`, `workspace_per_session`, `pricing`, `response_format` |
| Provider | `proxy` on all providers |
| Channels | `allow_from`, `tools`, `join_channels`, `embed_stream_url`, `request_timeout_secs` |
| Other sections | `camera.*`, `git.*`, `delegation.*`, MCP server definitions |

**Non-obvious env names (differ from naive path mapping):**

| JSON path | Actual env var |
|-----------|----------------|
| `agents.defaults.announce_on_join` | `SMOLCLAW_ANNOUNCE_ON_JOIN` (not under `AGENTS_DEFAULTS_`) |
| `channels.web.tls_cert` | `SMOLCLAW_WEB_TLS_CERT` |
| `channels.web.tls_key` | `SMOLCLAW_WEB_TLS_KEY` |
| `updater.check_interval_hours` | `SMOLCLAW_UPDATER_CHECK_INTERVAL` |
| `channels.x.poll_interval_sec` | `SMOLCLAW_CHANNELS_X_POLL_INTERVAL` |

**Special env formats:**

- `SMOLCLAW_AGENTS_DEFAULTS_EXEC_ALLOWED_COMMANDS` — comma-separated
- `SMOLCLAW_AGENTS_DEFAULTS_ALLOWED_TOOLS` — comma-separated
- `SMOLCLAW_AGENTS_DEFAULTS_FALLBACK_MODELS` — comma-separated
- `SMOLCLAW_AGENTS_DEFAULTS_MODEL_ALIASES` — semicolon-separated `key=value` pairs

---

## Minor / clarifying issues

| Topic | Detail |
|-------|--------|
| `config_version` | Written on save (`SC_CONFIG_VERSION = 1` in `src/constants_app.h`), validated on load; not documented in CONFIGURATION.md |
| Secret file refs | `file:///absolute/path` and `@/absolute/path` resolve secret fields at load time; not in CONFIGURATION conventions |
| `SMOLCLAW_VAULT_PASSWORD` | Used for non-interactive vault unlock; not documented |
| Provider `api_base` defaults | Doc says "provider default"; runtime defaults are in `provider_table[]` (`src/providers/factory.c`) |
| `camera.snap_command` | Documented as string — correct; split on whitespace into argv (no shell) |
| Brave `base_url` | Doc default `https://api.search.brave.com` is correct; applied at runtime in `src/tools/web.c` if unset in config struct |
| Core tools on minimal builds | Filesystem, exec, memory, `host_status`, etc. are always compiled; feature flags only gate optional tools/channels |
| `camera.events_dir` default | `"camera/motion"` applied when `camera` section exists in JSON, or inside `sc_tool_camera_new()` if NULL |

---

## Verified correct (spot-checked)

These match `src/config.c` and `src/constants_limits.h`:

### `agents.defaults`

All documented keys: model/provider, `summary_model`, `fallback_models`, `model_aliases`, limits, security (`restrict_to_workspace`, `exec_mode`, `network_scope`, `sandbox`, etc.), `tee`, `pricing`, `log_path`, `memory_consolidation`, `announce_on_join`, `verbose`, `auto_confirm`.

**Defaults confirmed:**

| Key | Default |
|-----|---------|
| `workspace` | `~/.smolclaw/workspace` |
| `model` | `claude-sonnet-4-5-20250929` |
| `max_tokens` | `8192` |
| `context_window` | `0` |
| `temperature` | `0.7` |
| `max_tool_iterations` | `20` |
| `session_summary_threshold` | `20` |
| `session_keep_last` | `4` |
| `max_output_chars` | `10000` |
| `max_fetch_chars` | `50000` |
| `max_background_procs` | `8` |
| `summary_max_transcript` | `4000` |
| `exec_timeout_secs` | `60` |
| `max_tool_calls_per_turn` | `50` |
| `max_turn_secs` | `300` |
| `max_output_total` | `500000` |
| `max_tool_calls_per_hour` | `200` |
| `max_tokens_per_hour` | `0` (unlimited) |
| `rate_limit_per_minute` | `20` |
| `restrict_to_workspace` | `true` |
| `workspace_per_session` | `false` |
| `sandbox` | `true` |
| `memory_consolidation` | `true` |
| `restrict_message_tool` | `false` |
| `exec_mode` | `denylist` (`allowlist` if `SC_STRICT_SECURITY`) |
| `network_scope` | `public` |
| `tee.enabled` | `true` |
| `tee.max_files` | `50` |
| `tee.max_file_size` | `10485760` |

### `providers.<name>`

Known builtins: `anthropic`, `openai`, `openrouter`, `groq`, `zhipu`, `vllm`, `gemini`, `deepseek`, `ollama`, `xai`. Up to 8 custom OpenAI-compatible providers.

Factory default bases (`src/providers/factory.c`):

| Provider | Default `api_base` |
|----------|-------------------|
| anthropic | `https://api.anthropic.com/v1` |
| openai | `https://api.openai.com/v1` |
| openrouter | `https://openrouter.ai/api/v1` |
| groq | `https://api.groq.com/openai/v1` |
| zhipu | `https://open.bigmodel.cn/api/paas/v4` |
| gemini | `https://generativelanguage.googleapis.com/v1beta` |
| vllm | *(none — must set `api_base`)* |
| deepseek | `https://api.deepseek.com/v1` |
| xai | `https://api.x.ai/v1` |
| ollama | `http://localhost:11434/v1` |

### Channels

Shared fields (`enabled`, `dm_policy`, `allow_from`, `tools`) and per-channel fields match, except `channels.x.api_base` (see above).

Runtime API base fallbacks when unset: Telegram → `https://api.telegram.org`, Discord → `https://discord.com/api/v10`.

`channels.web` defaults: `bind_addr=127.0.0.1`, `port=8080`, `isolation_pattern=wf-*`.

`channels.x` defaults: `poll_interval_sec=60`, `read_only=true`, `enable_dms=false`.

`dm_policy`: `open` by default; `allowlist` when `SC_STRICT_SECURITY`.

### Other sections

- `tools.web` — brave/searxng/duckduckgo keys and defaults
- `git.push_allowed_remotes` — empty means push denied
- `gitea` — url, token, default_org
- `camera` — snap_command, events_dir, vision_*, vision_timeout_secs (default 120)
- `updater` — enabled, manifest_url, check_interval_hours (24), auto_apply
- `notify_urls` — top-level comma-separated string
- `vault://` references — require `SC_ENABLE_VAULT`

---

## Compile-time vs runtime feature control

Agents must distinguish two layers:

1. **Kconfig flags** (`SC_ENABLE_*`) — controls what is compiled into the binary. See `Kconfig`, `configs/defconfig`, `configs/defconfig.minimal`.
2. **Config JSON** — controls runtime behavior (which channels are on, tool allowlists, provider credentials).

Even on a minimal build, core tools (`read_file`, `write_file`, `exec`, `memory_*`, `host_status`, etc.) remain in the binary. Use `agents.defaults.allowed_tools` and/or `channels.<name>.tools` to restrict what the LLM sees.

### Tool names for allowlists

Common registered tool names (full build):

| Tool | Name string |
|------|-------------|
| Filesystem | `read_file`, `write_file`, `list_dir`, `edit_file`, `append_file` |
| Shell | `exec`, `exec_background`, `bg_poll`, `bg_kill` |
| Web | `web_search`, `web_fetch` |
| Memory | `memory_read`, `memory_write`, `memory_log`, `memory_search`, `context_search` |
| Note | `note` |
| Git | `git`, `worktree_enter`, `worktree_exit` |
| Host | `host_status`, `host_inventory`, `host_trend` |
| Camera | `camera` |
| Multi-agent | `spawn`, `delegate`, `converse`, `message` |
| Other | `cron`, `notify`, `code_graph`, `symbol_lookup`, `tool_search`, `skill` |
| X tools | `x_get_tweet`, `x_get_thread`, `x_search`, `x_get_user` |

MCP tools are registered as `<server>__<tool>` (e.g. `mock__echo`).

---

## Example configurations

Recommended layout for user docs:

- **`docs/EXAMPLES.md`** — narrative + build commands (this section)
- **`config/examples/*.json`** — copy-paste JSON files
- Link from README Configuration section

---

### Scenario 1: x86 Linux desktop — local-only models, all features

**Profile:** Developer workstation with Ollama; no cloud LLM calls; full feature binary.

**Build:**

```bash
cmake -B build && cmake --build build -j$(nproc)
./build/smolclaw onboard
```

Uses default `configs/defconfig` (all `SC_ENABLE_*` features on).

**Config (`~/.smolclaw/config.json`):**

```json
{
  "config_version": 1,
  "agents": {
    "defaults": {
      "provider": "ollama",
      "model": "qwen2.5:14b",
      "summary_model": "qwen2.5:3b",
      "context_window": 32768,
      "max_tokens": 8192,
      "temperature": 0.7,
      "network_scope": "local",
      "restrict_to_workspace": true,
      "sandbox": true,
      "memory_consolidation": true,
      "verbose": true
    }
  },
  "providers": {
    "ollama": {
      "api_base": "http://127.0.0.1:11434/v1"
    }
  },
  "channels": {
    "web": {
      "enabled": true,
      "bind_addr": "127.0.0.1",
      "port": 8080,
      "bearer_token": "file:///home/you/.secrets/smolclaw-web-token"
    },
    "telegram": { "enabled": false },
    "discord": { "enabled": false },
    "irc": { "enabled": false },
    "slack": { "enabled": false },
    "x": { "enabled": false }
  },
  "tools": {
    "web": {
      "searxng": {
        "enabled": true,
        "base_url": "http://127.0.0.1:8081",
        "max_results": 5
      },
      "duckduckgo": { "enabled": false },
      "brave": { "enabled": false }
    }
  },
  "mcp": {
    "enabled": true,
    "servers": {
      "filesystem": {
        "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/you/projects"],
        "capabilities": {
          "fs_read": ["/home/you/projects"],
          "fs_write": ["/home/you/projects"]
        }
      }
    }
  },
  "heartbeat": { "enabled": true, "interval": 30 },
  "git": {
    "push_allowed_remotes": ["github.com/myuser", "gitea.home.lan"]
  }
}
```

**Key decisions:**

- `network_scope: "local"` — tool HTTP stays on localhost/LAN; pair with local SearXNG, disable cloud search backends.
- `context_window` — tune for VRAM with Ollama (`num_ctx`).
- Enable additional channels by setting `enabled: true` and adding tokens.
- Add `gitea`, `delegation`, `notify_urls`, `camera` sections as needed on full builds.

---

### Scenario 2: Raspberry Pi Zero — OpenRouter, camera + web only

**Profile:** Embedded armv7 host; cloud LLM via OpenRouter; minimal binary; camera surveillance via web UI.

**Build:**

```bash
cp configs/defconfig.minimal .config
# Merge in only required features (example — adjust merge mechanism to your workflow):
#   CONFIG_SC_ENABLE_WEB=y
#   CONFIG_SC_ENABLE_CAMERA=y
#   # CONFIG_SC_ENABLE_HOST_METRICS is not set  (saves ~700KB SQLite)

cmake -B build-armv7l -DSC_MUSL_STATIC=ON -DTARGET_ARCH=armv7l \
  -DCMAKE_C_COMPILER=deps/musl-toolchain-armv7l/bin/armv7l-linux-musleabihf-gcc
cmake --build build-armv7l -j2
```

**Config:**

```json
{
  "config_version": 1,
  "agents": {
    "defaults": {
      "provider": "openrouter",
      "model": "openrouter/anthropic/claude-sonnet-4",
      "max_tokens": 2048,
      "max_tool_iterations": 10,
      "max_turn_secs": 180,
      "network_scope": "public",
      "auto_confirm": true,
      "verbose": false,
      "allowed_tools": ["camera"]
    }
  },
  "providers": {
    "openrouter": {
      "api_key": "vault://openrouter_key"
    }
  },
  "channels": {
    "web": {
      "enabled": true,
      "bind_addr": "0.0.0.0",
      "port": 8080,
      "bearer_token": "vault://web_bearer",
      "dm_policy": "allowlist",
      "allow_from": ["home-laptop", "phone"],
      "tools": ["camera"],
      "embed_stream_url": "http://127.0.0.1:8081/stream.mjpg",
      "request_timeout_secs": 210
    }
  },
  "camera": {
    "snap_command": "rpicam-still -n --width 1280 --height 720 -o",
    "events_dir": "camera/motion",
    "vision_url": "http://127.0.0.1:11434/v1",
    "vision_model": "gemma3:4b",
    "vision_timeout_secs": 120
  },
  "heartbeat": { "enabled": false },
  "mcp": { "enabled": false }
}
```

**Key decisions:**

- Compile-time: `defconfig.minimal` + `SC_ENABLE_WEB` + `SC_ENABLE_CAMERA` only.
- Runtime: `allowed_tools` + `channels.web.tools` hide core tools from the LLM; only `camera` is exposed.
- OpenRouter requires `network_scope: "public"` (or `"any"`).
- `auto_confirm: true` for headless/autonomous gateway operation.
- `embed_stream_url` — MJPEG/live view toggle in embedded web UI.
- **armv7 caveat:** prefer `smolclaw gateway` over one-shot `smolclaw agent` — CLI exits with SIGILL on armv7 ([known-issue-armv7-cli-exit-sigill.md](known-issue-armv7-cli-exit-sigill.md)).
- Use `SMOLCLAW_HOME` for per-device config when running as a service user.

---

## Additional scenarios to document

| Scenario | Build / config highlights |
|----------|----------------------------|
| **smolswarm worker node** | Web channel; `isolation_pattern: "wf-*"`; `auto_confirm`; delegation target on dispatcher (object-map format) |
| **Strict production gateway** | `SC_STRICT_SECURITY` build; all channels `dm_policy: "allowlist"`; `exec_mode: "allowlist"`; vault for secrets; `restrict_message_tool: true` |
| **IRC + cloud, token budget** | IRC channel only; OpenRouter/Groq; per-channel `tools` allowlist |
| **Air-gapped / offline** | `network_scope: "none"`; Ollama only; all `tools.web` backends disabled |
| **Telegram home assistant** | Telegram channel; `notify_urls`; heartbeat + cron; no web exposure |
| **Developer workstation** | `workspace_per_session: true`; git + gitea + `code_graph`; `git.push_allowed_remotes` set |
| **Multi-agent fleet** | Per-agent `SMOLCLAW_HOME`; dispatcher with `delegation.targets` object map; workers on web ports 8082+ |

---

## Recommended doc fixes (priority order)

1. Fix `delegation.targets` to **object-map** format in CONFIGURATION.md and README.
2. Fix `mcp.enabled` and `heartbeat.enabled` defaults to **`true`**.
3. Document `mcp.capabilities.process: []` instead of `no_process: bool`.
4. Implement or remove `channels.x.api_base` from the reference.
5. Replace blanket env-var claim with the **actual list** from `apply_env_overrides()`.
6. Add to conventions: `config_version`, `file://` / `@/` secret refs, `SMOLCLAW_VAULT_PASSWORD`.

---

## Source file index (for re-validation)

| Concern | Primary files |
|---------|---------------|
| Config parse/load/save | `src/config.c`, `src/config.h` |
| Defaults | `src/constants_limits.h`, `sc_config_default()` |
| Provider routing | `src/providers/factory.c` |
| Tool registration | `src/agent.c` |
| Channel API bases | `src/channels/telegram.c`, `src/channels/discord.c`, `src/util/x_api.c` |
| Feature flags | `Kconfig`, `configs/defconfig`, `configs/defconfig.minimal` |
| Tests | `tests/test_config.c`, `tests/test_mcp.c` |

When re-running this audit after code changes, diff `src/config.c` (`load_*` and `apply_env_overrides`) first.