# Example configurations

Ready-to-adapt deployment scenarios. Each links a copy-paste config under
[`config/examples/`](../config/examples/). For the full key reference see
[CONFIGURATION.md](CONFIGURATION.md).

Two layers control what an agent can do:

1. **Compile-time** — Kconfig `SC_ENABLE_*` flags decide what is built into the
   binary (`Kconfig`, `configs/defconfig`, `configs/defconfig.minimal`).
2. **Runtime** — `config.json` decides which channels are on, provider
   credentials, and tool allowlists.

Core tools (`read_file`, `write_file`, `exec`, `memory_*`, `host_status`, …) are
always compiled in. Use `agents.defaults.allowed_tools` and/or
`channels.<name>.tools` to restrict what the LLM actually sees.

---

## Scenario 1 — x86 Linux desktop, local-only models, all features

**Profile:** developer workstation with Ollama; no cloud LLM calls; full-feature
binary.
Config: [`desktop-local-ollama.json`](../config/examples/desktop-local-ollama.json).

**Build** (default `configs/defconfig`, all features on):

```bash
cmake -B build && cmake --build build -j$(nproc)
./build/smolclaw onboard
```

**Key decisions:**

- `network_scope: "local"` keeps tool HTTP on localhost/LAN; pair with a local
  SearXNG and disable the cloud search backends.
- `context_window` tunes Ollama `num_ctx` for VRAM.
- The web `bearer_token` is read from a file via `file:///…` (see
  [secret file references](CONFIGURATION.md#conventions)).
- Enable more channels by setting `enabled: true` and adding tokens.

---

## Scenario 2 — Raspberry Pi Zero, OpenRouter, camera + web only

**Profile:** embedded armv7 host; cloud LLM via OpenRouter; minimal binary;
camera surveillance through the web UI.
Config: [`pizero-camera-openrouter.json`](../config/examples/pizero-camera-openrouter.json).

**Build** (minimal profile plus only the features needed):

```bash
cp configs/defconfig.minimal .config
# Enable only what this device needs, e.g.:
#   CONFIG_SC_ENABLE_WEB=y
#   CONFIG_SC_ENABLE_CAMERA=y
#   # CONFIG_SC_ENABLE_HOST_METRICS is not set   (drops ~700 KB SQLite)

cmake -B build-armv7l -DSC_MUSL_STATIC=ON -DTARGET_ARCH=armv7l \
  -DCMAKE_C_COMPILER=deps/musl-toolchain-armv7l/bin/armv7l-linux-musleabihf-gcc
cmake --build build-armv7l -j2
```

**Key decisions:**

- Runtime `allowed_tools` + `channels.web.tools` hide every core tool from the
  LLM; only `camera` is exposed.
- OpenRouter needs `network_scope: "public"` (or `"any"`).
- `auto_confirm: true` for headless/autonomous gateway operation.
- `embed_stream_url` adds a live-view (MJPEG) toggle to the embedded web UI.
- **armv7 caveat:** run `smolclaw gateway`, not one-shot `smolclaw agent` — the
  CLI exits with SIGILL on armv7 at process teardown
  ([known issue](known-issue-armv7-cli-exit-sigill.md)). The gateway is
  unaffected.
- Use `SMOLCLAW_HOME` for per-device config when running as a service user.

---

## More scenarios

- **Orchestrated worker node** — Web channel; `isolation_pattern: "wf-*"`;
  `auto_confirm`; delegation target on a dispatcher (object-map format).
- **Strict production gateway** — `SC_STRICT_SECURITY` build; all channels
  `dm_policy: "allowlist"`; `exec_mode: "allowlist"`; vault for secrets;
  `restrict_message_tool: true`.
- **IRC + cloud, token budget** — IRC channel only; OpenRouter/Groq; per-channel
  `tools` allowlist.
- **Air-gapped / offline** — `network_scope: "none"`; Ollama only; all
  `tools.web` backends disabled.
- **Telegram home assistant** — Telegram channel; `notify_urls`; heartbeat +
  cron; no web exposure.
- **Developer workstation** — `workspace_per_session: true`; git + gitea +
  `code_graph`; `git.push_allowed_remotes` set.
- **Multi-agent fleet** — per-agent `SMOLCLAW_HOME`; dispatcher with a
  `delegation.targets` object map; workers on web ports 8082+.

> Delegation targets are an **object map** keyed by target name, not an array —
> see [CONFIGURATION.md](CONFIGURATION.md#delegation--remote-agent-delegation-sc_enable_delegate).
