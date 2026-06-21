# Documentation Truthfulness Audit — smolclaw

**Audit ID:** repo-audit-4298ba13  
**Scope:** Full repo (prioritized: README.md, RELEASE_NOTES.md, SCOPE.md, docs/, CLAUDE.md, src/ public headers)  
**Mode:** Read-only spot-check against implementation  
**Date:** 2026-06-21

## Summary

| Category | Count |
|----------|------:|
| **False** (doc contradicts code) | **3** |
| **Stale** (outdated vs current code/build) | **5** |
| Missing / incomplete (medium) | 12 |
| Verified accurate (spot-checked) | 18+ claims |

---

## Findings

### README cron example uses wrong tool name (`cronjob` vs `cron`)
- Severity: high
- Doc location: README.md:Memory compaction (cron schedule example)
- Code location: src/tools/cron.c:188
- Claim: `{"name": "cronjob", "arguments": {...}}`
- Reality: The registered tool name is `"cron"` (`t->name = "cron"`). Copy-pasting the README example will fail tool validation.
- Fix: update doc
- Status: open

### README lists `analytics` CLI without build-flag qualifier
- Severity: high
- Doc location: README.md:Commands (`smolclaw analytics ...`)
- Code location: src/main.c:1070-1114, 2211-2214; Kconfig:150-152; configs/defconfig.minimal:25
- Claim: `smolclaw analytics` is always available with subcommands `summary|today|week|month|model|channel`.
- Reality: Command and `cmd_analytics()` are compiled only when `SC_ENABLE_ANALYTICS` is on (`#if SC_ENABLE_ANALYTICS`). Flag defaults **off** (`default n`); minimal defconfig explicitly disables it. Default/minimal builds have no `analytics` command.
- Fix: update doc (note `SC_ENABLE_ANALYTICS=ON` requirement, matching `mcp-server`/`vault`/`update` pattern)
- Status: open

### Kconfig web-channel help denies TLS support
- Severity: medium
- Doc location: Kconfig:40-47 (`SC_ENABLE_WEB` help text)
- Code location: src/channels/web.c:1232-1277, 1436-1437; docs/CONFIGURATION.md (tls_cert/tls_key)
- Claim: "No TLS — use a reverse proxy (nginx/caddy) for HTTPS."
- Reality: Web channel implements optional native TLS when both `channels.web.tls_cert` and `channels.web.tls_key` are set (OpenSSL `evhttp_set_bevcb`). CONFIGURATION.md documents these keys.
- Fix: update doc (Kconfig help: "optional built-in TLS or reverse proxy")
- Status: open

### RELEASE_NOTES dynamic-minimal size is outdated
- Severity: medium
- Doc location: RELEASE_NOTES.md:Binary sizes table (Dynamic minimal 280 KB)
- Code location: build-size/smolclaw (stripped: 261904 B ≈ 256 KB); docs/progress-2026-06-11.md:60 (257 KB); README.md:11 (256 KB)
- Claim: "Dynamic minimal | 280 KB"
- Reality: Current CI/minimal build reports ~256–257 KB stripped; local `build-size/smolclaw` strips to 255.7 KB. README headline (256 KB) matches; RELEASE_NOTES table does not.
- Fix: update doc
- Status: open

### Internal docs still cite 280 KB minimal binary
- Severity: low
- Doc location: docs/design/deferred-initialization.md:5; grok-cli-vs-smolclaw.md:8
- Code location: scripts/check_size_budget.sh; build-size artifact (256 KB stripped)
- Claim: "280 KB binary" / "280 KB dynamic"
- Reality: Superseded by 256–257 KB measurements in progress notes and README.
- Fix: update doc
- Status: open

### CONFIGURATION-VALIDATION.md meta-claim about `config_version` is stale
- Severity: low
- Doc location: docs/CONFIGURATION-VALIDATION.md:161
- Code location: docs/CONFIGURATION.md:19-21
- Claim: "`config_version` … not documented in CONFIGURATION.md"
- Reality: CONFIGURATION.md now documents `config_version` in Conventions. The validation doc's own remediation list (line 487) is also outdated.
- Fix: update doc (or remove stale validation artifact)
- Status: open

### CLI `print_help()` omits documented `analytics` command
- Severity: medium
- Doc location: README.md:471; src/main.c:197-224 (`print_help`)
- Code location: src/main.c:2212-2213 (dispatch exists behind `#if SC_ENABLE_ANALYTICS`)
- Claim: README Commands section is the CLI contract.
- Reality: `print_help()` never prints `analytics` even when compiled in. Users discover the command only from README/source.
- Fix: update code help text **or** document that help is incomplete (prefer adding to `print_help` behind `#if SC_ENABLE_ANALYTICS`)
- Status: open

### Audit log API endpoint undocumented
- Severity: medium
- Doc location: README.md:33 ("audit log API"); RELEASE_NOTES.md:60
- Code location: src/channels/web.c:871-902, 1287 (`GET /api/audit`)
- Claim: "audit log API" exists.
- Reality: `GET /api/audit?limit=&since=` returns recent audit entries as JSON; requires bearer auth. No request/response schema in docs/CONFIGURATION.md, SECURITY.md, or README.
- Fix: update doc (add Web API section: `/api/audit`, `/api/health`, `/api/progress`, `/api/media`)
- Status: open

### Config SHA-256 integrity sidecar mechanism undocumented in main references
- Severity: medium
- Doc location: README.md:33 ("config integrity verification (SHA-256)")
- Code location: src/config.c:1365-1404
- Claim: Config integrity verification via SHA-256.
- Reality: On load, if `{config_path}.sha256` exists, hash is checked via `sha256sum` subprocess; mismatch logs WARN only (non-blocking). Mechanism documented only in `docs/progress-2026-05-16.md`, not CONFIGURATION.md/README.
- Fix: update doc
- Status: open

### README tools list omits shipped tools
- Severity: medium
- Doc location: README.md:22-26 (Tools bullet)
- Code location: src/tools/host.c (host_status/host_inventory/host_trend); src/tools/symbol_lookup.c; src/tools/tool_search.c; src/tools/worktree.c
- Claim: Exhaustive tools list in Highlights.
- Reality: Additional always-built or flag-gated tools exist: `host_status`, `host_inventory`, `host_trend` (HOST_METRICS), `symbol_lookup`, `tool_search`, `worktree_enter`, `worktree_exit`, `skill` (slash commands). RELEASE_NOTES.md lists several; README does not.
- Fix: update doc
- Status: open

### Vault CLI subcommands partially documented
- Severity: medium
- Doc location: README.md:218-233 (vault section)
- Code location: src/main.c:977-1012
- Claim: Vault usage covers `init` and `set` only.
- Reality: CLI also supports `get`, `list`, `remove`, `export`, `change-password` (documented in `cmd_vault` usage text, not README).
- Fix: update doc
- Status: open

### `SC_STRICT_SECURITY` build flag absent from README Kconfig list
- Severity: medium
- Doc location: README.md:114-130 (Feature flags)
- Code location: Kconfig:240-254; docs/CONFIGURATION.md:23; docs/SECURITY.md:155
- Claim: "Available flags" list is complete.
- Reality: `SC_STRICT_SECURITY` is a first-class Kconfig option affecting DM policy, exec mode, channel quarantine, and config-version handling. Documented in CONFIGURATION.md/SECURITY.md but not README's authoritative flag list.
- Fix: update doc
- Status: open

### Custom/named providers missing from CONFIGURATION.md
- Severity: medium
- Doc location: docs/CONFIGURATION.md (providers section)
- Code location: src/config.c:1198+; src/config.h:283-288; src/providers/factory.c
- Claim: CONFIGURATION.md is the complete config reference.
- Reality: Parser supports up to 8 `custom_providers[]` entries for non-builtin provider names; factory clones them for fallback routing. RELEASE_NOTES mentions "custom named providers"; CONFIGURATION.md has no schema table.
- Fix: update doc
- Status: open

### Skills / slash-command system has no operator docs
- Severity: medium
- Doc location: RELEASE_NOTES.md:46-47; (absent from README.md, CONFIGURATION.md)
- Code location: src/agent.c:1039-1053 (skill registry load paths)
- Claim: "skills registry + slash commands" shipped feature.
- Reality: Code loads skills from `~/.smolclaw/skills/` and `{workspace}/.claude/skills/`. No user-facing setup, format, or invocation docs in primary references.
- Fix: update doc
- Status: open

### Signal channel docs correctly marked planned
- Severity: low (positive)
- Doc location: docs/channels/signal.md:3-4
- Code location: (no `SC_ENABLE_SIGNAL` in Kconfig; no `src/channels/signal.c`)
- Claim: "Planned feature — Not yet implemented"
- Reality: Accurate; design-only. No false advertising.
- Fix: none
- Status: open (informational)

---

## Spot-checks verified accurate

- **28 `SC_ENABLE_*` Kconfig flags** — grep `^config SC_ENABLE_` in Kconfig yields 28 symbols; README list matches (plus undocumented `SC_STRICT_SECURITY`).
- **~90 exec deny patterns** — `sc_deny_patterns[]` in `src/tools/deny_patterns.h` has 90 entries; README/SECURITY.md "~90" is correct.
- **13 secret redaction patterns** — `secret_patterns[]` in `src/util/secrets.c` has 13 entries.
- **10 LLM providers** — `PROVIDER_COUNT 10` in `src/providers/factory.c` matches README provider list.
- **7 channels** — CLI, Telegram, Discord, IRC, Slack, Web, X all have `SC_ENABLE_*` gates and channel sources.
- **Core CLI commands** — `onboard`, `agent`, `gateway`, `pairing`, `vault`, `update`, `backup`, `cost`, `doctor`, `selftest`, `host-refresh`, `version` dispatch in `src/main.c` (some behind feature flags as expected).
- **Tool output 32 KB cap** — `SC_TOOL_OUTPUT_MAX (32 * 1024)` in `src/util/str.c`.
- **Per-turn limits** — 50 tool calls, 300s wall clock, 500 KB cumulative output in `src/constants_limits.h`.
- **Spawn depth 3** — `SC_MAX_SPAWN_DEPTH 3`.
- **Note tool name** — scratchpad registers as `"note"` (`src/tools/scratchpad.c:142`); README "note (scratchpad)" is correct.
- **Memory API endpoints** — `POST /api/memory/log` and `POST /api/memory/search` implemented in `src/channels/web.c`; README auth requirement matches bearer check.
- **320 KB CI budget** — `SCOPE.md:22`, `.gitea/workflows/ci.yml:69`, `scripts/check_size_budget.sh`.
- **4.6 MB musl-static** — `build-musl-minimal/smolclaw` is 4.74 MB (close to documented 4.6 MB; within rounding/release measurement variance).
- **672 KB peak RSS** — cited in RELEASE_NOTES; not re-measured this audit (accepted as release baseline).
- **PBKDF2 600K iterations** — `VAULT_PBKDF2_ITER 600000` in `src/util/vault.c`.
- **Kconfig default-off list in README** — camera, gitea, X, voice, code graph, analytics, delegate, output filter all `default n` in Kconfig; README line 116 is accurate.

---

## Coverage summary

**Well-documented**
- Build matrix (dynamic/static/musl/cross-compile) and Kconfig `menuconfig` workflow
- Security model overview (deny patterns, SSRF, sandbox, vault, prompt guard) in README + `docs/SECURITY.md`
- Multi-agent deployment, delegation, converse, session isolation (`docs/operations/session-isolation.md`)
- Config reference breadth in `docs/CONFIGURATION.md` (env overrides, vault refs, channel keys)
- X/Twitter three-mode explanation (built-in tools, MCP, channel)
- Signal channel honestly marked "planned"

**Undocumented or thin**
- Web REST surface: `/api/audit`, `/api/health`, `/api/progress`, `/api/media`, `/api/ui-config`
- Config integrity `.sha256` sidecar file operator workflow
- Skills/slash-command system
- Custom/named providers config schema
- `SC_STRICT_SECURITY` in README feature-flag inventory
- Host introspection tools (`host_*`), research helpers (`symbol_lookup`, `tool_search`), git worktree tools
- Full vault CLI subcommand reference in README

**Comment / meta-doc rot**
- Binary size figures (280 KB) linger in RELEASE_NOTES and design notes after 256 KB baseline
- `docs/CONFIGURATION-VALIDATION.md` contains outdated self-audit items
- Kconfig `SC_ENABLE_WEB` help contradicts TLS implementation