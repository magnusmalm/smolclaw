# Design: Mixture of Agents (MoA-lite)

**Status**: Design — Ready for implementation (Phase 2.13)  
**Author**: Planning session (2026-06-27)  
**Last Updated**: 2026-06-27  
**Related**:
- [Hermes MoA user guide](https://hermes-agent.nousresearch.com/docs/user-guide/features/mixture-of-agents)
- [`docs/design/phases/phase-2-operator-provider-ux.md`](phases/phase-2-operator-provider-ux.md) — task **2.13**
- [`docs/design/master-plan.md`](master-plan.md) — §4.3 Hermes gap tier map
- `src/providers/factory.c`, `src/agent_turn.c` (`call_llm_with_fallback`), `src/config.{c,h}`
- `src/slash.c` (`/model`), `src/agent.c` (model aliases)
- Phase 5 — OpenRouter `/compare` A/B explicitly **rejected**; MoA is **not** compare

---

## 1. Summary

**Mixture of Agents (MoA)** is a virtual provider pattern: on each main LLM call in the
agent turn loop, **reference models** (no tools, trimmed context) run first; their outputs
are injected as private guidance on the **tail** of the latest user message; an
**aggregator** model then runs with the full system prompt, history, and tool schema and
acts as the real model for that iteration (including tool calls).

Hermes implements MoA as `provider: moa` with named YAML presets and full UI surfaces.
smolclaw ships a **MoA-lite** variant: config-json presets, Kconfig-gated, no dashboard,
2–3 reference cap, explicit **local-only** policy for air-gapped presets.

**Core constraint:** Honor the smol contract — default **off**, no new runtime deps, reuse
existing `sc_provider_t` + factory routing (Ollama, vLLM, Anthropic, OpenRouter, custom
providers). MoA multiplies API cost per iteration; it is opt-in for hard tasks, not the
default path.

---

## 2. Motivation

smolclaw already has:

- **Sequential fallback** on primary *failure* (`call_llm_with_fallback` in `agent_turn.c`)
- **delegate / converse** — multi-*agent* HTTP, not multi-*model* synthesis in one loop
- **Model aliases** and `/model` — per-session model switch, single provider call per iteration

Hermes benchmarks show MoA can lift quality on hard tasks when a second model perspective
feeds a stronger aggregator — distinct from fallback (reliability) and from Phase 5’s
rejected OpenRouter `/compare` (user-facing A/B).

smolclaw users on **edge + cloud** mixes (Ollama locally, Claude/Grok in cloud) benefit from
presets such as “local references, cloud aggregator” or “fully local council” without
bolting on Python or a separate orchestration layer.

---

## 3. Goals

- Virtual **`moa`** provider selectable like any other (`/model`, config, in-prompt alias)
- Named **presets** in `config.json` with explicit `provider` + `model` pairs per slot
- **Reference fan-out** per agent iteration (parallel HTTP via existing curl stack / `sc_task_t`)
- **Trimmed reference context** — user/assistant text only; no system prompt, no tool transcript
- **Aggregator** receives full agent context + injected reference block on user-message tail
- **Tool loop unchanged** — aggregator’s tool calls execute normally; next iteration re-runs MoA
- **`local_only`** preset flag — reject cloud providers for references and aggregator
- **Graceful degradation** — reference failure text included; turn continues
- **Cost + audit** — sum reference + aggregator token usage per iteration
- **Tests** — mock HTTP; no live API keys required for CI

## 4. Non-goals (MVP)

- Hermes Desktop/Dashboard preset editors
- Recursive MoA (aggregator preset pointing at another MoA preset)
- Reference models with tool schemas
- Unlimited reference count (cap at **3**)
- `/moa` one-shot sugar (optional follow-up; alias + `/model` sufficient for MVP)
- Streaming from reference models (aggregator streaming only, as today)
- Prompt-cache optimization beyond “inject at tail” (inherit normal prefix stability)
- Replacing fallback chain, delegate, or converse

---

## 5. Hermes behavior (reference)

Per [Hermes MoA docs](https://hermes-agent.nousresearch.com/docs/user-guide/features/mixture-of-agents):

1. Resolve preset by name (`moa` provider).
2. Run reference models **without tools** on trimmed conversation.
3. Append reference outputs as private context for the aggregator.
4. Call aggregator with normal tool schema; its response is the iteration result.
5. On tool execution and next iteration, repeat from step 2.
6. `enabled: false` on a preset → aggregator alone.
7. Credential failure on one reference → include error in context; continue.

smolclaw MoA-lite follows the same loop semantics with JSON config instead of YAML.

---

## 6. Architecture

### 6.1 Virtual provider

Add `sc_provider_moa_*` in `src/providers/moa.c` implementing `sc_provider_t`:

```text
moa_chat(provider, msgs, tools, preset_name, options) →
  if !preset.enabled → aggregator_chat only
  ref_msgs = sc_msgs_reference_view(msgs)     // strip system + tool roles
  refs[] = parallel_chat(ref_providers, ref_msgs, tools=NULL)
  agg_msgs = sc_msgs_inject_moa_refs(msgs, refs)
  return aggregator->chat(agg_msgs, tools, ...)
```

Factory: `sc_provider_create_for_model(cfg, "moa/review")` or config
`"provider": "moa", "model": "review"` resolves preset `review`.

Preset names are alphanumeric + `_` / `-`; max **8** presets (match `custom_providers` scale).

### 6.2 Hook point

**Primary:** wrap inside `call_llm_with_fallback` when `provider->name` is `moa` (or
`provider->impl == SC_PROVIDER_MOA`), before retry/fallback logic.

MoA is **not** a fallback — it is the selected primary path. Fallback chain still applies
if the **aggregator** fails (same as any primary provider failure).

### 6.3 Parallel reference calls

Use **pthread** per reference (same pattern as parallel read-only tools in `agent_turn.c`)
or `sc_task_spawn` + join. Cap **3** references. Each reference uses a **cloned** provider
handle (same as summarization thread pattern in `agent_session.c`).

References use `max_tokens` / `temperature` from preset (`reference_max_tokens` default
1024, `reference_temperature` default 0.6).

### 6.4 Message trimming (`sc_msgs_reference_view`)

Build a ephemeral message array for references:

| Include | Exclude |
|---------|---------|
| `user` content | `system` |
| `assistant` text content (no tool_calls JSON in reference view) | `tool` / `tool_result` rows |
| | Hermes system prompt (smolclaw: first system message) |

Keep message order. Do not mutate the live session array.

### 6.5 Reference injection (`sc_msgs_inject_moa_refs`)

Append to the **last user message** in a copy used only for the aggregator call:

```text

[MoA reference: ollama/qwen2.5:7b]
<reference text or error>

[MoA reference: openrouter/deepseek/deepseek-chat]
<reference text or error>
```

If the last message is not `user` (e.g. after tool results), prepend injection as a
synthetic user message **only for the aggregator request** — do not persist to session
JSONL (in-memory copy only).

### 6.6 Local / cloud mixing

Each slot is an independent `{provider, model}` resolved via existing factory:

| Preset | References | Aggregator | Egress |
|--------|------------|------------|--------|
| `hybrid` | `ollama/*`, `openrouter/*` | `anthropic/*` | Cloud sees refs + tail |
| `airgap` | `ollama/*`, `vllm/*` | `ollama/*` | None (when `local_only: true`) |
| `cloud` | `openai/*`, `openrouter/*` | `anthropic/*` | Full cloud |

**`local_only: true`** — at preset load, validate every slot:

- Allowed: `ollama`, `vllm`, `custom` where `api_base` is loopback or RFC1918 (same SSRF
  rules as `web_fetch` policy — document exact CIDR check in implementation).
- Reject: all other built-in providers.

Log warning once if a preset mixes `local_only` with a disallowed provider.

---

## 7. Configuration

Extend `config.json` (and `src/config.c` parser):

```json
{
  "provider": "moa",
  "model": "default",
  "moa": {
    "default_preset": "default",
    "presets": {
      "default": {
        "enabled": true,
        "local_only": false,
        "reference_models": [
          {"provider": "ollama", "model": "qwen2.5:7b"},
          {"provider": "openrouter", "model": "deepseek/deepseek-chat"}
        ],
        "aggregator": {"provider": "anthropic", "model": "claude-sonnet-4-20250514"},
        "reference_temperature": 0.6,
        "aggregator_temperature": 0.4,
        "reference_max_tokens": 1024,
        "aggregator_max_tokens": 4096
      },
      "airgap": {
        "enabled": true,
        "local_only": true,
        "reference_models": [
          {"provider": "ollama", "model": "llama3"},
          {"provider": "ollama", "model": "qwen2.5:7b"}
        ],
        "aggregator": {"provider": "ollama", "model": "qwen2.5:7b"}
      }
    }
  }
}
```

**Model alias integration:** Register each preset as alias target, e.g. `moa:default` →
provider `moa`, model `default` (extends `agent.c` alias table at init).

**Slash / CLI:** `/model airgap` when `provider` is `moa`, or `/model moa:airgap` via alias.
Optional later: `/moa <prompt>` one-shot (Hermes parity) — not MVP.

Document in `docs/CONFIGURATION.md` § MoA presets.

---

## 8. Kconfig & binary

| Flag | Default | Notes |
|------|---------|-------|
| `SC_ENABLE_MOA` | **n** | `depends on` at least one HTTP provider path |

**LOC budget:** 350–550 C (provider + config + message helpers).  
**Binary Δ:** ~10–20 KB stripped (estimate; measure in 2.13 slice).  
**KC-1:** Add `SC_ENABLE_MOA` to `FEATURE_SYMS` / `scripts/kconfig_genconfig.py`.

---

## 9. Files (planned)

| File | Change |
|------|--------|
| `src/providers/moa.c`, `src/providers/moa.h` | **New** — virtual provider |
| `src/providers/factory.c` | Route `moa` + `moa/<preset>` |
| `src/config.c`, `src/config.h` | Parse `moa.presets` |
| `src/agent_turn.c` | Detect MoA provider; optional thin wrapper |
| `src/agent.c` | Register preset aliases |
| `src/slash.c` | Help text for MoA presets |
| `tests/test_moa.c` | **New** — mock HTTP fan-out + injection |
| `CMakeLists.txt`, `Kconfig` | Gate + test target |
| `docs/CONFIGURATION.md`, `README.md` | Operator docs |

---

## 10. Testing & acceptance

**Unit / mock tests (`tests/test_moa.c`):**

- [ ] `sc_msgs_reference_view` excludes system and tool messages
- [ ] Injection appends to last user turn without mutating source array
- [ ] Two mock references + one aggregator — aggregator request contains both ref blocks
- [ ] Reference HTTP failure → error string in injection; aggregator still called
- [ ] `enabled: false` → single aggregator call, zero reference calls
- [ ] `local_only: true` rejects `anthropic` slot at config load
- [ ] Recursive preset blocked (aggregator provider `moa`)

**Integration (manual / gated-ext):**

- [ ] Preset with `ollama` reference + cloud aggregator completes one tool iteration
- [ ] `airgap` preset runs with no outbound non-RFC1918 URLs (strace spot-check)

**Phase gates:** KC-2 clean; `ctest` green; size budget pass; no regression in
`test_providers` / fallback tests.

---

## 11. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Cost explosion (N+1 calls × iterations) | Default off; document cost multiplier; cap references at 3 |
| Context overflow from injection | `reference_max_tokens`; compact ref summaries in v2 if needed |
| Privacy leak via cloud references | `local_only` preset + CONFIGURATION warning |
| Parallel curl memory | Cap references; free responses before aggregator call |
| Confusion with fallback | Docs: MoA = quality ensemble; fallback = failure recovery |
| Anthropic vs OpenAI message shapes | Reuse per-provider clones from factory (no new wire format) |

---

## 12. Relation to other features

| Feature | Relationship |
|---------|----------------|
| Fallback chain | Orthogonal — aggregator failure still triggers fallbacks |
| Provider health | References skip unhealthy providers; aggregator respects health |
| delegate / converse | Different — remote agents, not in-loop multi-model |
| Phase 5 `/compare` reject | MoA is not user A/B; optional quality preset |
| MCP cookbook (2.12) | Alternative zero-binary pattern: external fan-out script |
| xAI OAuth (2.1) | Aggregator/reference may use `xai-oauth` provider when enabled |

---

## 13. Suggested implementation order

1. Config schema + preset validation (`local_only`, caps)
2. `sc_msgs_reference_view` + `sc_msgs_inject_moa_refs`
3. `sc_provider_moa` with sequential references (get tests green)
4. Parallel reference fan-out
5. Factory + alias + `/model` help
6. CONFIGURATION.md + README section

**PR title:** `feat: mixture-of-agents virtual provider (MoA-lite)`

---

**Next:** Implement as [Phase 2 task 2.13](phases/phase-2-operator-provider-ux.md#213-mixture-of-agents-moa-lite).