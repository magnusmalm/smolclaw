# Scope

smolclaw is a **smol, modular AI agent runtime** in C11. The minimal
embedded build (single static binary, no runtime deps, runs on a Pi Zero
2 W) is the design constraint, not a side target.

## Goals

- Single-binary agent: LLM loop, tools, memory, channels — Kconfig-gated.
- Embedded-first: musl-static, aarch64/armv7; **size budgets** (see Rules) and
  low RSS as a design goal (no published numeric RSS budget).
- Safe by default: sandbox, deny patterns, secrets redaction, isolation.

## Non-goals

- Fleet orchestration, deployment, dashboards (belong in a separate orchestration layer).
- Chat relay / observation UI (belong in a separate relay/UI).
- Features that cannot be compiled out of the minimal build.

## Rules

- New features land behind Kconfig `default n`.
- **Size budgets** (stripped binaries; `scripts/check_size_budget.sh`):
  - minimal **dynamic** ≤ 1 MB (1024 KB) — **CI-enforced** on every push
  - minimal **static** (musl) ≤ 5 MB — design budget; run the script on
    musl release builds (not yet a CI job)
