# Scope

smolclaw is a **smol, modular AI agent runtime** in C11. The minimal
embedded build (single static binary, no runtime deps, runs on a Pi Zero
2 W) is the design constraint, not a side target.

## Goals

- Single-binary agent: LLM loop, tools, memory, channels — Kconfig-gated.
- Embedded-first: musl-static, aarch64/armv7, size + RSS budgets enforced.
- Safe by default: sandbox, deny patterns, secrets redaction, isolation.

## Non-goals

- Fleet orchestration, deployment, dashboards (→ smolswarm).
- Chat relay / observation UI (→ smolchat).
- Features that cannot be compiled out of the minimal build.

## Rules

- New features land behind Kconfig `default n`.
- CI fails if minimal-static > 5 MB or minimal-dynamic > 320 KB.
