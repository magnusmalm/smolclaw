---
name: companion-triage
description: Triage a quick-captured thought — categorize, tag, store, optional research
when-to-use: when the companion app sends a spur-of-the-moment thought for triage
arguments: "<raw thought text>"
allowed-tools: memory_read, memory_write, memory_search, note, web_search
user-invocable: true
version: "1.0.0"
---

Triage this captured thought. The operator text is:

$ARGUMENTS

Follow these steps in order:

1. **Classify** — pick a short category (task, idea, reminder, question, link, other) and 1–3 tags.
2. **Store** — call `memory_write` with the thought, category, and tags in structured form.
3. **Research (optional)** — you may call `web_search` **at most once** if a quick fact-check or context would materially improve the triage. Skip if unnecessary.
4. **Reply** — respond with a concise triage summary: category, tags, what was stored, and any research takeaway (or "no search needed").

Keep the reply under ~8 sentences. Do not call exec, git, spawn, or cron tools.