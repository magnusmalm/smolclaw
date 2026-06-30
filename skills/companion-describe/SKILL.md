---
name: companion-describe
description: Describe a companion snap image with vision and store the summary
when-to-use: when a snap path under companion/inbox/ needs vision description
arguments: "<workspace-relative image path>"
allowed-tools: camera, memory_write, memory_read
user-invocable: true
disable-model-invocation: true
version: "1.0.0"
---

Describe and remember this companion snap:

$ARGUMENTS

Steps:
1. Run `camera describe` on the image path above (workspace-relative).
2. `memory_write` a short entry with the description and path.
3. Reply with the vision description only (2–4 sentences).