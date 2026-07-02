---
name: companion-describe
description: Describe a companion snap image with vision and store the summary
when-to-use: when a snap path under companion/inbox/ needs vision description
arguments: "<workspace-relative image path>"
allowed-tools: camera, memory_read
user-invocable: true
disable-model-invocation: true
version: "1.1.0"
---

Describe this companion snap:

$ARGUMENTS

Steps:
1. Run `camera describe` on the image path above (workspace-relative).
   Storage is automatic: for companion/inbox/ images the camera tool itself
   appends the description to the daily notes (the tool result confirms it).
2. Reply with the vision description only (2–4 sentences).