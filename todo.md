# smolclaw TODO

## Audit low-severity fixes

Remaining items from the deep code audit (AUDIT_REPORT.md). All low severity.

### Won't fix

- **#23** `agent_turn.c` clones all messages at turn start — doubles memory (`agent_turn.c:544-552`). Borrowing requires invasive ownership tracking for modest savings. Current approach is correct, just not memory-optimal. Not worth the complexity risk.
- **#28** `sc_validate_path` 8KB stack from two PATH_MAX buffers (`str.c:115-116`). PATH_MAX is 4096 on Linux. 8KB stack is well within default thread stack sizes (1-8MB). Heap-allocating adds malloc/free overhead for no real benefit.
- **#32** Cost tracker `fsync` on every turn (`cost.c:132-177`). Ensures cost data survives crashes. The I/O cost is negligible on modern SSDs and happens once per turn (not per tool call). Correctness over performance here.
- **#34** CDATA wrap byte-by-byte append around `]]>` (`str.c:383-386`). No length-bounded `sc_strbuf_append` exists; adding one or using malloc is worse than the loop. Trivial cost relative to I/O.

## Port conflict logging

When the web channel fails to bind, the error could be more helpful.
Log what's holding the port (equivalent of `ss -tlnp | grep :PORT`)
to help diagnose conflicts without manual investigation.

Note: auto-port (`"auto_port": true`) is already implemented — tries
configured port, then increments up to +10.

## ~~X (Twitter) channel~~ ✓

Done. See `src/channels/x.c`, `tests/test_x.c`.

## X tools: `note_tweet` support

Add `note_tweet` to `tweet.fields` in `x_get_thread` and `x_search` API
requests so long tweets (up to 25k chars, Premium feature) return the
full untruncated text instead of the 280-char truncation.

Currently only `x_get_tweet` requests `note_tweet`. The `format_tweet()`
helper already handles `note_tweet.text` — just needs the field requested
in the other endpoints' `tweet.fields` params.
