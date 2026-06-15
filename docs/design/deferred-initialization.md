# Deferred initialization spec

## Why this exists

smolclaw's headline claim is small: 280 KB binary, 672 KB peak RSS on
musl-static. Kconfig already does the heavy lifting at *compile time* —
unused features are not in the binary at all. This spec is about applying
the same discipline at *runtime*: subsystems that compile into the binary
but are not needed on a given invocation should not allocate, probe, or
spin up until something actually asks for them.

The pattern is borrowed from a cluster of Hermes Agent PRs (#28864,
#28957) that moved heavy initialization from eager-at-startup to
lazy-on-first-use. Their wins (240ms cold start, 17 MB RSS, 170-290 ms
per invocation) came from a Python-specific lever (`sys.meta_path`
import shimming), but the underlying lesson — *module-level eagerness is
hidden bloat* — translates directly to C.

If you only remember one thing from this spec: **a smolclaw run that
doesn't search memory should not pay for an FTS5 index rebuild. A run
that doesn't exec a tool should not pay for 90 compiled regexes. The
fact that those subsystems compile into the binary is a Kconfig
decision; whether they initialize is a runtime decision, and right now
we're getting the runtime decision wrong.**

## Scope

Four targets, ranked by expected RSS / startup-time win. Items 1 and 2
are real work. Items 3 and 4 are verify-and-document — the audit may
show they are already lazy, in which case the deliverable is a comment
that documents the invariant so it doesn't regress.

- **1** — Target: FTS5 memory index rebuild; Status: Eager — needs defer; Expected win: Largest
- **2** — Target: Exec deny-regex table (compiled twice); Status: Eager + duplicated — needs defer +
  dedup; Expected win: Medium
- **3** — Target: TLS context init (IRC / Web / WSS); Status: Likely lazy — verify; Expected win:
  Small / nil
- **4** — Target: Vault unlock probe; Status: Likely lazy — verify; Expected win: Small / nil

Out of scope for this spec: perf wins that *add* state or code without
reducing RSS (memoization caches, adaptive-poll state machines, regex
prefix-screen tables). Those are catalogued in the broader Hermes-PR
analysis but do not belong in a smol-themed work item.

## Smol invariants (apply to every item below)

- **Subtraction beats addition.** A defer that removes a `calloc` is
  worth more than a defer that just moves it later. Prefer designs
  where the cold path never allocates the resource at all.
- **No new globals.** A sentinel that lives in an existing struct
  (`sc_agent_t`, `sc_memory_index_t`) is fine. A new file-scope
  `static bool initialized` is fine when scoped to one translation
  unit. A new global registry or singleton is not.
- **No new abstractions.** Don't introduce a `lazy_init_t<T>`
  facility. Three sentinel checks across three subsystems is fine;
  one shared "lazy-init framework" is not.
- **Thread safety where it already exists, not where it doesn't.**
  `util/secrets.c` uses `pthread_once` because it's reached from
  logger threads. Subsystems called only from the main agent loop
  (`sc_memory_index_*`) don't need a mutex on their sentinel.
- **The cold path must stay genuinely cold.** Verify with `strace
  -e openat,mmap` or equivalent that the deferred subsystem leaves
  no fingerprint on a `--help` or `doctor` run.

---

## Item 1 — Defer FTS5 memory index rebuild

### Current behavior

`sc_memory_index_rebuild(midx, mem_dir)` is called eagerly during agent
construction at two sites:

- `src/agent.c:314` — full-agent path, inside the `SC_ENABLE_MEMORY_SEARCH`
  block immediately after `sc_memory_index_new` at `src/agent.c:306`.
  Followed by an analogous rebuild over `workspace/context/` for known
  doc extensions.
- `src/main.c:287` — standalone-mode path (similar shape).

The rebuild walks `~/.smolclaw/memory/`, opens every `.md` file, chunks
it, and feeds it into the FTS5 virtual table. For a populated memory
directory this is the largest single cost on agent startup outside of
LLM provider resolution.

### Cold paths that pay for this today

- `smolclaw --help`, `smolclaw doctor`, `smolclaw --version`
  (if any of these reach `sc_agent_new`)
- Cron-triggered turns that complete without ever calling
  `memory_search`
- One-shot tool dispatches where the model doesn't search memory
- The `spawn`/`delegate` subagent path on tasks that don't search

The majority of short interactive sessions never hit `memory_search`.

### Design

Add a sentinel to `sc_memory_index_t`:

```c
struct sc_memory_index {
    /* existing fields... */
    bool                rebuild_done;   /* sentinel: has the initial
                                         * rebuild walked the memory
                                         * dir yet? */
    char               *pending_mem_dir;    /* strdup of dir to rebuild
                                             * on first search */
    char               *pending_ctx_dir;    /* analogous for context */
};
```

Replace the eager rebuild at `src/agent.c:314` with:

```c
midx->pending_mem_dir = sc_strdup(mem_dir);
midx->pending_ctx_dir = sc_strdup(ctx_dir);
/* rebuild_done remains false */
```

At the top of `sc_memory_index_search` (and `sc_memory_index_search_prefix`)
in `src/memory_index.c:832`:

```c
if (!idx->rebuild_done) {
    if (idx->pending_mem_dir)
        sc_memory_index_rebuild_dir(idx, idx->pending_mem_dir,
                                    NULL, md_ext, 1);
    if (idx->pending_ctx_dir)
        sc_memory_index_rebuild_dir(idx, idx->pending_ctx_dir,
                                    NULL, ctx_exts, ctx_ext_count);
    free(idx->pending_mem_dir); idx->pending_mem_dir = NULL;
    free(idx->pending_ctx_dir); idx->pending_ctx_dir = NULL;
    idx->rebuild_done = true;
}
```

Incremental writes through `sc_memory_index_put_chunked` (already wired
via `memory_index_cb` at `src/agent.c:83`) must still work *before*
rebuild — they should run unconditionally and trigger the deferred
rebuild lazily by setting `rebuild_done = true` themselves (a write
implies the index is now authoritative for that file; no rebuild
needed for it).

Subtle case: the very first `memory_write` in a process that has not
yet searched will pay both costs (rebuild + write). Acceptable —
writes are user-initiated and infrequent.

### Smol checks

- No new translation unit. Edits live in `memory_index.c` + `agent.c` +
  `main.c`.
- Adds two `char *` and one `bool` to `sc_memory_index_t`. The freed
  `pending_*` strings net to zero RSS after first search.
- A cold run that never searches now allocates the FTS5 schema (cheap;
  empty virtual table) but does not walk the filesystem.

### Validation

Measure with `getrusage(RUSAGE_SELF)` peak RSS on `smolclaw doctor`
before and after, on a workspace with a populated `memory/` dir
(use the existing test fixtures or seed with 100+ markdown files).
Document the delta in the commit message. Target: visible RSS drop
on the cold path; no regression on the hot path (warm-cache search
latency).

Tests: existing `tests/test_memory_search.c` (or equivalent) must
pass unchanged — the first search inside any test still triggers
the rebuild. Add one test that constructs the agent, asserts the
FTS5 table is empty (or near-empty), then calls `memory_search` and
asserts the rebuild happened.

---

## Item 2 — Defer (and dedup) exec deny-regex compilation

### Current behavior

`sc_deny_list_init` at `src/tools/exec_common.c:49` compiles the full
deny-pattern table (~90 POSIX extended regexes) into a freshly
`calloc`'d `regex_t[]`. It is called from two tool constructors:

- `src/tools/shell.c:339`
- `src/tools/background.c:226`

This is doubly wasteful:

1. **Eager.** Both calls happen at tool *registration* during agent
   construction, before the model has decided whether it will use a
   shell tool.
2. **Duplicated.** Each tool keeps its own copy of the compiled table.
   ~90 `regex_t` structures × 2 tools.

### Design

Two stages — they can ship as one PR or two.

**2a. Share one compiled table across both tools.**

Replace the per-tool `sc_deny_list_t` member with a borrowed pointer to
a process-global singleton:

```c
/* in exec_common.c */
static sc_deny_list_t g_deny;
static pthread_once_t g_deny_once = PTHREAD_ONCE_INIT;

static void deny_do_init(void) { sc_deny_list_init(&g_deny); }

const sc_deny_list_t *sc_deny_list_get(void)
{
    pthread_once(&g_deny_once, deny_do_init);
    return &g_deny;
}
```

`shell.c` and `background.c` switch from owning a `sc_deny_list_t deny`
to holding a `const sc_deny_list_t *deny` set at construction time —
*but* the singleton is not initialized until the first
`sc_deny_list_get()` call.

**2b. Defer the first `sc_deny_list_get()` call to first exec attempt.**

Hold `NULL` until first use. The matching site
(`sc_exec_guard_command` at `src/tools/exec_common.c:187`) already runs
on every shell command; have it call `sc_deny_list_get()` itself and
ignore the pointer stored on the tool struct.

After 2b, the tool constructor stores nothing related to the deny
list. A run that registers shell/background tools but never invokes
them never compiles the regex table.

### Smol checks

- Net change: ~90 `regex_t` structs × 1 (was × 2). Concrete RSS
  win, not just a perf shuffle.
- `pthread_once` is already in `util/secrets.c`; pattern is consistent.
- The signature of `sc_deny_list_matches` changes from
  `(const sc_deny_list_t *, ...)` to `(const char *)` (the pointer
  becomes implicit). Callers in shell/background simplify.
- The `sc_deny_list_init`/`sc_deny_list_free` pair becomes file-scope
  static after 2a; remove from `exec_common.h`.

### Validation

- Existing exec / deny-pattern tests must pass without modification —
  the first call into `sc_exec_guard_command` from any test triggers
  the lazy init, and `regexec` semantics are unchanged.
- Add a test that constructs `shell` + `background` tools, asserts
  `g_deny.patterns == NULL` (i.e. lazy init has not fired), then
  invokes a command and asserts it has.
- RSS measurement on a run that registers tools but exits before any
  shell command (e.g. `doctor`).

---

## Item 3 — Verify TLS context init is already lazy

### Current state

`SSL_CTX_new` is called at three sites, all already inside channel
start paths:

- `src/channels/irc.c:476` — inside the IRC connect path
- `src/channels/web.c:138` — inside the web-channel start path
- `src/util/websocket.c:186` — inside the WSS client connect path

None of these are called from `sc_main` or `sc_agent_new` directly.
Channels start only when their Kconfig flag is on *and* the config
enables them.

### Deliverable

Audit only. Confirm with `strace -e openat,connect smolclaw doctor 2>&1
| grep -i 'ssl\|crypto\|cert'` (or equivalent) that a doctor run on a
config with all channels disabled performs zero TLS-library
initialization.

If the audit confirms laziness, the deliverable is a one-line comment
above each `SSL_CTX_new` call noting "lazy: only reached from channel
start, not agent init — keep this property; see
docs/design/deferred-initialization.md item 3."

If the audit reveals OpenSSL self-initializes globals via constructor
attributes (it does in some build configs), document the finding but
do not chase a fix unless RSS measurably benefits — OpenSSL global
init is bounded and one-shot.

### Smol check

The point of including this as a spec item is to *prevent regression*.
Future work that adds a new TLS-using channel must keep the
SSL_CTX_new call inside the channel start path, never in agent init.

---

## Item 4 — Verify vault probe is already lazy

### Current state

`sc_vault_unlock` is called only on explicit paths:

- `src/main.c:1000` via `vault_load_and_unlock(vault_path)` — only
  when `vault_path` was resolved from config or CLI
- `src/main.c:1273`, `src/main.c:1557` — vault management CLI subcommands
- `src/config.c:338` — only when a `vault://` ref is dereferenced
  during config parse

A run with no `vault://` refs in config and no vault CLI subcommand
performs no vault open, no PBKDF2, no AES init.

### Deliverable

Audit only, same shape as item 3. Confirm with a `strace` run against a
config containing no `vault://` refs that vault code is not entered.
Add a comment at the top of `sc_vault_unlock` (or near the `vault_path`
resolution in `src/main.c`) documenting the invariant.

If the audit reveals `sc_vault_init` being called unconditionally
somewhere in startup (it shouldn't be — grep confirms only line
`src/main.c:810` calls it, inside the `vault init` subcommand), file
a follow-up.

### Smol check

Same as item 3 — this is a regression-prevention item, not a refactor.
Future config-parsing changes must keep vault dereference behind the
`vault://` prefix check, not eagerly probe.

---

## Acceptance criteria for the spec as a whole

A reviewer should be able to confirm, after this work lands:

1. `smolclaw doctor` on a workspace with a populated `memory/` dir
   shows measurably lower peak RSS than before (item 1).
2. A run that registers shell+background tools but executes no
   command shows the deny-regex table is uninitialized (item 2,
   inspectable via a test, or via RSS delta).
3. The codebase has zero `SSL_CTX_new` or `sc_vault_unlock` calls
   reachable from `sc_main` or `sc_agent_new` without an explicit
   user-config gate (items 3 + 4).
4. No new global registry, no new "lazy init framework", no new
   subsystem of any kind. Net code delta should be negative or
   near-zero — items 1 and 2 should *remove* eager work, not add
   scaffolding around it.

The fourth criterion is the smol one. If a draft of this work grows a
new abstraction layer, stop and reconsider — the spec is to make the
binary do less, not to make the codebase do more.

## Out of scope (explicit non-goals)

- Memoization of `sc_model_strip_prefix` or any provider-detection
  helper. Caches add RSS; reject unless a profiler demonstrates the
  uncached path is a real bottleneck.
- Substring-prefix screens in `util/secrets.c`. Real perf win in the
  Hermes PR, but adds a parallel lookup table. Not smol-aligned.
- Adaptive-backoff polling in `tools/background.c`. Adds a small
  state machine. Defer to a separate spec if pursued.
- A "lazy init" framework or macro. The three sentinel patterns in
  this spec are intentionally hand-written and divergent — that is
  the smol design choice.

## References

- Hermes PR #28864 — defer expensive Python import via `sys.meta_path`
- Hermes PR #28957 — defer compression-feasibility check via sentinel
- Hermes PRs #28866, #29006 — perf wins explicitly excluded from this
  spec for being non-smol (memoization / state machine / lookup tables)
