# Signal 3.1 — Acceptance Gate Runbook

> Manual smoke test for the Signal channel (task 3.1) against a real `signal-cli`
> daemon. Everything except this live test is done: pure logic is unit-tested
> (`tests/test_signal.c`), the channel is wired into the manager, config + env
> overrides exist, KC-1 is satisfied. This runbook is the remaining 🟠 human
> acceptance gate.
>
> Code: `src/channels/signal.c`, `src/channels/signal_internal.h`.
> Design: [docs/design/signal-channel.md](../design/signal-channel.md).
> User guide: [docs/channels/signal.md](signal.md).

## 0. What this gate is

The single open item is a real `signal-cli` smoke test — and specifically
**reconciling the `receive` JSON-RPC shape** the polling loop assumes against
what a real daemon emits. That is the one thing most likely to need a code tweak.

## 1. The exact wire protocol the code expects

This is the contrast you are validating. From `src/channels/signal.c`:

**Endpoint:** HTTP POST to `{base_url}/api/v1/rpc`, default
`http://127.0.0.1:7583/api/v1/rpc`.

**receive (the poll, `signal.c:328-333`)** — sent every ~2s:

```json
{"jsonrpc":"2.0","method":"receive","params":{"account":"+15551234567","timeout":5},"id":"1"}
```

Code expects a response with a **`result` array** (`process_receive_result`,
`signal.c:304-316`). Each element is either the envelope directly, or
`{"envelope": {...}}` — both are tolerated. The envelope must contain
(`sc_signal_envelope_extract`, `signal.c:131-176`):

- `dataMessage.message` → non-empty string (else ignored: sync/receipt/typing/
  attachment-only are dropped)
- `source` and/or `sourceUuid` → sender (UUID preferred, normalized to
  `uuid:<uuid>`)
- optional `dataMessage.groupInfo.groupId` → makes it a group message
  (`chat_id` = `signal:group:<groupId>`)

**send (`signal.c:392-406`):**

```json
{"jsonrpc":"2.0","method":"send","params":{"account":"+1555...","message":"hi","recipient":["+1555dest"]},"id":"1"}
```

Groups use `"groupId":"<id>"` instead of `recipient`.

> ⚠️ **Reconciliation risk:** signal-cli's JSON-RPC daemon only returns queued
> messages from the `receive` *method* when started with `--receive-mode manual`.
> In the default `on-start` mode it **pushes notifications** instead, which this
> polling loop will never see. The setup below uses `--receive-mode manual` —
> keep it. The other likely deltas are the `result` wrapper shape and `groupId`
> encoding; verify both with raw curl in step 5 before trusting the loop.

## 2. Prerequisites

- A **dedicated test phone number** registered with Signal (do **not** link your
  personal account — message loops + session conflicts). Registration is done via
  `signal-cli register` / `verify` or the container's register endpoint.
- `signal-cli` (native) **or** Docker for `bbernhard/signal-cli-rest-api`.
- A second Signal account (your phone) to message the bot from.

## 3. Build with Signal enabled

```bash
cd /home/magnus/devel/smolclaw
cp configs/defconfig .config
cmake -B build -DCMAKE_BUILD_TYPE=Release -DSC_ENABLE_SIGNAL=ON
cmake --build build
# sanity: the gated test compiled
ctest --test-dir build -R test_signal --output-on-failure
```

(`ctest` may need the sandbox disabled — it `mkdtemp`s under `/tmp`.)

## 4. Run the daemon (port 7583, manual receive)

**Native:**

```bash
signal-cli -a +15551234567 daemon \
    --http 127.0.0.1:7583 \
    --receive-mode manual \
    --no-receive-stdout
```

**Container** (`bbernhard/signal-cli-rest-api`, JSON-RPC mode at `/api/v1/rpc`):

```bash
docker run -d --name signal-api -p 7583:8080 \
  -e MODE=json-rpc \
  -v $HOME/.local/share/signal-cli:/home/.local/share/signal-cli \
  bbernhard/signal-cli-rest-api
```

(Container listens on 8080 internally; `-p 7583:8080` maps it to the port the
config expects. Account data must already be registered in that volume.)

## 5. Verify the wire shapes with raw curl FIRST (the actual gate work)

Before running smolclaw, confirm the daemon speaks what the code expects. From
your phone, send the bot a DM, then:

```bash
# RECEIVE — inspect the real shape
curl -s http://127.0.0.1:7583/api/v1/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"receive","params":{"account":"+15551234567","timeout":5},"id":"1"}' | jq .
```

**Check:** Is there a top-level `result` array? Does each element have
`envelope.dataMessage.message`, `envelope.source`/`sourceUuid`? For a group
message, `envelope.dataMessage.groupInfo.groupId`? If the shape differs (e.g.
messages arrive as JSON-RPC *notifications*, `result` is wrapped differently, or
`groupId` is encoded unexpectedly), **that is the reconciliation** — note the
real shape; the fix is localized to `sc_signal_envelope_extract` /
`process_receive_result`.

```bash
# SEND — confirm a DM lands on your phone
curl -s http://127.0.0.1:7583/api/v1/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"send","params":{"account":"+15551234567","message":"hello from acceptance test","recipient":["+1555YOURPHONE"]},"id":"1"}' | jq .
```

## 6. Run smolclaw end-to-end

Config (in your workspace `config.json`, or `--config <path>`):

```json
{
  "channels": {
    "signal": {
      "enabled": true,
      "account": "+15551234567",
      "http_host": "127.0.0.1",
      "http_port": 7583,
      "dm_policy": "pairing",
      "allow_from": [],
      "group_trigger": "smolclaw"
    }
  }
}
```

(Full base-URL override: set `http_url` to win over host/port. Every field has an
env override, e.g. `SMOLCLAW_CHANNELS_SIGNAL_ACCOUNT`,
`SMOLCLAW_CHANNELS_SIGNAL_HTTP_URL`.)

```bash
./build/smolclaw gateway --config /path/to/config.json
```

Watch the log for `Polling thread started (account +1555...)`. (The gateway
refuses to start if another gateway is already running for that workspace —
`main.c:1517`.)

## 7. Pass criteria (the acceptance checklist)

1. **Receive shape matches** (step 5) — or you have reconciled it and re-tested.
2. **DM round-trip:** message the bot → with `dm_policy:"pairing"` an unknown
   sender gets a pairing challenge. Approve it:
   ```bash
   ./build/smolclaw pairing list signal
   ./build/smolclaw pairing approve signal <CODE>
   ```
   Then message again → the agent replies in Signal.
3. **Group:** add the bot to a group, send a message containing `smolclaw` (the
   `group_trigger`) → agent replies to the group; a message *without* the trigger
   is ignored.
4. **Identifier normalization:** confirm `allow_from` works with both `+phone`
   and `uuid:...` forms (UUID preferred).
5. **Resilience:** stop the daemon mid-run → log shows `receive failed, retrying
   in Ns` with backoff 5→300s; restart daemon → polling resumes, no crash.
6. **Clean shutdown:** SIGTERM the gateway → `Polling thread stopped`, no hang
   (thread is `pthread_join`ed in `signal_stop`).

## 8. If you find a mismatch

The whole receive path is isolated in two functions, so a fix is small and
unit-testable:

- `sc_signal_envelope_extract` (`signal.c:131`) — envelope field shape
- `process_receive_result` (`signal.c:304`) — the `result`/wrapper shape

Add a captured real envelope as a fixture to `tests/test_signal.c`, adjust the
extractor, re-run `ctest -R test_signal`.

## 9. Post-acceptance bookkeeping

Once the smoke test passes, flip the 🟠 gate to accepted:

- `docs/design/autonomy-readiness.md` row 3.1
- `docs/design/phases/phase-3-optional-surface-area.md` status
- Memory files (`smol-roadmap-execution.md`, checkpoint)
