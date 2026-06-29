# Signal Channel

> **Status**: Implemented (MVP) — text DMs + groups, polling receive.  
> Build with `-DSC_ENABLE_SIGNAL=ON` (Kconfig `SC_ENABLE_SIGNAL`, **default off**).
>
> The mock-tested code is complete (`tests/test_signal.c`). A manual smoke test
> against a real `signal-cli` daemon with a test number is still recommended
> before production use.

The Signal channel lets you interact with smolclaw directly inside Signal, using either direct messages or group chats.

smolclaw does **not** speak the Signal protocol natively. It connects to an external `signal-cli` daemon (or the popular `bbernhard/signal-cli-rest-api` Docker container) over HTTP JSON-RPC.

---

## Why Signal?

Signal offers strong end-to-end encryption and privacy properties, making it an attractive channel for sensitive or long-running agent interactions.

---

## Architecture

- You run and maintain the `signal-cli` daemon yourself (or via Docker).
- smolclaw communicates with it over HTTP JSON-RPC.
- Full support for the existing security model:
  - `dm_policy` (`pairing`, `allowlist`, `open`)
  - `allow_from` lists (supporting both phone numbers and `uuid:...` entries)
  - Automatic pairing challenge flow
  - Participation in strict security mode

---

## Recommended Setup

### 1. Use a Dedicated Bot Number

It is **strongly recommended** to register a separate phone number for the bot rather than linking your personal Signal account. This avoids session conflicts, message loops, and privacy issues.

### 2. Run the Daemon

**Native mode (most common):**

```bash
signal-cli -a +15551234567 daemon \
    --http 127.0.0.1:7583 \
    --receive-mode manual \
    --no-receive-stdout
```

**Container mode:**

Use the `bbernhard/signal-cli-rest-api` image with `MODE=json-rpc`.

### 3. Configure smolclaw

Example configuration:

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

The daemon is reached at `http://<http_host>:<http_port>/api/v1/rpc`. To point
at a non-default endpoint (e.g. a container on another host), set `http_url`
to the full base URL — it overrides `http_host`/`http_port`. A `proxy` field
and per-channel `tools` allowlist are also supported. Every field has an
environment override (`SMOLCLAW_CHANNELS_SIGNAL_ACCOUNT`,
`SMOLCLAW_CHANNELS_SIGNAL_HTTP_URL`, …).

---

## Pairing New Contacts

When `dm_policy` is set to `"pairing"`, unknown numbers will receive a message like:

> Access requires pairing. Your code: ABCDEF123456  
> Ask the owner to run: `smolclaw pairing approve signal ABCDEF123456`

You can manage pairings with the existing command:

```bash
smolclaw pairing list signal
smolclaw pairing approve signal ABCDEF123456
smolclaw pairing revoke signal "+15557654321"
smolclaw pairing revoke signal "uuid:123e4567-e89b-12d3-a456-426614174000"
```

UUID-based identifiers are preferred when available.

---

## Groups

Basic group support is implemented. Use the `group_trigger` setting to reduce noise in busy groups — only messages containing the trigger substring are processed by the agent (when unset, all group messages are processed). Group replies are routed back to the originating group.

---

## Current Limitations (MVP Scope)

The Signal channel MVP has these limitations:

- Text messages only (no attachments or voice notes)
- Polling-based receive (real-time SSE streaming is a planned follow-up)
- No reactions, polls, or read receipts
- Single account per channel instance

Media support, typing indicators, and richer features are planned for later phases.

---

## Security Notes

- You are responsible for running and securing the `signal-cli` daemon.
- Back up the Signal account data (`~/.local/share/signal-cli` or your Docker volume) regularly. Loss of keys means loss of the identity.
- Keep `signal-cli` reasonably up to date, as Signal server changes can affect older versions.
- Prefer `dm_policy: "pairing"` for most deployments.

See [Security](../SECURITY.md) for more details.

---

## Related Documentation

- [Security](../SECURITY.md)

---

**Note**: The Signal channel is implemented (MVP — text DMs + groups, polling
receive) behind `SC_ENABLE_SIGNAL` (**default off**). A live `signal-cli` smoke
test is the remaining acceptance step before production use.