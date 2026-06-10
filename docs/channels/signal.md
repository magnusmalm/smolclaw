# Signal Channel

> **Status**: Planned feature — Not yet implemented  
> Design document: [docs/design/signal-channel.md](../design/signal-channel.md)

The Signal channel will allow you to interact with smolclaw directly inside Signal, using either direct messages or group chats.

smolclaw does **not** speak the Signal protocol natively. It connects to an external `signal-cli` daemon (or the popular `bbernhard/signal-cli-rest-api` Docker container) over HTTP JSON-RPC.

---

## Why Signal?

Signal offers strong end-to-end encryption and privacy properties, making it an attractive channel for sensitive or long-running agent interactions.

---

## Planned Architecture

- You run and maintain the `signal-cli` daemon yourself (or via Docker).
- smolclaw communicates with it over HTTP.
- Full support for the existing security model is planned:
  - `dm_policy` (`pairing`, `allowlist`, `open`)
  - `allow_from` lists (supporting both phone numbers and `uuid:...` entries)
  - Automatic pairing challenge flow
  - Participation in strict security mode

---

## Recommended Setup (Planned)

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

Example configuration (subject to final API):

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

---

## Pairing New Contacts (Planned Behavior)

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

Basic group support is planned. Use the `group_trigger` setting to reduce noise in busy groups — only messages containing the trigger word will be processed by the agent.

---

## Current Limitations (MVP Scope)

When first implemented, the Signal channel is expected to have these limitations:

- Text messages only (no attachments or voice notes in the initial release)
- Polling-based receive (real-time SSE streaming planned for a follow-up)
- No reactions, polls, or read receipts initially
- Single account per channel instance

Media support, typing indicators, and richer features are planned for later phases.

---

## Security Notes

- You are responsible for running and securing the `signal-cli` daemon.
- Back up the Signal account data (`~/.local/share/signal-cli` or your Docker volume) regularly. Loss of keys means loss of the identity.
- Keep `signal-cli` reasonably up to date, as Signal server changes can affect older versions.
- Prefer `dm_policy: "pairing"` for most deployments.

See [Security](../SECURITY.md) and the [design document](../design/signal-channel.md) for more details.

---

## Related Documentation

- [Pairing](pairing.md)
- [Security](../SECURITY.md)
- Design document: [docs/design/signal-channel.md](../design/signal-channel.md)

---

**Note**: This page describes planned functionality. The Signal channel is not yet available in smolclaw. Implementation will follow the design in `docs/design/signal-channel.md`, with particular attention to security and testability.