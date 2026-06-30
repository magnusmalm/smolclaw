# Companion remote access

How to expose a smolclaw gateway to the Android companion app over LAN,
Tailscale, or a reverse proxy. The companion app enforces **HTTPS** for
non-private hosts; loopback and RFC1918 addresses may use HTTP.

## Prerequisites

1. Gateway with `channels.web` enabled and a strong `bearer_token`.
2. Restrictive `channels.web.tools` allowlist (primary security boundary).
3. `SC_ENABLE_COMPANION=y` build for snap upload and `smolclaw companion qr`.

```jsonc
"channels": {
  "web": {
    "enabled": true,
    "bind_addr": "127.0.0.1",
    "port": 8080,
    "bearer_token": "file:///etc/smolclaw/companion.token",
    "tools": ["message", "memory_read", "memory_write", "memory_search", "note"]
  }
}
```

Generate the setup QR on the gateway host:

```bash
smolclaw companion qr
# Remote / Tailscale — override the public origin:
smolclaw companion qr --url https://pi.tailnet-name.ts.net
```

## LAN (same Wi‑Fi)

Bind to all interfaces only if you trust the LAN:

```jsonc
"bind_addr": "0.0.0.0",
"port": 8080
```

The QR CLI defaults `0.0.0.0` to `http://127.0.0.1:8080` for encoding; use
`--url http://192.0.2.10:8080` with the Pi's LAN IP when pairing from a phone.

Verify:

```bash
export TOKEN="$(cat /etc/smolclaw/companion.token)"
curl -s -H "Authorization: Bearer $TOKEN" http://192.0.2.10:8080/api/health
```

## Tailscale Serve (recommended for remote)

Keep the gateway on loopback; let Tailscale terminate TLS:

```bash
# On the gateway host (Tailscale 1.52+)
sudo tailscale serve --bg --https=443 http://127.0.0.1:8080
```

Pair with:

```bash
smolclaw companion qr --url https://$(tailscale status --json | jq -r .Self.DNSName)
```

The app accepts HTTPS origins from your tailnet.

## Caddy reverse proxy

```caddyfile
companion.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Use `smolclaw companion qr --url https://companion.example.com`.

## SC1 manual timing script

Human-only success criterion — run with a physical Android device:

1. Start gateway; run `smolclaw companion qr`.
2. Start stopwatch when QR appears on terminal.
3. Scan QR in companion app (or paste URI).
4. Stop when chat screen shows connected / health check passes.

Target: **under 2 minutes** for a tester who has never paired before.

Record date, gateway version, and elapsed seconds in your run log.

## Notifications (v1)

There is no `/api/companion/events` long-poll in v1. Poll instead:

```bash
# Agent events
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://gateway.example.com/api/audit?since=1719750000&limit=20"

# Memory approvals
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://gateway.example.com/api/memory/pending"
```

## Snap upload

Raw body upload (not `multipart/form-data`):

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: image/jpeg" \
  --data-binary @photo.jpg \
  https://gateway.example.com/api/companion/snap
```

Reference the returned `path` in a follow-up `POST /api/message`.