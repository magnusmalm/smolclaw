#!/usr/bin/env bash
#
# companion_smoke.sh — end-to-end smoke test for the SC_ENABLE_COMPANION gateway API.
#
# Spins a throwaway gateway on loopback in an isolated SMOLCLAW_HOME, generates a
# fresh bearer token, and exercises every companion route plus Layer-0 polling —
# the things the in-process unit tests can't cover (real network, real config,
# real `companion qr`). Prints PASS/FAIL per check and a §9.5 baseline block.
#
# No committed secrets; everything lives under $TMPDIR and is removed on success
# (kept on failure for debugging). Routes that need an LLM (/api/message) are
# intentionally NOT exercised, so no provider/API key is required.
#
# Usage:
#   scripts/companion_smoke.sh [path/to/smolclaw]   # defaults to build-companion/ or build/
#   PORT=18080 scripts/companion_smoke.sh           # override loopback port
#
# Build first:  cmake -B build-companion -DSC_ENABLE_COMPANION=ON -DSC_ENABLE_WEB=ON
#               cmake --build build-companion -j --target smolclaw
#
# Note: curls hit 127.0.0.1. If your shell sandbox blocks loopback, run with the
# sandbox disabled.

set -uo pipefail

# --- locate binary -----------------------------------------------------------
BIN="${1:-}"
if [ -z "$BIN" ]; then
  for c in build-companion/smolclaw build/smolclaw ./smolclaw; do
    [ -x "$c" ] && BIN="$c" && break
  done
fi
[ -n "$BIN" ] && [ -x "$BIN" ] || {
  echo "error: no smolclaw binary found. Build with -DSC_ENABLE_COMPANION=ON or pass a path." >&2
  exit 2
}
if ! "$BIN" companion qr --help >/dev/null 2>&1; then
  echo "error: $BIN lacks companion support — rebuild with -DSC_ENABLE_COMPANION=ON -DSC_ENABLE_WEB=ON" >&2
  exit 2
fi

# --- isolated environment ----------------------------------------------------
PORT="${PORT:-18088}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/sc-companion-smoke.XXXXXX")"
export SMOLCLAW_HOME="$TMP/home"
WS="$TMP/workspace"
mkdir -p "$SMOLCLAW_HOME" "$WS"
TOKEN="smoke-$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
BASE="http://127.0.0.1:$PORT"
AUTH=(-H "Authorization: Bearer $TOKEN")

cat > "$SMOLCLAW_HOME/config.json" <<JSON
{
  "config_version": 1,
  "agents": { "defaults": {
    "provider": "ollama", "model": "qwen2.5:14b",
    "workspace": "$WS", "network_scope": "local",
    "restrict_to_workspace": true, "sandbox": false
  }},
  "providers": { "ollama": { "api_base": "http://127.0.0.1:11434/v1" } },
  "channels": {
    "web": {
      "enabled": true, "bind_addr": "127.0.0.1", "port": $PORT,
      "bearer_token": "$TOKEN",
      "tools": ["note", "memory_read"]
    },
    "telegram": {"enabled": false}, "discord": {"enabled": false},
    "irc": {"enabled": false}, "slack": {"enabled": false}, "x": {"enabled": false}
  }
}
JSON

# --- start gateway -----------------------------------------------------------
"$BIN" gateway >"$TMP/gateway.log" 2>&1 &
GW=$!
cleanup() {
  # Bounded teardown: SIGTERM, wait up to ~3s, then SIGKILL. Never block on
  # `wait` — the gateway's graceful shutdown can be slow and would hang the script
  # (and any pipe it feeds, e.g. `| tail`).
  if kill -0 "$GW" 2>/dev/null; then
    kill "$GW" 2>/dev/null
    for _ in 1 2 3 4 5 6; do kill -0 "$GW" 2>/dev/null || break; sleep 0.5; done
    kill -9 "$GW" 2>/dev/null
  fi
  if [ "${FAIL:-1}" -eq 0 ]; then rm -rf "$TMP"; else
    echo "  (artifacts kept for debugging: $TMP)"; fi
}
trap cleanup EXIT

# wait for health (gateway death is detected, not just timeout)
ready=0
for _ in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$BASE/api/health" 2>/dev/null || echo 000)
  [ "$code" = "200" ] && { ready=1; break; }
  kill -0 "$GW" 2>/dev/null || { echo "error: gateway exited during startup:"; tail -20 "$TMP/gateway.log"; FAIL=1; exit 1; }
  sleep 0.25
done
[ "$ready" = 1 ] || { echo "error: gateway never became healthy on $BASE"; tail -20 "$TMP/gateway.log"; FAIL=1; exit 1; }

# --- check helpers -----------------------------------------------------------
PASS=0; FAIL=0
green() { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
red()   { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
expect() { # desc want_code got_code [needle] [body]
  local desc="$1" want="$2" got="$3" needle="${4:-}" body="${5:-}"
  if [ "$got" != "$want" ]; then red "$desc (want HTTP $want, got $got)"; return; fi
  if [ -n "$needle" ] && ! printf '%s' "$body" | grep -q "$needle"; then
    red "$desc (HTTP $want ok, but body missing '$needle')"; return; fi
  green "$desc"
}
req() { # method url ctype datafile  -> RCODE, RBODY
  local m="$1" u="$2" ct="${3:-}" df="${4:-}"
  local a=(-s -o "$TMP/resp" -w '%{http_code}' -X "$m" "${AUTH[@]}")
  [ -n "$ct" ] && a+=(-H "Content-Type: $ct")
  [ -n "$df" ] && a+=(--data-binary "@$df")
  RCODE=$(curl "${a[@]}" "$u" 2>/dev/null || echo 000)
  RBODY=$(cat "$TMP/resp" 2>/dev/null)
}

echo "smolclaw companion smoke test — $BASE  (bin: $BIN)"
echo

# 1. health (authed) — doubles as §9.5 baseline curl
req GET "$BASE/api/health"
BASELINE_HEALTH="$RBODY"
expect "health (authed) 200 + status ok" 200 "$RCODE" '"status":"ok"' "$RBODY"

# 2. health (wrong bearer) -> 401
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer wrong" "$BASE/api/health" 2>/dev/null || echo 000)
expect "health (bad bearer) 401" 401 "$code"

# 3. capabilities
req GET "$BASE/api/companion/capabilities"
expect "companion capabilities 200 + protocol" 200 "$RCODE" 'smolclaw-companion/1' "$RBODY"
expect "companion capabilities advertises snap_max_bytes" 200 "$RCODE" '10485760' "$RBODY"

# 4. snap upload (raw jpeg body, not multipart)
printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9' > "$TMP/test.jpg"
req POST "$BASE/api/companion/snap" "image/jpeg" "$TMP/test.jpg"
expect "snap upload 201 + inbox path" 201 "$RCODE" 'companion/inbox/' "$RBODY"
expect "snap upload returns .jpg + bytes" 201 "$RCODE" '.jpg' "$RBODY"
# confirm the file actually landed in the workspace
relpath=$(printf '%s' "$RBODY" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')
if [ -n "$relpath" ] && [ -f "$WS/$relpath" ]; then green "snap file written to workspace ($relpath)"
else red "snap file not found on disk ($relpath)"; fi

# 5. snap with bad content-type -> 400
req POST "$BASE/api/companion/snap" "text/plain" "$TMP/test.jpg"
expect "snap rejects non-image content-type 400" 400 "$RCODE"

# 6. audit poll (the v1 notification substitute for the cut events endpoint)
req GET "$BASE/api/audit?since=0&limit=10"
expect "audit poll 200" 200 "$RCODE"

# 7. companion qr CLI emits a connect URI (reads same SMOLCLAW_HOME config)
uri=$("$BIN" companion qr --force 2>/dev/null | head -1)
case "$uri" in
  smolclaw://v1/connect\?*) green "companion qr emits connect URI" ;;
  *) red "companion qr URI malformed: '$uri'" ;;
esac

# --- §9.5 baseline -----------------------------------------------------------
echo
echo "----- §9.5 baseline (paste into docs/plans/companion-android-v1-baseline.md) -----"
echo "Commit: $(git rev-parse --short HEAD 2>/dev/null || echo '<unknown>')"
echo "Health: $BASELINE_HEALTH"
echo "Companion build size: $(ls -l "$(dirname "$BIN")/smolclaw" 2>/dev/null | awk '{print $5" bytes"}')"
if [ -x build-size/smolclaw ]; then
  echo -n "Minimal (SC_ENABLE_COMPANION=n): "
  ./scripts/check_size_budget.sh build-size/smolclaw 1024 minimal-dynamic 2>/dev/null || echo "(run check_size_budget.sh manually)"
fi
echo "--------------------------------------------------------------------------------"

# --- summary -----------------------------------------------------------------
echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "✅ companion gateway works end-to-end" || echo "❌ see failures above"
exit "$FAIL"
