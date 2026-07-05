#!/bin/sh
# SC7 — verify docs/companion-protocol.yaml matches registered handlers.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPEC="$ROOT/docs/companion-protocol.yaml"
WEB="$ROOT/src/channels/web.c"
ROUTES="$ROOT/src/companion/routes.c"

fail() { echo "check_companion_openapi: $*" >&2; exit 1; }

[ -f "$SPEC" ] || fail "missing $SPEC"
[ -f "$WEB" ] || fail "missing $WEB"

# Layer 0 routes (always registered when web channel is enabled)
for path in \
    /api/health \
    /api/message \
    /api/progress \
    /api/media \
    /api/memory/pending \
    /api/audit \
    /api/ui-config; do
    grep -q "$path" "$SPEC" || fail "OpenAPI missing path $path"
    grep -q "$path" "$WEB" || fail "web.c missing route $path"
done

# Layer 1 routes (companion flag)
if [ -f "$ROUTES" ]; then
    for path in /api/companion/capabilities /api/companion/snap /api/companion/snaps /api/companion/notes; do
        grep -q "$path" "$SPEC" || fail "OpenAPI missing path $path"
        grep -q "$path" "$WEB" || fail "web.c missing registration for $path"
    done
    grep -q 'smolclaw-companion/1' "$SPEC" "$ROUTES" \
        || fail "protocol string mismatch"
    grep -q '10485760' "$SPEC" "$ROUTES" \
        || fail "snap_max_bytes mismatch"
else
    echo "check_companion_openapi: routes.c absent (SC_ENABLE_COMPANION=n?) — spec-only checks"
fi

grep -q 'ErrorResponse' "$SPEC" || fail "missing ErrorResponse schema"
grep -q 'unsupported content type' "$ROUTES" 2>/dev/null \
    || grep -q 'unsupported content type' "$SPEC" \
    || fail "snap content-type error not documented"

grep -q 'send_json_error\|sc_web_send_json_error' "$WEB" \
    || fail "web.c missing JSON error helper"

echo "check_companion_openapi: OK"