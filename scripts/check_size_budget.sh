#!/usr/bin/env bash
#
# check_size_budget.sh - enforce SCOPE.md binary size budgets
#
# "smol" is a regression test, not a vibe: the minimal build must stay
# within budget. Budgets (SCOPE.md):
#   minimal dynamic : 1 MB     (stripped; 1024 KB) — CI-enforced
#   minimal static  : 5 MB     (musl, stripped)    — design budget;
#                         invoke this script on musl builds locally/release
#
# Usage: check_size_budget.sh <binary> <max_kb> [label]
# Strips a COPY of the binary (original untouched), compares.

set -euo pipefail

BIN="${1:?usage: check_size_budget.sh <binary> <max_kb> [label]}"
MAX_KB="${2:?usage: check_size_budget.sh <binary> <max_kb> [label]}"
LABEL="${3:-$(basename "$BIN")}"

[ -f "$BIN" ] || { echo "FAIL: $BIN not found"; exit 1; }

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
cp "$BIN" "$TMP"
strip "$TMP" 2>/dev/null || true

SIZE=$(stat -c %s "$TMP")
SIZE_KB=$(( (SIZE + 1023) / 1024 ))

if [ "$SIZE_KB" -gt "$MAX_KB" ]; then
    echo "FAIL: $LABEL is ${SIZE_KB} KB stripped (budget: ${MAX_KB} KB)"
    echo "The minimal build grew past its SCOPE.md budget. Either the"
    echo "new code must shrink, move behind a default-off Kconfig flag,"
    echo "or the budget change must be a deliberate, reviewed decision."
    exit 1
fi

echo "OK: $LABEL is ${SIZE_KB} KB stripped (budget: ${MAX_KB} KB, headroom: $((MAX_KB - SIZE_KB)) KB)"
