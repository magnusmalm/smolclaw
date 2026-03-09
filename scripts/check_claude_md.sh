#!/usr/bin/env bash
# Validate CLAUDE.md facts against the actual codebase.
# Used by Claude Code PostToolUse hook to catch accuracy drift.
#
# Reads PostToolUse JSON on stdin. Only runs checks when an edit touches
# a file that could make CLAUDE.md stale (CMakeLists.txt, Kconfig, main.c,
# channels/, kconfig_genconfig.py). Outputs warnings to stderr.

set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)"
CLAUDE_MD="$DIR/CLAUDE.md"

# --- Read hook input (PostToolUse JSON on stdin) ---
if [ -t 0 ]; then
    # Interactive / manual run — check everything
    edited_file="FORCE"
else
    input=$(cat)
    edited_file=$(echo "$input" | grep -oP '"file_path"\s*:\s*"[^"]*"' | head -1 | sed 's/.*"file_path"\s*:\s*"\([^"]*\)".*/\1/' || true)
fi

# Only trigger on files that affect CLAUDE.md facts
case "$edited_file" in
    FORCE) ;;  # manual run
    *CMakeLists.txt|*Kconfig|*main.c|*channels/*.c|*channels/*.h|*kconfig_genconfig.py) ;;
    *) exit 0 ;;
esac

[ -f "$CLAUDE_MD" ] || exit 0

warnings=()

# --- Count features in Kconfig (SC_ENABLE_* configs) ---
actual_features=$(grep -cP '^config SC_ENABLE_' "$DIR/Kconfig" 2>/dev/null || echo 0)
claimed_features=$(grep -oP '^\d+(?= features managed via Kconfig)' "$CLAUDE_MD" 2>/dev/null || echo "?")
if [ "$claimed_features" != "?" ] && [ "$actual_features" != "$claimed_features" ]; then
    warnings+=("Features: CLAUDE.md says $claimed_features, actual $actual_features")
fi

# --- Count core tests (TEST_SOURCES entries + standalone add_test) ---
# Count .c files in the initial TEST_SOURCES set() block
core_in_set=$(sed -n '/^set(TEST_SOURCES/,/^)/p' "$DIR/CMakeLists.txt" | grep -c '\.c' 2>/dev/null || echo 0)
# Count standalone add_test calls outside the foreach
standalone=$(grep -cP 'add_test\(NAME\s+\w+' "$DIR/CMakeLists.txt" 2>/dev/null || echo 0)
# Subtract 1 for the foreach-based add_test
actual_core=$((core_in_set + standalone - 1))
claimed_core=$(grep -oP '^\d+(?= core tests always build)' "$CLAUDE_MD" 2>/dev/null || echo "?")
if [ "$claimed_core" != "?" ] && [ "$actual_core" != "$claimed_core" ]; then
    warnings+=("Core tests: CLAUDE.md says $claimed_core, actual $actual_core")
fi

# --- Count feature-gated tests ---
actual_gated=$(grep -cP 'list\(APPEND TEST_SOURCES' "$DIR/CMakeLists.txt" 2>/dev/null || echo 0)
claimed_gated=$(grep -oP '\d+(?= feature-gated tests compile)' "$CLAUDE_MD" 2>/dev/null || echo "?")
if [ "$claimed_gated" != "?" ] && [ "$actual_gated" != "$claimed_gated" ]; then
    warnings+=("Feature-gated tests: CLAUDE.md says $claimed_gated, actual $actual_gated")
fi

# --- Count channel implementations ---
actual_channels=$(find "$DIR/src/channels" -name '*.c' ! -name 'manager.c' ! -name 'base.c' 2>/dev/null | wc -l)
claimed_channels_line=$(grep -P 'Channels.*src/channels' "$CLAUDE_MD" | head -1)
# Count comma-separated items in the channel list
claimed_channel_count=$(echo "$claimed_channels_line" | grep -oP '(?<=\| )[^|]+(?=\. Manager)' | tr ',' '\n' | wc -l)
if [ "$actual_channels" -gt 0 ] && [ "$claimed_channel_count" -gt 0 ] && [ "$actual_channels" != "$claimed_channel_count" ]; then
    warnings+=("Channels: CLAUDE.md lists $claimed_channel_count, actual $actual_channels .c files")
fi

# --- Output ---
if [ ${#warnings[@]} -gt 0 ]; then
    echo "CLAUDE.md accuracy drift detected:" >&2
    for w in "${warnings[@]}"; do
        echo "  - $w" >&2
    done
    echo "Run: scripts/check_claude_md.sh (manual) to see all checks" >&2
fi

exit 0
