#!/usr/bin/env bash
# Validate CLAUDE.md facts — and numeric claims in the public docs —
# against the actual codebase.
# Used by Claude Code PostToolUse hook to catch accuracy drift.
#
# Reads PostToolUse JSON on stdin. Only runs checks when an edit touches
# a file that could make CLAUDE.md or the docs stale (CMakeLists.txt,
# Kconfig, main.c, channels/, kconfig_genconfig.py, deny_patterns.h,
# test_security_prod.c) or one of the checked docs themselves. Outputs
# warnings to stderr.
#
# Doc checks cover counts derivable without a build (deny patterns,
# Kconfig flags, test functions). Binary sizes are NOT checked here —
# remeasure those with scripts/check_size_budget.sh on real builds.

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

# Only trigger on files that affect CLAUDE.md/doc facts, or the docs themselves
case "$edited_file" in
    FORCE) ;;  # manual run
    *CMakeLists.txt|*Kconfig|*main.c|*channels/*.c|*channels/*.h|*kconfig_genconfig.py) ;;
    *deny_patterns.h|*test_security_prod.c) ;;
    *README.md|*RELEASE_NOTES.md|*docs/SECURITY.md|*docs/CONFIGURATION.md|*gateway-threat-model.md) ;;
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
claimed_channels_line=$(grep -P 'Channels.*src/channels' "$CLAUDE_MD" | head -1 || true)
# Count comma-separated items in the channel list
claimed_channel_count=$(echo "$claimed_channels_line" | { grep -oP '(?<=\| )[^|]+(?=\. Manager)' || true; } | tr ',' '\n' | grep -c . || true)
if [ "$actual_channels" -gt 0 ] && [ "$claimed_channel_count" -gt 0 ] && [ "$actual_channels" != "$claimed_channel_count" ]; then
    warnings+=("Channels: CLAUDE.md lists $claimed_channel_count, actual $actual_channels .c files")
fi

# ========================================================================
# Public-doc numeric claims vs code (docs truthfulness pass, 2026-07-13).
# Each claim regex extracts the number a doc cites; mismatch = drift.
# ========================================================================

# Deny-pattern count: entries in sc_deny_patterns[] are one string per line.
# (Authoritative count is SC_DENY_PATTERN_COUNT = sizeof/sizeof; this grep
# matches it as long as the one-pattern-per-line style holds.)
actual_deny=$(grep -c '^[[:space:]]*"' "$DIR/src/tools/deny_patterns.h" 2>/dev/null || echo 0)

# check_doc_number <file> <pcre-with-\d+-capture> <label> <actual>
# Warns on every occurrence in <file> whose number differs from <actual>.
check_doc_number() {
    local file="$1" regex="$2" label="$3" actual="$4"
    [ -f "$DIR/$file" ] || return 0
    local n
    while IFS= read -r n; do
        if [ -n "$n" ] && [ "$n" != "$actual" ]; then
            warnings+=("$label: $file says $n, actual $actual")
        fi
    done < <(grep -oP "$regex" "$DIR/$file" 2>/dev/null || true)
}

check_doc_number README.md                                '\d+(?= deny patterns)'                    "Deny patterns" "$actual_deny"
check_doc_number README.md                                '\d+(?= POSIX ERE patterns)'               "Deny patterns" "$actual_deny"
check_doc_number docs/SECURITY.md                         '\d+(?=\*\* POSIX ERE patterns)'           "Deny patterns" "$actual_deny"
check_doc_number docs/SECURITY.md                         '(?<=with the )\d+(?= patterns)'           "Deny patterns" "$actual_deny"
check_doc_number docs/CONFIGURATION.md                    '(?<=blocks )\d+(?= dangerous patterns)'   "Deny patterns" "$actual_deny"
check_doc_number docs/operations/gateway-threat-model.md  '\d+(?= POSIX ERE patterns)'               "Deny patterns" "$actual_deny"
check_doc_number RELEASE_NOTES.md                         '\d+(?= patterns in current tree)'         "Deny patterns" "$actual_deny"

# Kconfig SC_ENABLE_* flag count (README cites it twice, RELEASE_NOTES once)
check_doc_number README.md        '\d+(?=\*\* `SC_ENABLE_\*`)'  "Kconfig flags" "$actual_features"
check_doc_number README.md        '(?<=are \*\*)\d+(?=\*\*)'    "Kconfig flags" "$actual_features"
check_doc_number RELEASE_NOTES.md '\d+(?= `SC_ENABLE_\*`)'      "Kconfig flags" "$actual_features"

# test_security_prod test-function count (docs/SECURITY.md)
actual_testfns=$(grep -cE '^static (int|void) test_' "$DIR/tests/test_security_prod.c" 2>/dev/null || echo 0)
check_doc_number docs/SECURITY.md '\d+(?=\*\* test functions)' "Security test functions" "$actual_testfns"

# --- Output ---
if [ ${#warnings[@]} -gt 0 ]; then
    echo "Doc accuracy drift detected (CLAUDE.md / public docs):" >&2
    printf '%s\n' "${warnings[@]}" | sort -u | while IFS= read -r w; do
        echo "  - $w" >&2
    done
    echo "Run: scripts/check_claude_md.sh (manual) to see all checks" >&2
fi

exit 0
