#!/usr/bin/env bash
#
# test_security.sh - Production security integration test orchestrator
#
# Builds and runs test_security_prod, then optionally runs IRC smoke tests.
#
# Usage:
#   ./scripts/test_security.sh [--skip-irc] [--verbose] [--local]
#
# Environment variables:
#   SSH_HOST      SSH target for remote tests (default: none, use --local)
#   REMOTE_DIR    Repo path on remote host (default: ~/smolclaw)
#   IRC_SERVER    IRC server for smoke tests (default: localhost)
#   IRC_PORT      IRC port (default: 6667)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

SSH_HOST="${SSH_HOST:-}"
REMOTE_DIR="${REMOTE_DIR:-~/smolclaw}"
IRC_SERVER="${IRC_SERVER:-localhost}"
IRC_PORT="${IRC_PORT:-6667}"

SKIP_IRC=0
VERBOSE=0
LOCAL=0  # Run C tests locally instead of remote

# Parse flags
for arg in "$@"; do
    case "$arg" in
        --skip-irc) SKIP_IRC=1 ;;
        --verbose|-v) VERBOSE=1 ;;
        --local) LOCAL=1 ;;
        --help|-h)
            echo "Usage: $0 [--skip-irc] [--verbose] [--local]"
            echo ""
            echo "  --skip-irc   Skip IRC smoke tests"
            echo "  --verbose    Verbose output"
            echo "  --local      Run C tests locally (not on remote host)"
            echo ""
            echo "Environment: SSH_HOST, REMOTE_DIR, IRC_SERVER, IRC_PORT"
            exit 0
            ;;
        *) echo "Unknown flag: $arg"; exit 1 ;;
    esac
done

PASS=0
FAIL=0

header() {
    echo ""
    echo "========================================"
    echo "  $1"
    echo "========================================"
}

# ---------- Part 1: Build and run C tests ----------

if [ "$LOCAL" -eq 1 ]; then
    header "Building test_security_prod (local)"

    cmake -B "$PROJECT_DIR/build" "$PROJECT_DIR" > /dev/null 2>&1
    cmake --build "$PROJECT_DIR/build" --target test_security_prod -j"$(nproc)" 2>&1

    header "Running test_security_prod (local)"
    if "$PROJECT_DIR/build/test_security_prod"; then
        echo "  C tests: PASSED"
        PASS=$((PASS + 1))
    else
        echo "  C tests: FAILED"
        FAIL=$((FAIL + 1))
    fi
elif [ -n "$SSH_HOST" ]; then
    header "Building test_security_prod on $SSH_HOST"

    ssh "$SSH_HOST" "cd $REMOTE_DIR && git pull --ff-only" 2>&1 | \
        { [ "$VERBOSE" -eq 1 ] && cat || tail -1; }

    ssh "$SSH_HOST" "cd $REMOTE_DIR && cmake -B build . > /dev/null 2>&1 && \
        cmake --build build --target test_security_prod -j\$(nproc)" 2>&1 | \
        { [ "$VERBOSE" -eq 1 ] && cat || tail -3; }

    header "Running test_security_prod on $SSH_HOST"

    # Ensure SSRF checks are active (not bypassed)
    if ssh "$SSH_HOST" "cd $REMOTE_DIR && unset SC_TEST_DISABLE_SSRF && ./build/test_security_prod"; then
        echo ""
        echo "  C tests: PASSED"
        PASS=$((PASS + 1))
    else
        echo ""
        echo "  C tests: FAILED"
        FAIL=$((FAIL + 1))
    fi
else
    echo "Error: Set SSH_HOST for remote tests, or use --local"
    exit 1
fi

# ---------- Part 2: IRC smoke tests ----------

if [ "$SKIP_IRC" -eq 0 ]; then
    header "IRC smoke tests"

    IRC_ARGS="--server $IRC_SERVER --port $IRC_PORT"
    [ "$VERBOSE" -eq 1 ] && IRC_ARGS="$IRC_ARGS --verbose"

    if python3 "$SCRIPT_DIR/irc_smoke_test.py" $IRC_ARGS; then
        echo "  IRC tests: PASSED"
        PASS=$((PASS + 1))
    else
        echo "  IRC tests: FAILED"
        FAIL=$((FAIL + 1))
    fi
else
    echo ""
    echo "(IRC smoke tests skipped)"
fi

# ---------- Part 3: Audit log check ----------

if [ "$LOCAL" -eq 0 ] && [ -n "$SSH_HOST" ]; then
    header "Audit log check (last 20 entries)"

    AUDIT_PATH="~/.smolclaw/workspace/audit.log"
    ssh "$SSH_HOST" "tail -20 $AUDIT_PATH 2>/dev/null || echo '(no audit log)'"
fi

# ---------- Summary ----------

header "Summary"

TOTAL=$((PASS + FAIL))
echo "  $PASS/$TOTAL test groups passed"

if [ "$FAIL" -gt 0 ]; then
    echo "  RESULT: FAIL"
    exit 1
else
    echo "  RESULT: PASS"
    exit 0
fi
