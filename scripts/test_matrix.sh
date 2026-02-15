#!/usr/bin/env bash
#
# test_matrix.sh - Build matrix test runner for smolclaw
#
# Runs up to 10 build combinations across 4 tiers:
#   Tier 1: Default dynamic (full + minimal)
#   Tier 2: + musl native (full + minimal)
#   Tier 3: + cross-compile aarch64 + armv7l (full, needs QEMU)
#   Tier 4: + glibc-static + cross-compile minimal (everything)
#
# Usage: ./scripts/test_matrix.sh [OPTIONS] [TIER]
#
# Options:
#   --verbose|-v     Show full build/test output (default: summary only)
#   --dry-run        Print what would run without executing
#   --keep-builds    Don't delete build dirs after (default: keep all)
#   --skip-build     Only run tests, assume builds already exist
#   -j N             Parallel build jobs (default: nproc)
#
# Tiers:
#   1        Default dynamic: full + minimal (default)
#   2        + musl native: full + minimal
#   3        + cross-compile: aarch64 + armv7l (full only, needs QEMU)
#   4 | all  Everything
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Defaults
TIER=1
VERBOSE=0
DRY_RUN=0
KEEP_BUILDS=1
SKIP_BUILD=0
JOBS="$(nproc)"

# Colors (disabled if not a tty)
if [ -t 1 ]; then
    GREEN=$'\033[32m'
    RED=$'\033[31m'
    YELLOW=$'\033[33m'
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    RESET=$'\033[0m'
else
    GREEN="" RED="" YELLOW="" BOLD="" DIM="" RESET=""
fi

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --verbose|-v) VERBOSE=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --keep-builds) KEEP_BUILDS=1 ;;
        --skip-build) SKIP_BUILD=1 ;;
        -j)
            shift
            JOBS="$1"
            ;;
        1|2|3|4) TIER="$1" ;;
        all) TIER=4 ;;
        --help|-h)
            sed -n '2,/^$/{ s/^# \?//; p }' "$0"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [OPTIONS] [TIER]"
            exit 1
            ;;
    esac
    shift
done

# --- .config backup/restore ---

CONFIG_FILE="$PROJECT_DIR/.config"
BACKUP_FILE="$PROJECT_DIR/.config.matrix-backup"
HAD_CONFIG=0

backup_config() {
    if [ -f "$CONFIG_FILE" ]; then
        cp "$CONFIG_FILE" "$BACKUP_FILE"
        HAD_CONFIG=1
    fi
}

restore_config() {
    if [ "$HAD_CONFIG" -eq 1 ] && [ -f "$BACKUP_FILE" ]; then
        mv "$BACKUP_FILE" "$CONFIG_FILE"
    elif [ "$HAD_CONFIG" -eq 0 ]; then
        rm -f "$CONFIG_FILE" "$BACKUP_FILE"
    fi
}

trap restore_config EXIT

# --- Result tracking ---

declare -a RESULT_LABELS=()
declare -a RESULT_STATUS=()   # pass/fail/skip
declare -a RESULT_DETAIL=()   # "19/19 passed" or skip reason
declare -a RESULT_TIME=()     # seconds

TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

record_result() {
    local label="$1" status="$2" detail="$3" elapsed="$4"
    RESULT_LABELS+=("$label")
    RESULT_STATUS+=("$status")
    RESULT_DETAIL+=("$detail")
    RESULT_TIME+=("$elapsed")
    TOTAL=$((TOTAL + 1))
    case "$status" in
        pass) PASSED=$((PASSED + 1)) ;;
        fail) FAILED=$((FAILED + 1)) ;;
        skip) SKIPPED=$((SKIPPED + 1)) ;;
    esac
}

# --- Build matrix definition ---
#
# Each combo: PRESET CONFIG_TYPE TIER ARCH_CHECK STATIC_CHECK QEMU_BIN
#   PRESET:       cmake preset name
#   CONFIG_TYPE:  "full" or "minimal"
#   TIER:         tier number (1-4)
#   ARCH_CHECK:   string to grep for in `file` output (e.g. "x86-64", "aarch64")
#   STATIC_CHECK: "static" if we expect statically linked, "" otherwise
#   QEMU_BIN:     qemu binary name for cross tests, "" for native

COMBOS=(
    # Tier 1: default dynamic
    "default       full    1 x86-64   ''       ''"
    "default       minimal 1 x86-64   ''       ''"
    # Tier 2: musl native
    "musl          full    2 x86-64   static   ''"
    "musl          minimal 2 x86-64   static   ''"
    # Tier 3: cross-compile full
    "musl-aarch64  full    3 aarch64  static   qemu-aarch64-static"
    "musl-armv7    full    3 ARM      static   qemu-arm-static"
    # Tier 4: glibc-static + cross minimal
    "static        full    4 x86-64   static   ''"
    "static        minimal 4 x86-64   static   ''"
    "musl-aarch64  minimal 4 aarch64  static   qemu-aarch64-static"
    "musl-armv7    minimal 4 ARM      static   qemu-arm-static"
)

# --- Helper functions ---

log() {
    echo "${BOLD}$1${RESET}"
}

# Run a command, capturing output. Show output if verbose.
# On failure in non-verbose mode, caller decides whether to dump the log.
run_cmd() {
    local logfile="$1"
    shift
    if [ "$VERBOSE" -eq 1 ]; then
        "$@" 2>&1 | tee "$logfile"
        return "${PIPESTATUS[0]}"
    else
        "$@" > "$logfile" 2>&1
        return $?
    fi
}

# Show tail of captured log on failure (non-verbose mode only)
dump_log() {
    if [ "$VERBOSE" -eq 0 ] && [ -f "$1" ]; then
        echo ""
        tail -20 "$1"
    fi
}

# Set .config for a combo
setup_config() {
    local config_type="$1"
    if [ "$config_type" = "minimal" ]; then
        cp "$PROJECT_DIR/configs/defconfig.minimal" "$CONFIG_FILE"
    else
        rm -f "$CONFIG_FILE"
    fi
}

# Get build dir for a preset + config_type (avoid collisions between full/minimal)
build_dir() {
    local preset="$1" config_type="$2"
    local base
    # Read binaryDir from the preset
    case "$preset" in
        default)      base="build" ;;
        static)       base="build-static" ;;
        musl)         base="build-musl" ;;
        musl-aarch64) base="build-musl-aarch64" ;;
        musl-armv7)   base="build-musl-armv7" ;;
    esac
    if [ "$config_type" = "minimal" ]; then
        echo "${base}-minimal"
    else
        echo "${base}"
    fi
}

# Validate binary with `file`
validate_binary() {
    local binary="$1" arch_check="$2" static_check="$3"
    local file_out
    file_out="$(file "$binary" 2>&1)"

    if ! echo "$file_out" | grep -q "$arch_check"; then
        echo "FAIL: expected arch '$arch_check' in: $file_out"
        return 1
    fi

    if [ -n "$static_check" ] && [ "$static_check" != "''" ]; then
        if ! echo "$file_out" | grep -q "static"; then
            echo "FAIL: expected statically linked: $file_out"
            return 1
        fi
    fi

    return 0
}

# Count test executables in a build dir
count_tests() {
    local dir="$1"
    find "$dir" -maxdepth 1 -name 'test_*' -executable -type f | wc -l
}

# Run tests natively via ctest
run_native_tests() {
    local bdir="$1" logfile="$2"
    local count
    count="$(count_tests "$bdir")"

    if [ "$VERBOSE" -eq 1 ]; then
        ctest --test-dir "$bdir" --output-on-failure 2>&1 | tee "$logfile"
        local rc="${PIPESTATUS[0]}"
    else
        ctest --test-dir "$bdir" --output-on-failure > "$logfile" 2>&1
        local rc=$?
    fi

    if [ $rc -eq 0 ]; then
        echo "$count/$count passed"
    else
        # Extract failure count from ctest output
        local fail_count
        fail_count="$(grep -oP '\d+(?= tests? failed)' "$logfile" 2>/dev/null || echo "?")"
        local pass_count=$(( count - ${fail_count:-0} ))
        if [ "$VERBOSE" -eq 0 ]; then
            # Show failing test output
            echo ""
            tail -30 "$logfile" >&2
        fi
        echo "${pass_count}/$count passed ($fail_count failed)"
    fi
    return $rc
}

# Run tests via QEMU for cross-compiled binaries
run_qemu_tests() {
    local bdir="$1" qemu_bin="$2" logfile="$3"
    local total=0 pass=0 fail=0

    : > "$logfile"

    while IFS= read -r test_bin; do
        local tname
        tname="$(basename "$test_bin")"
        total=$((total + 1))

        if [ "$VERBOSE" -eq 1 ]; then
            echo "  Running: $qemu_bin $test_bin"
        fi

        if "$qemu_bin" "$test_bin" >> "$logfile" 2>&1; then
            pass=$((pass + 1))
        else
            fail=$((fail + 1))
            if [ "$VERBOSE" -eq 0 ]; then
                echo "" >&2
                echo "  ${RED}FAIL${RESET}: $tname (via $qemu_bin)" >&2
                "$qemu_bin" "$test_bin" >&2 2>&1 || true
            fi
        fi
    done < <(find "$bdir" -maxdepth 1 -name 'test_*' -executable -type f | sort)

    if [ $fail -eq 0 ]; then
        echo "$pass/$total passed"
    else
        echo "$pass/$total passed ($fail failed)"
    fi
    return $fail
}

# --- Main ---

backup_config

# Filter combos by tier
active_combos=()
for combo in "${COMBOS[@]}"; do
    read -r preset config_type combo_tier arch_check static_check qemu_bin <<< "$combo"
    if [ "$combo_tier" -le "$TIER" ]; then
        active_combos+=("$combo")
    fi
done

num_combos=${#active_combos[@]}

echo ""
echo "${BOLD}=== smolclaw build matrix (tier $TIER) ===${RESET}"
echo ""

if [ "$DRY_RUN" -eq 1 ]; then
    for i in "${!active_combos[@]}"; do
        read -r preset config_type combo_tier arch_check static_check qemu_bin <<< "${active_combos[$i]}"
        idx=$((i + 1))
        bdir="$(build_dir "$preset" "$config_type")"
        printf "[%2d/%d] %-15s + %-8s → %-25s" "$idx" "$num_combos" "$preset" "$config_type" "$bdir"
        if [ -n "$qemu_bin" ] && [ "$qemu_bin" != "''" ]; then
            printf " (via %s)" "$qemu_bin"
        fi
        echo ""
    done
    echo ""
    echo "${DIM}Dry run — nothing executed.${RESET}"
    exit 0
fi

LOGDIR="$(mktemp -d /tmp/smolclaw-matrix.XXXXXX)"
trap 'restore_config; rm -rf "$LOGDIR"' EXIT

for i in "${!active_combos[@]}"; do
    read -r preset config_type combo_tier arch_check static_check qemu_bin <<< "${active_combos[$i]}"
    # Strip quotes from parsed values
    arch_check="${arch_check//\'/}"
    static_check="${static_check//\'/}"
    qemu_bin="${qemu_bin//\'/}"

    idx=$((i + 1))
    label="${preset} + ${config_type}"
    bdir="$(build_dir "$preset" "$config_type")"
    full_bdir="$PROJECT_DIR/$bdir"
    logfile="$LOGDIR/${preset}-${config_type}.log"

    # Progress prefix
    printf "[%2d/%d] %-30s " "$idx" "$num_combos" "$label"

    start_time="$SECONDS"

    # Check QEMU availability for cross combos
    if [ -n "$qemu_bin" ]; then
        if ! command -v "$qemu_bin" > /dev/null 2>&1; then
            elapsed=$((SECONDS - start_time))
            record_result "$label" "skip" "$qemu_bin not found" "$elapsed"
            echo "${YELLOW}SKIP${RESET} ($qemu_bin not found)"
            continue
        fi
    fi

    if [ "$SKIP_BUILD" -eq 0 ]; then
        # Set up .config
        setup_config "$config_type"

        # Configure — use preset but override binaryDir for minimal variants
        # Use --fresh to avoid stale cache issues between configs
        if [ "$config_type" = "minimal" ]; then
            set +e
            run_cmd "$logfile.configure" \
                cmake --preset "$preset" -B "$full_bdir" --fresh
            configure_rc=$?
            set -e
        else
            set +e
            run_cmd "$logfile.configure" \
                cmake --preset "$preset" --fresh
            configure_rc=$?
            set -e
        fi

        if [ $configure_rc -ne 0 ]; then
            elapsed=$((SECONDS - start_time))
            record_result "$label" "fail" "configure failed" "$elapsed"
            dump_log "$logfile.configure"
            printf "\n  ${RED}FAIL${RESET} configure failed (%ds)\n" "$elapsed"
            continue
        fi

        # Build
        set +e
        run_cmd "$logfile.build" \
            cmake --build "$full_bdir" -j"$JOBS"
        build_rc=$?
        set -e

        if [ $build_rc -ne 0 ]; then
            elapsed=$((SECONDS - start_time))
            record_result "$label" "fail" "build failed" "$elapsed"
            dump_log "$logfile.build"
            printf "\n  ${RED}FAIL${RESET} build failed (%ds)\n" "$elapsed"
            continue
        fi
    fi

    # Validate binary
    binary="$full_bdir/smolclaw"
    if [ -f "$binary" ]; then
        set +e
        val_msg="$(validate_binary "$binary" "$arch_check" "$static_check")"
        val_rc=$?
        set -e

        if [ $val_rc -ne 0 ]; then
            elapsed=$((SECONDS - start_time))
            record_result "$label" "fail" "$val_msg" "$elapsed"
            echo "${RED}FAIL${RESET} ($val_msg, ${elapsed}s)"
            continue
        fi
    fi

    # Run tests
    set +e
    if [ -n "$qemu_bin" ]; then
        test_detail="$(run_qemu_tests "$full_bdir" "$qemu_bin" "$logfile")"
        test_rc=$?
    else
        test_detail="$(run_native_tests "$full_bdir" "$logfile")"
        test_rc=$?
    fi
    set -e

    elapsed=$((SECONDS - start_time))

    if [ $test_rc -eq 0 ]; then
        record_result "$label" "pass" "$test_detail" "$elapsed"
        # Pad dots between label and result
        dots_len=$((40 - ${#label}))
        [ $dots_len -lt 3 ] && dots_len=3
        printf "%.*s ${GREEN}%s${RESET} (%ds)\n" "$dots_len" "........................................" "$test_detail" "$elapsed"
    else
        record_result "$label" "fail" "$test_detail" "$elapsed"
        printf "%s ${RED}%s${RESET} (%ds)\n" "" "$test_detail" "$elapsed"
    fi
done

# --- Summary ---

echo ""
summary="${BOLD}=== Results: ${GREEN}${PASSED} passed${RESET}"
[ "$FAILED" -gt 0 ] && summary+=", ${RED}${FAILED} failed${RESET}"
[ "$SKIPPED" -gt 0 ] && summary+=", ${YELLOW}${SKIPPED} skipped${RESET}"
summary+="${BOLD} ===${RESET}"
echo "$summary"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
