#!/usr/bin/env bash
# test.sh  —  Build and run the binja-ghidra test suite (Linux / macOS)
#
# Usage:  ./test.sh [options]
#
#   (no args)   Run the C++ unit tests, the BN-headless/parity tests and
#               the Java bridge tests (tiers 0-3)
#   --cpp       C++ tests only (unit + BN-headless)
#   --java      Java tests only
#   --parity    Cross-DB parity tier only (C++ BN tests + gradlew parityTest)
#   --e2e       Live Ghidra-server E2E tier (sets GHIDRA_E2E=1, gradlew e2eTest)
#   --no-build  Skip the cmake --build step (use existing test binaries)
#   --verbose   Pass --gtest_print_time=1 to C++ runner; show all Gradle output
#
# Test tiers (see testdata/parity/RULES.md):
#   0  Pure unit          binja-ghidra-tests + bridge *Test.java     always
#   1  Ghidra round-trip  bridge *RoundTripTest.java                 needs GHIDRA_HOME
#   2  BN .bndb tests     binja-ghidra-bn-tests                      SKIPs w/o BN license
#   3  Cross-DB parity    CanonicalParityTest (C++ + Java)           shared goldens
#   4  Live-server E2E    LiveServerE2ETest                          only via --e2e
#
# Prerequisites:
#   C++ tests: CMake build must have been configured (cmake -B plugin/build -S plugin)
#   BN tests:  Binary Ninja libs resolvable; headless-capable license
#              (BN_LICENSE env var is honoured); otherwise those tests SKIP
#   Java tests: Java 17+ must be on PATH; gradle.properties must set ghidraHome
#   E2E tests: runnable ghidraSvr under ghidraHome (full Ghidra install)
#
# Exit code:
#   0  All selected test suites passed
#   1  One or more suites failed or could not run

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PLUGIN_BUILD="$SCRIPT_DIR/plugin/build"
BRIDGE_DIR="$SCRIPT_DIR/bridge"

# ---------------------------------------------------------------------------
# Colour helpers (disabled when not writing to a terminal)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BOLD=''; RESET=''
fi

info()    { echo -e "${BOLD}$*${RESET}"; }
success() { echo -e "${GREEN}$*${RESET}"; }
warn()    { echo -e "${YELLOW}$*${RESET}"; }
fail()    { echo -e "${RED}$*${RESET}"; }

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
RUN_CPP=1
RUN_BN=1
RUN_JAVA=1
RUN_E2E=0
DO_BUILD=1
VERBOSE=0
JAVA_TASK=test

for arg in "$@"; do
    case "$arg" in
        --cpp)      RUN_JAVA=0 ;;
        --java)     RUN_CPP=0; RUN_BN=0 ;;
        --parity)   RUN_CPP=0; JAVA_TASK=parityTest ;;
        --e2e)      RUN_CPP=0; RUN_BN=0; RUN_JAVA=0; RUN_E2E=1 ;;
        --no-build) DO_BUILD=0 ;;
        --verbose)  VERBOSE=1  ;;
        -h|--help)
            sed -n '2,32p' "$0" | sed 's/^# *//'
            exit 0
            ;;
        *)
            warn "Unknown option: $arg  (try --help)"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Tracking
# ---------------------------------------------------------------------------
CPP_STATUS="skipped"
BN_STATUS="skipped"
JAVA_STATUS="skipped"
E2E_STATUS="skipped"

# ---------------------------------------------------------------------------
# Shared: run one gtest binary; sets the named status variable
# ---------------------------------------------------------------------------
run_gtest_target() {
    local target="$1" status_var="$2"
    if [[ ! -f "$PLUGIN_BUILD/build.ninja" && ! -f "$PLUGIN_BUILD/Makefile" ]]; then
        fail "ERROR: plugin/build has not been configured yet."
        fail "       Run:  cmake -B plugin/build -S plugin   then try again."
        printf -v "$status_var" error
        return
    fi
    if [[ $DO_BUILD -eq 1 ]]; then
        info "Building $target..."
        local nproc
        nproc=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
        if ! cmake --build "$PLUGIN_BUILD" --target "$target" -j "$nproc"; then
            printf -v "$status_var" error
            return
        fi
    fi
    local bin="$PLUGIN_BUILD/$target"
    if [[ ! -x "$bin" ]]; then
        fail "ERROR: Test binary not found at $bin"
        printf -v "$status_var" error
        return
    fi
    info "Running $target..."
    local args=("--gtest_color=yes")
    [[ $VERBOSE -eq 1 ]] && args+=("--gtest_print_time=1")
    if "$bin" "${args[@]}"; then
        printf -v "$status_var" passed
    else
        printf -v "$status_var" failed
    fi
}

# ---------------------------------------------------------------------------
# C++ unit tests (tier 0)
# ---------------------------------------------------------------------------
if [[ $RUN_CPP -eq 1 ]]; then
    echo
    info "====== C++ unit tests ======"
    run_gtest_target binja-ghidra-tests CPP_STATUS
fi

# ---------------------------------------------------------------------------
# BN-headless tests (tiers 2 + 3, C++ side) — SKIP cleanly without a license
# ---------------------------------------------------------------------------
if [[ $RUN_BN -eq 1 ]]; then
    echo
    info "====== BN-headless / parity tests ======"
    run_gtest_target binja-ghidra-bn-tests BN_STATUS
fi

# ---------------------------------------------------------------------------
# Java tests (tiers 0/1/3 via `test`, or parityTest / e2eTest tasks)
# ---------------------------------------------------------------------------
if [[ $RUN_JAVA -eq 1 || $RUN_E2E -eq 1 ]]; then
    echo
    info "====== Java bridge tests ======"

    GRADLE_TASK="$JAVA_TASK"
    [[ $RUN_E2E -eq 1 ]] && GRADLE_TASK=e2eTest

    if ! java -version > /dev/null 2>&1; then
        fail "ERROR: Java not found — cannot run Java tests."
        fail "       Install JDK 17+ and ensure 'java' is on your PATH."
        [[ $RUN_E2E -eq 1 ]] && E2E_STATUS="error" || JAVA_STATUS="error"
    elif [[ ! -f "$BRIDGE_DIR/gradle.properties" ]]; then
        fail "ERROR: bridge/gradle.properties not found."
        fail "       Create it with:  ghidraHome=/path/to/ghidra_12.x_PUBLIC"
        [[ $RUN_E2E -eq 1 ]] && E2E_STATUS="error" || JAVA_STATUS="error"
    else
        GRADLE_ARGS=("$GRADLE_TASK" --rerun)
        if [[ $VERBOSE -eq 0 ]]; then
            # Quiet build output; test results are always shown via testLogging
            GRADLE_ARGS+=(--quiet)
        fi

        if [[ $RUN_E2E -eq 1 ]]; then
            info "Running live-server E2E tests (this starts a local ghidraSvr)..."
            export GHIDRA_E2E=1
        else
            info "Running Java tests via Gradle ($GRADLE_TASK)..."
        fi
        pushd "$BRIDGE_DIR" > /dev/null
        if ./gradlew "${GRADLE_ARGS[@]}"; then
            RESULT="passed"
        else
            RESULT="failed"
        fi
        popd > /dev/null
        [[ $RUN_E2E -eq 1 ]] && E2E_STATUS="$RESULT" || JAVA_STATUS="$RESULT"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
info "======================================================"
info "  Test summary"
info "======================================================"

EXIT_CODE=0

print_status() {
    local suite="$1" status="$2"
    case "$status" in
        passed)  success "  $suite: PASSED" ;;
        failed)  fail    "  $suite: FAILED";  EXIT_CODE=1 ;;
        error)   fail    "  $suite: ERROR";   EXIT_CODE=1 ;;
        skipped) warn    "  $suite: skipped" ;;
    esac
}

print_status "C++ unit tests (GhidraConnectionState / CheckinPreview / Protocol / GhidraJson)" "$CPP_STATUS"
print_status "BN-headless tests (SyncEngine / CheckinCollect / CanonicalParity)"               "$BN_STATUS"
print_status "Java tests (RoundTrip / CanonicalParity)"                                        "$JAVA_STATUS"
print_status "Live-server E2E"                                                                  "$E2E_STATUS"

echo
if [[ $EXIT_CODE -eq 0 ]]; then
    success "All tests passed."
else
    fail "One or more test suites failed."
fi

exit $EXIT_CODE
