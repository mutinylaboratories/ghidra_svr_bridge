#!/usr/bin/env bash
# start-bridge.sh — Run the ghidra-bridge service on the Ghidra server machine.
#
# The bridge listens for Binary Ninja connections (default port 13200) and
# proxies requests to the local Ghidra Server via RMI.
#
# Usage:
#   ./start-bridge.sh [--port <N>] [--trust-all]
#
# Configuration (edit the variables below or set them in the environment):
#   GHIDRA_HOME   Path to the Ghidra installation directory (required).
#   BRIDGE_JAR    Path to ghidra-bridge-0.1.0.jar (default: same dir as script).
#   BRIDGE_PORT   TCP port to listen on (default: 13200).
#   JAVA_CMD      Java executable (default: java from PATH).
#
# The bridge always binds to 0.0.0.0 (all interfaces) when started from this
# script so that Binary Ninja can connect from the network.  Restrict access
# using your firewall — only trusted Binary Ninja clients should reach port 13200.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Configuration — override with environment variables or edit here
# ---------------------------------------------------------------------------
GHIDRA_HOME="${GHIDRA_HOME:-}"
BRIDGE_JAR="${BRIDGE_JAR:-$SCRIPT_DIR/ghidra-bridge-0.1.0.jar}"
BRIDGE_PORT="${BRIDGE_PORT:-13200}"
JAVA_CMD="${JAVA_CMD:-java}"

# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------
if [[ -z "$GHIDRA_HOME" ]]; then
    # Auto-detect: look for ghidra_*_PUBLIC next to the script or one level up.
    for search_dir in "$SCRIPT_DIR" "$(dirname "$SCRIPT_DIR")"; do
        found=$(find "$search_dir" -maxdepth 1 -name "ghidra_*_PUBLIC" -type d 2>/dev/null | head -1)
        if [[ -n "$found" ]]; then
            GHIDRA_HOME="$found"
            break
        fi
    done
fi

if [[ -z "$GHIDRA_HOME" ]]; then
    echo "ERROR: GHIDRA_HOME is not set and could not be auto-detected."
    echo "       Set the GHIDRA_HOME environment variable to your Ghidra installation directory."
    exit 1
fi

if [[ ! -f "$BRIDGE_JAR" ]]; then
    echo "ERROR: Bridge JAR not found: $BRIDGE_JAR"
    echo "       Build it with:  ./build.sh bridge   (from the repo root on a build machine)"
    echo "       Then copy ghidra-bridge-0.1.0.jar to this directory."
    exit 1
fi

# ---------------------------------------------------------------------------
# Build classpath: bridge JAR + Ghidra Framework JARs
# ---------------------------------------------------------------------------
CP="$BRIDGE_JAR"
for module in FileSystem DB Generic Utility SoftwareModeling Project; do
    CP="$CP:$GHIDRA_HOME/Ghidra/Framework/$module/lib/*"
done
CP="$CP:$GHIDRA_HOME/Ghidra/Features/GhidraServer/lib/*"

# ---------------------------------------------------------------------------
# Extra flags from command line (passed through to BridgeMain)
# ---------------------------------------------------------------------------
EXTRA_FLAGS=()
for arg in "$@"; do
    EXTRA_FLAGS+=("$arg")
done

# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------
echo "Ghidra Bridge starting..."
echo "  GHIDRA_HOME : $GHIDRA_HOME"
echo "  BRIDGE_JAR  : $BRIDGE_JAR"
echo "  Port        : $BRIDGE_PORT"
echo ""
echo "Binary Ninja should be configured with:"
echo "  Bridge Port : $BRIDGE_PORT  (Settings → Ghidra → Bridge Port)"
echo ""

exec "$JAVA_CMD" \
    -cp "$CP" \
    com.ghidra_svr.bridge.BridgeMain \
    --port "$BRIDGE_PORT" \
    --bind-all \
    --ghidra-home "$GHIDRA_HOME" \
    "${EXTRA_FLAGS[@]}"
