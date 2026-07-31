#!/usr/bin/env bash
# build.sh  —  Build the binja-ghidra project (Linux / macOS)
#
# Usage:  ./build.sh [clean] [install] [bridge] [plugin] [qt]
#                    [--channel stable|dev] [--bn-api <commit>]
#
#   (no args)  Build both the C++ plugin and the Java bridge JAR (if Java is available)
#   clean      Delete build directories before building
#   install    Copy the plugin (and JAR if built) into the BN plugins folder
#   bridge     Build the Java bridge JAR only + package it for server deployment
#   plugin     Build the C++ plugin only (skips Java bridge)
#   qt         Build Qt 6 via the qt-build submodule (~1-2 hours, first time only)
#
# Binary Ninja API version (pick the one matching your installed BN):
#   --channel stable   Fetch + build against the latest stable release (default)
#   --channel dev      Fetch + build against the latest dev (dev branch head)
#   --bn-api <commit>  Build against an explicit commit (no GitHub lookup)
#   (--channel and --bn-api are mutually exclusive; stable is the default.
#    --channel queries the binaryninja-api GitHub, so it needs network access.)
#
# Examples:
#   ./build.sh                   — build everything (Java optional — warns if missing)
#   ./build.sh clean install     — clean rebuild + install into BN
#   ./build.sh plugin            — C++ plugin only, no Java required
#   ./build.sh bridge            — build bridge JAR + create server-package/
#   ./build.sh qt                — compile Qt (required once on a fresh machine)
#
# Bridge modes (configured in BN Settings → Ghidra → Bridge Mode):
#   local   — bridge JAR runs on this machine alongside BN (default)
#             Java + Ghidra must be installed locally; JAR installed next to plugin
#   remote  — bridge runs as a service on the Ghidra server machine
#             Run ./build.sh bridge, copy server-package/ to server, run start-bridge.sh
#
# Environment variables (override defaults):
#   Qt6_DIR     Path to Qt6 CMake dir  (default: auto-detected)
#   BN_INSTALL  Path to BN install dir (default: platform-specific — see below)
#   JAVA_HOME   Path to a JDK 17+ install (required only for the bridge JAR;
#               must contain bin/java — an error is printed if it's missing)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Configuration — adjust paths here if your environment differs
# ---------------------------------------------------------------------------
if [[ "$(uname)" == "Darwin" ]]; then
    BN_INSTALL="${BN_INSTALL:-/Applications/Binary Ninja.app/Contents/MacOS}"
    _QT_COMPILER="clang_64"
else
    BN_INSTALL="${BN_INSTALL:-/opt/Vector35/BinaryNinja}"
    _ARCH=$(uname -m)
    _QT_COMPILER="gcc_64"
fi

# Binary Ninja API commit is resolved from GitHub at build time (see the
# channel-resolution section below): --channel stable fetches the latest stable
# release, --channel dev fetches the dev branch head, and --bn-api <sha> pins an
# explicit commit without contacting GitHub.
BN_API_REPO="https://api.github.com/repos/Vector35/binaryninja-api"

# Qt version must match qt-build/target_qt6_version.py
_QT_VERSION="6.10.1"

# Resolve Qt6_DIR in priority order (only if not already set by the caller):
#   1. Locally built Qt from the qt-build submodule  (<repo>/qt/<ver>/<compiler>/)
#   2. Qt online installer on macOS                  (/usr/local/Qt-<ver>/)
#   3. System Qt                                      (/usr/lib/cmake/Qt6)
if [[ -z "${Qt6_DIR:-}" ]]; then
    _LOCAL_QT="$SCRIPT_DIR/qt/$_QT_VERSION/$_QT_COMPILER/lib/cmake/Qt6"
    if [[ -f "$_LOCAL_QT/Qt6Config.cmake" ]]; then
        Qt6_DIR="$_LOCAL_QT"
    elif [[ "$(uname)" == "Darwin" ]]; then
        _QMAKE=$(find /usr/local/Qt* -name "qmake" -maxdepth 5 2>/dev/null | head -1)
        if [[ -n "$_QMAKE" ]]; then
            Qt6_DIR="$("$_QMAKE" -query QT_INSTALL_LIBS 2>/dev/null)/cmake/Qt6"
        fi
    fi
    Qt6_DIR="${Qt6_DIR:-/usr/lib/cmake/Qt6}"
fi

# Add qmake to PATH so FindBinaryNinjaUI.cmake can locate Qt.
_QT_BIN="$(cd "$Qt6_DIR/../../.." 2>/dev/null && pwd)/bin"
[[ -f "$_QT_BIN/qmake" ]] && export PATH="$_QT_BIN:$PATH"

BRIDGE_DIR="$SCRIPT_DIR/bridge"
PLUGIN_DIR="$SCRIPT_DIR/plugin"
PLUGIN_BUILD="$PLUGIN_DIR/build"
BRIDGE_JAR="$BRIDGE_DIR/build/libs/ghidra-bridge-0.1.0.jar"

NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
DO_CLEAN=0
DO_INSTALL=0
DO_QT=0
DO_BRIDGE=1   # on by default (skipped with a warning if Java is absent)
DO_PLUGIN=1   # on by default
BRIDGE_ONLY=0
PLUGIN_ONLY=0
BN_CHANNEL=""
BN_API_COMMIT_ARG=""

while [[ $# -gt 0 ]]; do
    case "$(echo "$1" | tr '[:upper:]' '[:lower:]')" in
        clean)   DO_CLEAN=1 ;;
        install) DO_INSTALL=1 ;;
        bridge)  BRIDGE_ONLY=1 ;;
        plugin)  PLUGIN_ONLY=1 ;;
        qt)      DO_QT=1 ;;
        # Value-taking flags: keep the original-case value (commit SHAs etc.).
        --channel)   BN_CHANNEL="${2:-}";        shift ;;
        --channel=*) BN_CHANNEL="${1#*=}" ;;
        --bn-api)    BN_API_COMMIT_ARG="${2:-}"; shift ;;
        --bn-api=*)  BN_API_COMMIT_ARG="${1#*=}" ;;
        *) echo "WARNING: ignoring unknown argument '$1'" ;;
    esac
    shift
done

# Explicit single-component flags override the defaults.
if [[ $BRIDGE_ONLY -eq 1 && $PLUGIN_ONLY -eq 0 ]]; then DO_PLUGIN=0; fi
if [[ $PLUGIN_ONLY -eq 1 && $BRIDGE_ONLY -eq 0 ]]; then DO_BRIDGE=0; fi

# Resolve the Binary Ninja API commit from --channel / --bn-api.
# The two are mutually exclusive; with neither, default to the stable channel.
if [[ -n "$BN_CHANNEL" && -n "$BN_API_COMMIT_ARG" ]]; then
    echo "ERROR: pass either --channel or --bn-api, not both."
    exit 1
fi
if [[ -n "$BN_API_COMMIT_ARG" ]]; then
    # Explicit commit — no GitHub lookup.
    BN_API_COMMIT="$BN_API_COMMIT_ARG"
    echo "Binary Ninja API: explicit commit $BN_API_COMMIT"
else
    _ch="$(echo "${BN_CHANNEL:-stable}" | tr '[:upper:]' '[:lower:]')"
    echo "Fetching latest '$_ch' binaryninja-api commit from GitHub..."
    # dev    -> head of the dev branch.
    # stable -> commit of the latest published 'stable/*' release.
    case "$_ch" in
        dev)
            BN_API_COMMIT=$(curl -fsSL "$BN_API_REPO/commits/dev" \
                | grep '"sha"' | head -1 | sed -E 's/.*"sha": *"([0-9a-f]{40})".*/\1/')
            ;;
        stable)
            _tag=$(curl -fsSL "$BN_API_REPO/releases/latest" \
                | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
            BN_API_COMMIT=$(curl -fsSL "$BN_API_REPO/commits/$_tag" \
                | grep '"sha"' | head -1 | sed -E 's/.*"sha": *"([0-9a-f]{40})".*/\1/')
            ;;
        *) echo "ERROR: --channel must be 'stable' or 'dev' (got '$BN_CHANNEL')"; exit 1 ;;
    esac
    if [[ ! "$BN_API_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
        echo "ERROR: could not fetch the latest '$_ch' binaryninja-api commit from GitHub."
        echo "       Check your network/curl, or pass --bn-api <commit> explicitly."
        exit 1
    fi
    echo "Binary Ninja API: channel '$_ch' -> commit $BN_API_COMMIT"
fi

# ---------------------------------------------------------------------------
# Ensure qt-build submodule is populated (fast — just checks out scripts)
# ---------------------------------------------------------------------------
if [[ ! -f "$SCRIPT_DIR/qt-build/build_macosx" && \
      ! -f "$SCRIPT_DIR/qt-build/build_linux"  && \
      ! -f "$SCRIPT_DIR/qt-build/build_linux-arm" ]]; then
    echo
    echo "Initialising qt-build submodule..."
    git -C "$SCRIPT_DIR" submodule update --init qt-build
fi

# ---------------------------------------------------------------------------
# Build Qt (only when explicitly requested with the 'qt' argument)
# ---------------------------------------------------------------------------
if [[ $DO_QT -eq 1 ]]; then
    echo
    echo "====== Building Qt $_QT_VERSION via qt-build submodule ======"
    echo "This takes 1-2 hours on a fresh machine."
    echo

    # ---- Check and install prerequisites ------------------------------------

    _LLVM_VERSION="19.1.7"   # must match qt-build/target_qt6_version.py
    _MISSING_DEPS=0

    # Poetry
    if ! command -v poetry &>/dev/null; then
        echo "Installing Poetry..."
        if command -v brew &>/dev/null; then
            brew install poetry
        elif command -v pipx &>/dev/null; then
            pipx install poetry
            export PATH="$HOME/.local/bin:$PATH"
        elif command -v pip3 &>/dev/null; then
            pip3 install --user poetry
            export PATH="$HOME/.local/bin:$PATH"
        else
            echo "ERROR: Cannot install Poetry — brew, pipx, and pip3 not found."
            echo "       Install Poetry manually: https://python-poetry.org/docs/"
            _MISSING_DEPS=1
        fi
    fi

    # libclang — qt6_build.py looks for ~/libclang/<version>/
    if [[ ! -d "$HOME/libclang/$_LLVM_VERSION" ]]; then
        if [[ "$(uname)" == "Darwin" ]]; then
            if ! command -v brew &>/dev/null; then
                echo "ERROR: Homebrew not found. Install it from https://brew.sh/ then re-run."
                _MISSING_DEPS=1
            else
                echo "Installing llvm@19 via Homebrew (provides libclang $_LLVM_VERSION)..."
                brew install llvm@19
                mkdir -p "$HOME/libclang"
                ln -sf "$(brew --prefix llvm@19)" "$HOME/libclang/$_LLVM_VERSION"
                echo "Symlinked $(brew --prefix llvm@19) → ~/libclang/$_LLVM_VERSION"
            fi
        else
            # Linux — try apt/dnf first (fast, small download); fall back to
            # the official LLVM GitHub release tarball if the exact version
            # isn't in the distro repos.
            _LLVM_MAJOR="${_LLVM_VERSION%%.*}"   # "19"
            _CLANG_PREFIX=""
            if command -v apt-get &>/dev/null; then
                echo "Installing libclang-$_LLVM_MAJOR via apt..."
                sudo apt-get install -y "libclang-$_LLVM_MAJOR-dev" "llvm-$_LLVM_MAJOR-dev"
                _CLANG_PREFIX=$(llvm-config-$_LLVM_MAJOR --prefix 2>/dev/null || echo "/usr/lib/llvm-$_LLVM_MAJOR")
            elif command -v dnf &>/dev/null; then
                echo "Installing clang$_LLVM_MAJOR via dnf..."
                sudo dnf install -y "clang$_LLVM_MAJOR" "llvm$_LLVM_MAJOR-devel"
                _CLANG_PREFIX="/usr/lib/llvm${_LLVM_MAJOR}"
            fi

            # If no package manager found the prefix, fall back to the
            # pre-built tarball from GitHub LLVM releases.
            if [[ -z "$_CLANG_PREFIX" || ! -d "$_CLANG_PREFIX" ]]; then
                _ARCH=$(uname -m)
                if [[ "$_ARCH" == "aarch64" ]]; then
                    _LLVM_TARBALL="clang+llvm-${_LLVM_VERSION}-aarch64-linux-gnu.tar.xz"
                elif [[ "$_ARCH" == "x86_64" ]]; then
                    _LLVM_TARBALL="clang+llvm-${_LLVM_VERSION}-x86_64-linux-gnu-ubuntu-22.04.tar.xz"
                else
                    echo "ERROR: No pre-built libclang for architecture $_ARCH."
                    echo "       Install libclang $_LLVM_VERSION manually at ~/libclang/$_LLVM_VERSION"
                    _MISSING_DEPS=1
                fi
                if [[ -n "${_LLVM_TARBALL:-}" ]]; then
                    _LLVM_URL="https://github.com/llvm/llvm-project/releases/download/llvmorg-${_LLVM_VERSION}/${_LLVM_TARBALL}"
                    echo "Downloading LLVM $_LLVM_VERSION from GitHub (~1 GB)..."
                    _TMP_DIR=$(mktemp -d)
                    curl -L --progress-bar "$_LLVM_URL" -o "$_TMP_DIR/$_LLVM_TARBALL"
                    echo "Extracting..."
                    tar -xf "$_TMP_DIR/$_LLVM_TARBALL" -C "$_TMP_DIR"
                    _CLANG_PREFIX=$(echo "$_TMP_DIR"/clang+llvm-*)
                    mkdir -p "$HOME/libclang"
                    mv "$_CLANG_PREFIX" "$HOME/libclang/$_LLVM_VERSION"
                    rm -rf "$_TMP_DIR"
                    echo "Installed to ~/libclang/$_LLVM_VERSION"
                    _CLANG_PREFIX=""  # already moved into place, skip symlink below
                fi
            fi

            if [[ -n "$_CLANG_PREFIX" && -d "$_CLANG_PREFIX" ]]; then
                mkdir -p "$HOME/libclang"
                ln -sf "$_CLANG_PREFIX" "$HOME/libclang/$_LLVM_VERSION"
                echo "Symlinked $_CLANG_PREFIX → ~/libclang/$_LLVM_VERSION"
            fi
        fi
    fi

    if [[ $_MISSING_DEPS -ne 0 ]]; then
        echo
        echo "ERROR: Missing prerequisites — fix the errors above and re-run ./build.sh qt"
        exit 1
    fi

    # ---- Select the platform-specific script --------------------------------
    if [[ "$(uname)" == "Darwin" ]]; then
        _QT_SCRIPT="$SCRIPT_DIR/qt-build/build_macosx"
    else
        _ARCH=$(uname -m)
        if [[ "$_ARCH" == "aarch64" || "$_ARCH" == "arm"* ]]; then
            _QT_SCRIPT="$SCRIPT_DIR/qt-build/build_linux-arm"
        else
            _QT_SCRIPT="$SCRIPT_DIR/qt-build/build_linux"
        fi
    fi

    # Run from qt-build/ — poetry looks for pyproject.toml in the working
    # directory.  QT_INSTALL_DIR tells qt6_build.py where to copy the finished
    # build; --no-pyside skips PySide; --no-prompt prevents an interactive pause.
    (cd "$SCRIPT_DIR/qt-build" && QT_INSTALL_DIR="$SCRIPT_DIR/qt" bash "$_QT_SCRIPT" --no-pyside --no-prompt)
    if [[ $? -ne 0 ]]; then
        echo "ERROR: Qt build failed."
        exit 1
    fi

    # Point Qt6_DIR at the freshly built Qt so the re-configure picks it up.
    Qt6_DIR="$SCRIPT_DIR/qt/$_QT_VERSION/$_QT_COMPILER/lib/cmake/Qt6"
    _QT_BIN="$SCRIPT_DIR/qt/$_QT_VERSION/$_QT_COMPILER/bin"
    [[ -f "$_QT_BIN/qmake" ]] && export PATH="$_QT_BIN:$PATH"

    echo
    echo "Qt build complete. Re-running CMake configure to pick up Qt..."
    cmake \
        -B "$PLUGIN_BUILD" \
        -S "$PLUGIN_DIR" \
        -G Ninja \
        -DQt6_DIR="$Qt6_DIR" \
        -DBN_INSTALL_DIR="$BN_INSTALL" \
        -DBN_API_COMMIT_OVERRIDE="$BN_API_COMMIT" \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo
    echo
    echo "Qt is ready. Re-run ./build.sh to build the plugin."
    exit 0
fi

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------
if [[ $DO_CLEAN -eq 1 ]]; then
    echo
    echo "Cleaning build directories..."
    rm -rf "$PLUGIN_BUILD" "$BRIDGE_DIR/build"
    echo "Done."
fi

# ---------------------------------------------------------------------------
# Build Java bridge
# ---------------------------------------------------------------------------
if [[ $DO_BRIDGE -eq 1 ]]; then
    # Bridge build needs a JDK; require JAVA_HOME from the environment (Gradle
    # picks it up automatically). Validate it has a runnable bin/java.
    if [[ -z "${JAVA_HOME:-}" || ! -x "$JAVA_HOME/bin/java" ]]; then
        echo
        if [[ $BRIDGE_ONLY -eq 1 ]]; then
            echo "ERROR: JAVA_HOME is not set (or has no bin/java) — cannot build the bridge JAR."
            echo "       Set JAVA_HOME to a JDK 17+ install and re-run, e.g.:"
            echo "         export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home   # macOS"
            echo "         export JAVA_HOME=/usr/lib/jvm/temurin-21-jdk                                       # Linux"
            exit 1
        else
            echo "NOTE: JAVA_HOME is not set (or has no bin/java) — skipping bridge JAR build."
            echo "      Set JAVA_HOME to a JDK 17+ install, then: ./build.sh bridge"
            echo "      (Java is needed on the build machine to compile the JAR;"
            echo "       it runs on the Ghidra server in remote mode, or locally in local mode.)"
        fi
        DO_BRIDGE=0
    fi
fi

if [[ $DO_BRIDGE -eq 1 ]]; then
    echo
    echo "====== Building Java bridge JAR ======"
    pushd "$BRIDGE_DIR" > /dev/null
    ./gradlew shadowJar
    popd > /dev/null
    echo "Bridge JAR: $BRIDGE_JAR"

    # ---- Package for server deployment ----------------------------------------
    SERVER_PKG="$SCRIPT_DIR/server-package"
    echo
    echo "====== Packaging bridge for server deployment ======"
    rm -rf "$SERVER_PKG"
    mkdir -p "$SERVER_PKG"
    cp "$BRIDGE_JAR"                         "$SERVER_PKG/"
    cp "$SCRIPT_DIR/server/start-bridge.sh"  "$SERVER_PKG/"
    cp "$SCRIPT_DIR/server/start-bridge.bat" "$SERVER_PKG/"
    chmod +x "$SERVER_PKG/start-bridge.sh"
    cat > "$SERVER_PKG/README.txt" <<'README'
Ghidra Bridge — Server Deployment Package
==========================================

This package runs on the same machine as your Ghidra Server.
Java (JDK 17+) and a Ghidra installation are required on the server.

Quick start (Linux / macOS)
---------------------------
1. Copy this directory to the Ghidra server machine.
2. Set GHIDRA_HOME to your Ghidra installation:
     export GHIDRA_HOME=/path/to/ghidra_12.x_PUBLIC
3. Start the bridge:
     ./start-bridge.sh
   The bridge listens on port 13200 by default.  Use --port N to change it.

Quick start (Windows)
---------------------
1. Copy this directory to the Ghidra server machine.
2. Set GHIDRA_HOME in the environment or edit start-bridge.bat.
3. Run start-bridge.bat.

Firewall
--------
Allow TCP port 13200 inbound from your Binary Ninja client machine(s).
The bridge has no built-in authentication — restrict access at the
firewall level to trusted hosts only.

Binary Ninja settings
---------------------
In BN: Settings → Ghidra → Bridge Mode  → set to "remote"
        Settings → Ghidra → Bridge Port  → set to match the port above (default: 13200)
The bridge host is always the same as the Ghidra Server host entered in
the Connect dialog — no separate host configuration needed.

Running as a service
--------------------
Linux (systemd) — create /etc/systemd/system/ghidra-bridge.service:

  [Unit]
  Description=Ghidra Bridge
  After=network.target

  [Service]
  ExecStart=/path/to/server-package/start-bridge.sh
  Environment=GHIDRA_HOME=/path/to/ghidra_12.x_PUBLIC
  Restart=on-failure
  User=ghidra

  [Install]
  WantedBy=multi-user.target

Then: systemctl enable --now ghidra-bridge
README

    echo
    echo "Server package: $SERVER_PKG/"
    echo "Copy server-package/ to your Ghidra server machine and run start-bridge.sh"
    echo "(needed only if using remote bridge mode)."
fi

# ---------------------------------------------------------------------------
# Build C++ plugin
# ---------------------------------------------------------------------------
if [[ $DO_PLUGIN -eq 1 ]]; then
    echo
    echo "====== Configuring C++ plugin ======"
    cmake \
        -B "$PLUGIN_BUILD" \
        -S "$PLUGIN_DIR" \
        -G Ninja \
        -DQt6_DIR="$Qt6_DIR" \
        -DBN_INSTALL_DIR="$BN_INSTALL" \
        -DBN_API_COMMIT_OVERRIDE="$BN_API_COMMIT" \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo
    if [[ $? -ne 0 ]]; then
        echo "ERROR: CMake configure failed."
        exit 1
    fi

    # CMake returns() early (without defining the plugin target) when Qt is
    # missing.  Detect this so we can print actionable guidance.
    # Note: grep -q closes the pipe early once a match is found, causing cmake
    # to receive SIGPIPE (exit 141).  With pipefail that would invert the check,
    # so we capture output first then grep the captured string.
    _cmake_targets=$(cmake --build "$PLUGIN_BUILD" --target help 2>&1 || true)
    if ! echo "$_cmake_targets" | grep -q "binja-ghidra"; then
        echo
        echo "======================================================"
        echo "  Qt 6 not found — plugin cannot be built yet."
        echo
        echo "  Run once to compile Qt (~1-2 hours):"
        echo "    ./build.sh qt"
        echo
        echo "  Then build normally:"
        echo "    ./build.sh"
        echo "======================================================"
        exit 1
    fi

    echo
    echo "====== Building C++ plugin ======"
    cmake --build "$PLUGIN_BUILD" --config RelWithDebInfo -j "$NPROC"
    if [[ $? -ne 0 ]]; then
        echo "ERROR: Plugin build failed."
        exit 1
    fi
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "Plugin: $PLUGIN_BUILD/libbinja-ghidra.dylib"
    else
        echo "Plugin: $PLUGIN_BUILD/libbinja-ghidra.so"
    fi
fi

# ---------------------------------------------------------------------------
# Install into Binary Ninja plugins folder
# ---------------------------------------------------------------------------
if [[ $DO_INSTALL -eq 1 ]]; then
    echo
    echo "====== Installing ======"

    # Resolve the BN user plugins directory (mirrors BN_USER_PLUGINS_DIR in CMake).
    if [[ "$(uname)" == "Darwin" ]]; then
        _BN_PLUGINS="$HOME/Library/Application Support/Binary Ninja/plugins"
    else
        _BN_PLUGINS="$HOME/.binaryninja/plugins"
    fi
    mkdir -p "$_BN_PLUGINS"

    # Install the C++ plugin (and JAR via cmake OPTIONAL install rule) whenever
    # cmake has already been configured for this build directory.
    if [[ -f "$PLUGIN_BUILD/cmake_install.cmake" ]]; then
        cmake --install "$PLUGIN_BUILD" --config RelWithDebInfo
        if [[ $? -ne 0 ]]; then
            echo "ERROR: Plugin install failed."
            exit 1
        fi
    elif [[ $DO_PLUGIN -eq 1 ]]; then
        echo "ERROR: Plugin build directory not found — run without 'install' first, or"
        echo "       run './build.sh' (no args) to build everything before installing."
        exit 1
    fi

    # Always explicitly copy the JAR when it was built in this run (belt-and-suspenders:
    # covers bridge-only mode where cmake may never have been configured, and also makes
    # it obvious when the JAR is fresh even if cmake's OPTIONAL rule would silently skip it).
    if [[ $DO_BRIDGE -eq 1 ]] && [[ -f "$BRIDGE_JAR" ]]; then
        cp "$BRIDGE_JAR" "$_BN_PLUGINS/"
        echo "Bridge JAR: $_BN_PLUGINS/$(basename "$BRIDGE_JAR")"
    fi

    echo "Installed to: $_BN_PLUGINS/"
fi

echo
echo "====== Build complete ======"
