#!/bin/bash
# =============================================================================
# Source-based SVF Bitcode Pipeline — builds ANY C/C++ repo from source
# =============================================================================
# Clones a repo, auto-detects build system, compiles with wllvm,
# extracts bitcode, and produces library.bc for SVF analysis.
#
# Usage (inside Docker):
#   source-build.sh
#
# Required environment:
#   REPO_URL       — git repo URL to clone
#   PROJECT_NAME   — project name for logging
#
# Optional environment:
#   REPO_BRANCH    — branch/tag/commit (default: HEAD)
#   OUTPUT_DIR     — output directory (default: /output)
#   MAX_BUILD_TIME — max build time in seconds (default: 600)
#   SOURCE_DIR     — pre-mounted source directory (skip clone)
# =============================================================================

set -euo pipefail

PROJECT_NAME="${PROJECT_NAME:?PROJECT_NAME is required}"
REPO_URL="${REPO_URL:-}"
REPO_BRANCH="${REPO_BRANCH:-}"
REPO_REF="${REPO_REF:-}"          # tag, commit hash, or PR number (e.g., "v1.6.44", "abc123", "PR:42")
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
MAX_BUILD_TIME="${MAX_BUILD_TIME:-600}"
SOURCE_DIR="${SOURCE_DIR:-}"

PIPELINE_START=$(date +%s)

mkdir -p "$OUTPUT_DIR"
exec > >(tee -a "${OUTPUT_DIR}/pipeline.log") 2>&1

log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { log "FATAL: $*"; exit 1; }

log "================================================================"
log " Source Build Pipeline: ${PROJECT_NAME}"
log " REPO_URL=${REPO_URL}  OUTPUT=${OUTPUT_DIR}"
log "================================================================"

# ── Bootstrap: install essential tools ───────────────────────────────────────

export DEBIAN_FRONTEND=noninteractive

# Skip bootstrap if tools already present (pre-built image)
if ! command -v git &>/dev/null || ! command -v cmake &>/dev/null; then
    log "  Installing essential packages..."
    apt-get update -qq 2>/dev/null
    apt-get install -y -qq git ca-certificates curl gnupg software-properties-common 2>&1 | tail -3
else
    log "  Using pre-installed toolchain"
fi

# ── Step 0: Get source code ──────────────────────────────────────────────────

# Convert SSH git URLs to HTTPS (SSH fails in Docker without keys)
git config --global url."https://github.com/".insteadOf "git@github.com:" 2>/dev/null || true
git config --global url."https://github.com/".insteadOf "ssh://git@github.com/" 2>/dev/null || true

if [ -n "$SOURCE_DIR" ] && [ -d "$SOURCE_DIR" ]; then
    PROJECT_SRC="$SOURCE_DIR"
    log "  Using pre-mounted source: $PROJECT_SRC"
else
    [ -n "$REPO_URL" ] || die "REPO_URL or SOURCE_DIR is required"
    PROJECT_SRC="/tmp/source-${PROJECT_NAME}"

    # Determine effective ref: REPO_REF takes priority, then REPO_BRANCH
    _REF="${REPO_REF:-$REPO_BRANCH}"
    _IS_PR=0
    _IS_HASH=0
    _PR_NUM=""

    if [ -n "$_REF" ]; then
        # Detect ref type
        if echo "$_REF" | grep -qiE '^PR[:/#]?[0-9]+$'; then
            # PR reference: "PR:42", "PR/42", "PR#42", "pr42"
            _PR_NUM=$(echo "$_REF" | grep -oP '[0-9]+')
            _IS_PR=1
            log "  Checking out PR #${_PR_NUM} ..."
        elif echo "$_REF" | grep -qP '^[0-9a-f]{7,40}$'; then
            _IS_HASH=1
            log "  Checking out commit ${_REF} ..."
        else
            log "  Checking out ref: ${_REF} (branch/tag) ..."
        fi
    fi

    # Clone strategy depends on ref type (300s timeout for clone)
    # Clone WITHOUT --recurse-submodules first (submodule failures shouldn't block main repo)
    _CLONE_OK=0
    if [ "$_IS_PR" -eq 1 ]; then
        # PR: full clone needed to fetch the PR ref
        timeout 300 git clone "$REPO_URL" "$PROJECT_SRC" 2>&1 && _CLONE_OK=1
        if [ "$_CLONE_OK" -eq 1 ]; then
            cd "$PROJECT_SRC"
            git fetch origin "pull/${_PR_NUM}/head:pr-${_PR_NUM}" 2>&1
            git checkout "pr-${_PR_NUM}" 2>&1
        fi
    elif [ "$_IS_HASH" -eq 1 ]; then
        # Commit hash: can't use --branch, need full clone + checkout
        timeout 300 git clone "$REPO_URL" "$PROJECT_SRC" 2>&1 && _CLONE_OK=1
        if [ "$_CLONE_OK" -eq 1 ]; then
            cd "$PROJECT_SRC"
            git checkout "$_REF" 2>&1
        fi
    elif [ -n "$_REF" ]; then
        # Branch or tag: use --branch for shallow clone
        timeout 120 git clone --depth 1 --shallow-submodules \
            --branch "$_REF" "$REPO_URL" "$PROJECT_SRC" 2>&1 && _CLONE_OK=1
        if [ "$_CLONE_OK" -eq 0 ]; then
            timeout 300 git clone "$REPO_URL" "$PROJECT_SRC" 2>&1 && _CLONE_OK=1
        fi
    else
        # Default: shallow clone of default branch
        timeout 120 git clone --depth 1 \
            "$REPO_URL" "$PROJECT_SRC" 2>&1 && _CLONE_OK=1
    fi

    [ "$_CLONE_OK" -eq 1 ] || die "Git clone failed or timed out for $REPO_URL"

    # Init submodules separately — tolerate failures (e.g. SSH-only submodules)
    cd "$PROJECT_SRC"
    timeout 120 git submodule update --init --depth 1 2>&1 || true
    log "  Cloned to $PROJECT_SRC ($(git rev-parse --short HEAD 2>/dev/null || echo '?'))"
fi

[ -d "$PROJECT_SRC" ] || die "Source directory not found: $PROJECT_SRC"

# ── Step 1: Install toolchain ────────────────────────────────────────────────

log "=== [1/5] Installing LLVM toolchain ==="

# Find or install matching clang + llvm-link pair
LLVM_VER=""

# Check existing tools
if command -v clang &>/dev/null && command -v llvm-link &>/dev/null; then
    CLANG_VER=$(clang --version 2>/dev/null | grep -oP 'clang version \K[0-9]+' || echo "")
    LINK_VER=$(llvm-link --version 2>/dev/null | grep -oP 'LLVM version \K[0-9]+' || echo "")
    if [ "$CLANG_VER" = "$LINK_VER" ] && [ -n "$CLANG_VER" ]; then
        LLVM_VER=$CLANG_VER
        log "  Using existing toolchain: clang-$CLANG_VER"
    fi
fi

# Install from apt if needed
if [ -z "$LLVM_VER" ]; then
    # Add LLVM apt repository for newer versions
    if command -v curl &>/dev/null; then
        curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm.gpg 2>/dev/null || true
        CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME" 2>/dev/null || echo "jammy")
        echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] https://apt.llvm.org/$CODENAME/ llvm-toolchain-$CODENAME main" \
            > /etc/apt/sources.list.d/llvm.list 2>/dev/null || true
        for v in 18 17 16 15; do
            echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] https://apt.llvm.org/$CODENAME/ llvm-toolchain-$CODENAME-$v main" \
                >> /etc/apt/sources.list.d/llvm.list 2>/dev/null || true
        done
        apt-get update -qq 2>/dev/null || true
    fi
    for v in 18 17 16 15 14; do
        if apt-cache show "clang-${v}" &>/dev/null 2>&1 && \
           apt-cache show "llvm-${v}" &>/dev/null 2>&1; then
            log "  Installing clang-${v} + llvm-${v}..."
            apt-get install -y -qq "clang-${v}" "llvm-${v}" 2>&1 | tail -3
            if [ -f "/usr/bin/clang-${v}" ] && [ -f "/usr/bin/llvm-link-${v}" ]; then
                LLVM_VER=$v
                ln -sf "/usr/bin/clang-${v}" /usr/local/bin/clang
                ln -sf "/usr/bin/clang++-${v}" /usr/local/bin/clang++
                ln -sf "/usr/bin/llvm-link-${v}" /usr/local/bin/llvm-link
                ln -sf "/usr/bin/llvm-dis-${v}" /usr/local/bin/llvm-dis
                ln -sf "/usr/bin/llvm-ar-${v}" /usr/local/bin/llvm-ar 2>/dev/null || true
                break
            fi
        fi
    done
fi

[ -n "$LLVM_VER" ] || die "Could not install matching clang + llvm-link pair"
log "  LLVM version: ${LLVM_VER}"

# Install common build dependencies (skip if cmake already present = pre-built image)
if ! command -v cmake &>/dev/null; then
    log "  Installing build dependencies..."
    apt-get install -y -qq cmake autoconf automake libtool pkg-config \
        make ninja-build meson python3 python3-pip gawk bear gettext autopoint \
        zlib1g-dev libssl-dev libpsl-dev libnghttp2-dev libbrotli-dev \
        libc-ares-dev libssh2-1-dev libzstd-dev liblzma-dev \
        2>&1 | tail -3
    # Upgrade cmake and meson via pip
    pip3 install --upgrade cmake meson 2>&1 | tail -1 || true
    # Install optional packages that may not be available
    apt-get install -y -qq libxml2-dev libbz2-dev libffi-dev \
        libabsl-dev libre2-dev libicu-dev libpcre2-dev libjpeg-dev \
        libglib2.0-dev libcurl4-openssl-dev libevent-dev libpng-dev \
        libfreetype-dev libexpat1-dev libdbus-1-dev libsqlite3-dev \
        libpcap-dev libudev-dev libsystemd-dev libelf-dev \
        libavcodec-dev libavformat-dev libavutil-dev libswscale-dev \
        libswresample-dev libgpgme-dev libjson-glib-dev libarchive-dev \
        libapr1-dev libaprutil1-dev libpcre3-dev \
        libtiff-dev libyaml-dev libjansson-dev libmaxminddb-dev \
        libcjson-dev libhiredis-dev liblz4-dev libsnappy-dev \
        libprotobuf-c-dev libcbor-dev libfuse3-dev libmicrohttpd-dev \
        libusb-1.0-0-dev libpcsclite-dev libgcrypt20-dev \
        libunistring-dev libgmp-dev nettle-dev \
        2>&1 | tail -1 || true
else
    log "  Build dependencies already installed"
fi

# ── Step 2: Detect build system and build ────────────────────────────────────

log "=== [2/5] Detecting build system and building ==="

# Set compiler to clang (no wllvm needed — we compile to bitcode directly)
CLANG_BIN=$(command -v "clang-${LLVM_VER}" 2>/dev/null || command -v clang)
CLANGPP_BIN=$(command -v "clang++-${LLVM_VER}" 2>/dev/null || command -v clang++)

export CC="$CLANG_BIN"
export CXX="$CLANGPP_BIN"
export CFLAGS="-emit-llvm -g -O0 -fPIC"
export CXXFLAGS="-emit-llvm -g -O0 -fPIC"

# Detect build system (check root, then one level of subdirectories)
BUILD_SYSTEM="unknown"
BUILD_DIR="$PROJECT_SRC"

# Some repos put source in a subdirectory (e.g., libexpat has expat/)
# Check root first, then subdirectories
_detect_build_system() {
    local dir="$1"
    if [ -f "$dir/CMakeLists.txt" ]; then
        echo "cmake $dir"
    elif [ -f "$dir/configure" ]; then
        echo "autotools-configured $dir"
    elif [ -f "$dir/configure.ac" ] || [ -f "$dir/configure.in" ]; then
        echo "autotools $dir"
    elif [ -f "$dir/meson.build" ]; then
        echo "meson $dir"
    elif [ -f "$dir/Configure" ] && head -1 "$dir/Configure" 2>/dev/null | grep -q "perl"; then
        echo "perl-configure $dir"
    elif [ -f "$dir/configure.py" ]; then
        echo "configure-py $dir"
    elif [ -d "$dir/auto" ] && [ -f "$dir/auto/configure" ]; then
        echo "auto-configure $dir"
    elif [ -f "$dir/Makefile" ] || [ -f "$dir/makefile" ] || [ -f "$dir/GNUmakefile" ]; then
        echo "make $dir"
    fi
}

_detected=$(_detect_build_system "$PROJECT_SRC")
if [ -z "$_detected" ]; then
    # Search one level of subdirectories — pick best build system
    _best_detected=""
    _best_subdir=""
    _best_priority=99
    for _subdir in "$PROJECT_SRC"/*/; do
        [ -d "$_subdir" ] || continue
        _det=$(_detect_build_system "$_subdir")
        if [ -n "$_det" ]; then
            _bs=$(echo "$_det" | cut -d' ' -f1)
            case "$_bs" in
                cmake) _pri=1 ;;
                autotools|autotools-configured) _pri=2 ;;
                meson) _pri=3 ;;
                perl-configure) _pri=4 ;;
                configure-py) _pri=4 ;;
                auto-configure) _pri=4 ;;
                make) _pri=5 ;;
                *) _pri=6 ;;
            esac
            if [ "$_pri" -lt "$_best_priority" ]; then
                _best_priority=$_pri
                _best_detected="$_det"
                _best_subdir="${_subdir%/}"
            fi
        fi
    done
    if [ -n "$_best_detected" ]; then
        _detected="$_best_detected"
        PROJECT_SRC="$_best_subdir"
        log "  Source found in subdirectory: $PROJECT_SRC"
    fi
fi
# Search two levels deep if still not found (e.g. icu/icu4c/source/)
if [ -z "$_detected" ]; then
    _best_detected=""
    _best_subdir=""
    _best_priority=99
    for _subdir in "$PROJECT_SRC"/*/*/; do
        [ -d "$_subdir" ] || continue
        _det=$(_detect_build_system "$_subdir")
        if [ -n "$_det" ]; then
            _bs=$(echo "$_det" | cut -d' ' -f1)
            # Prioritize: cmake=1, autotools=2, meson=3, configure-py=4, make=5
            case "$_bs" in
                cmake) _pri=1 ;;
                autotools|autotools-configured) _pri=2 ;;
                meson) _pri=3 ;;
                perl-configure) _pri=4 ;;
                configure-py) _pri=4 ;;
                auto-configure) _pri=4 ;;
                make) _pri=5 ;;
                *) _pri=6 ;;
            esac
            if [ "$_pri" -lt "$_best_priority" ]; then
                _best_priority=$_pri
                _best_detected="$_det"
                _best_subdir="${_subdir%/}"
            fi
        fi
    done
    if [ -n "$_best_detected" ]; then
        _detected="$_best_detected"
        PROJECT_SRC="$_best_subdir"
        log "  Source found in nested subdirectory: $PROJECT_SRC"
    fi
fi

if [ -n "$_detected" ]; then
    BUILD_SYSTEM=$(echo "$_detected" | cut -d' ' -f1)
    PROJECT_SRC=$(echo "$_detected" | cut -d' ' -f2-)
    BUILD_DIR="$PROJECT_SRC"
fi

# Legacy detection fallback (shouldn't reach here normally)
if [ "$BUILD_SYSTEM" = "unknown" ]; then
    if [ -f "$PROJECT_SRC/CMakeLists.txt" ]; then
        BUILD_SYSTEM="cmake"
    elif [ -f "$PROJECT_SRC/configure" ]; then
        BUILD_SYSTEM="autotools-configured"
    elif [ -f "$PROJECT_SRC/configure.ac" ] || [ -f "$PROJECT_SRC/configure.in" ]; then
        BUILD_SYSTEM="autotools"
    elif [ -f "$PROJECT_SRC/meson.build" ]; then
        BUILD_SYSTEM="meson"
    elif [ -f "$PROJECT_SRC/configure.py" ]; then
        BUILD_SYSTEM="configure-py"
    elif [ -f "$PROJECT_SRC/Makefile" ] || [ -f "$PROJECT_SRC/makefile" ] || [ -f "$PROJECT_SRC/GNUmakefile" ]; then
        BUILD_SYSTEM="make"
    fi
fi

log "  Detected build system: $BUILD_SYSTEM"

# Strategy: compile individual source files to .bc directly, then link
# This is the most reliable approach — works regardless of build system
# because we bypass make/cmake entirely.
#
# For projects that need configure (to generate config.h etc.), we run
# configure first, then compile sources directly.

# Run configure/cmake if needed to generate headers
_run_configure() {
    cd "$PROJECT_SRC"

    # Temporarily unset -emit-llvm from CFLAGS/CXXFLAGS — it breaks configure
    # tests that need to link executables (not just compile).
    _saved_cflags="$CFLAGS"
    _saved_cxxflags="$CXXFLAGS"
    export CFLAGS="-g -O0 -fPIC"
    export CXXFLAGS="-g -O0 -fPIC"

    case "$BUILD_SYSTEM" in
        cmake)
            BUILD_DIR="$PROJECT_SRC/_build"
            mkdir -p "$BUILD_DIR"
            # Use regular compiler for cmake configure (not -emit-llvm)
            _cmake_ok=0
            _cmake_log="/tmp/cmake_config.log"
            cmake -S "$PROJECT_SRC" -B "$BUILD_DIR" \
                -DCMAKE_C_COMPILER="$CLANG_BIN" \
                -DCMAKE_CXX_COMPILER="$CLANGPP_BIN" \
                -DCMAKE_C_FLAGS="-g -O0 -fPIC" \
                -DCMAKE_CXX_FLAGS="-g -O0 -fPIC" \
                -DBUILD_SHARED_LIBS=OFF \
                -DBUILD_TESTING=OFF \
                -DBUILD_TESTS=OFF \
                -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
                > "$_cmake_log" 2>&1 && _cmake_ok=1
            tail -10 "$_cmake_log"

            if [ "$_cmake_ok" -eq 0 ]; then
                # cmake failed — maybe missing deps. Try with autotools if available
                log "  CMake configure failed, trying autotools fallback..."
                BUILD_DIR="$PROJECT_SRC"
                BUILD_SYSTEM="autotools-configured"
                if [ -f "$PROJECT_SRC/configure.ac" ] || [ -f "$PROJECT_SRC/configure.in" ] || [ -f "$PROJECT_SRC/configure" ]; then
                    cd "$PROJECT_SRC"
                    if [ ! -f "configure" ]; then
                        if [ -f "autogen.sh" ]; then
                            bash autogen.sh 2>&1 | tail -5 || true
                        fi
                        if [ ! -f "configure" ] && [ -f "buildconf" ]; then
                            bash buildconf 2>&1 | tail -5 || true
                        fi
                        if [ ! -f "configure" ]; then
                            autoreconf -fi 2>&1 | tail -5 || true
                        fi
                    fi
                    if [ -f "configure" ]; then
                        ./configure CC="$CLANG_BIN" CXX="$CLANGPP_BIN" \
                            CFLAGS="-g -O0 -fPIC" CXXFLAGS="-g -O0 -fPIC" \
                            --disable-shared \
                            2>&1 | tail -10 || true
                        if command -v bear &>/dev/null; then
                            bear -- make -j$(nproc) 2>&1 | tail -10 || true
                        else
                            make -j$(nproc) 2>&1 | tail -10 || true
                        fi
                        log "  Autotools fallback configure + build done"
                    fi
                elif [ -f "$PROJECT_SRC/meson.build" ]; then
                    # Try meson fallback
                    log "  Trying meson fallback..."
                    BUILD_DIR="$PROJECT_SRC/_build"
                    BUILD_SYSTEM="meson"
                    meson setup "$BUILD_DIR" "$PROJECT_SRC" \
                        --default-library=static \
                        2>&1 | tail -10 || \
                    meson setup "$BUILD_DIR" "$PROJECT_SRC" \
                        2>&1 | tail -10 || true
                    if [ -f "$BUILD_DIR/build.ninja" ]; then
                        cd "$BUILD_DIR"
                        ninja 2>&1 | tail -10 || true
                    fi
                    log "  Meson fallback done"
                fi
            else
                # cmake succeeded — run build to generate headers
                log "  Running partial build for generated headers..."
                cd "$BUILD_DIR"
                make -j$(nproc) 2>&1 | tail -20 || \
                    ninja 2>&1 | tail -20 || true
                log "  CMake configure + build done"
            fi
            ;;
        autotools)
            if [ -f "autogen.sh" ]; then
                bash autogen.sh 2>&1 | tail -5 || true
            fi
            if [ ! -f "configure" ] && [ -f "buildconf" ]; then
                bash buildconf 2>&1 | tail -5 || true
            fi
            if [ ! -f "configure" ]; then
                autoreconf -fi 2>&1 | tail -5 || true
            fi
            if [ -f "configure" ]; then
                ./configure CC="$CLANG_BIN" CXX="$CLANGPP_BIN" \
                    CFLAGS="-g -O0 -fPIC" CXXFLAGS="-g -O0 -fPIC" \
                    --disable-shared 2>&1 | tail -10 || true
                # Use bear to capture compile_commands.json, then make
                if command -v bear &>/dev/null; then
                    bear -- make -j$(nproc) 2>&1 | tail -10 || true
                else
                    make -j$(nproc) 2>&1 | tail -10 || true
                fi
            fi
            log "  Autotools configure + build done"
            ;;
        autotools-configured)
            ./configure CC="$CLANG_BIN" CXX="$CLANGPP_BIN" \
                CFLAGS="-g -O0 -fPIC" CXXFLAGS="-g -O0 -fPIC" \
                --disable-shared 2>&1 | tail -10 || true
            if command -v bear &>/dev/null; then
                bear -- make -j$(nproc) 2>&1 | tail -10 || true
            else
                make -j$(nproc) 2>&1 | tail -10 || true
            fi
            log "  Configure + build done"
            ;;
        meson)
            BUILD_DIR="$PROJECT_SRC/_build"
            # Try with common options first, fall back to bare setup
            _meson_ok=0
            meson setup "$BUILD_DIR" "$PROJECT_SRC" \
                --default-library=static \
                2>&1 | tail -10 && _meson_ok=1
            if [ "$_meson_ok" -eq 0 ]; then
                # If meson version too old, upgrade via pip
                if grep -q "Meson version is" "$BUILD_DIR/meson-logs/meson-log.txt" 2>/dev/null || \
                   meson setup "$BUILD_DIR" "$PROJECT_SRC" 2>&1 | grep -q "Meson version"; then
                    log "  Upgrading meson via pip..."
                    pip3 install --quiet --break-system-packages meson 2>/dev/null || \
                        pip3 install --quiet meson 2>/dev/null || true
                    rm -rf "$BUILD_DIR"
                    meson setup "$BUILD_DIR" "$PROJECT_SRC" \
                        --default-library=static \
                        2>&1 | tail -10 || \
                    meson setup "$BUILD_DIR" "$PROJECT_SRC" \
                        2>&1 | tail -10 || true
                else
                    meson setup "$BUILD_DIR" "$PROJECT_SRC" \
                        2>&1 | tail -10 || true
                fi
            fi
            if [ -f "$BUILD_DIR/build.ninja" ]; then
                cd "$BUILD_DIR"
                ninja 2>&1 | tail -10 || true
            fi
            log "  Meson configure + build done"
            ;;
        perl-configure)
            # OpenSSL-style: Perl Configure script
            perl Configure linux-generic64 \
                CC="$CLANG_BIN" CXX="$CLANGPP_BIN" \
                --prefix=/tmp/openssl-install \
                no-shared no-asm \
                2>&1 | tail -10 || \
            perl Configure linux-x86_64 \
                CC="$CLANG_BIN" CXX="$CLANGPP_BIN" \
                no-shared no-asm \
                2>&1 | tail -10 || true
            if command -v bear &>/dev/null; then
                bear -- make -j$(nproc) 2>&1 | tail -10 || true
            else
                make -j$(nproc) 2>&1 | tail -10 || true
            fi
            log "  Perl Configure + build done"
            ;;
        auto-configure)
            # nginx-style: auto/configure script
            if [ -f "auto/configure" ]; then
                # nginx expects CC env var
                ./auto/configure \
                    --with-cc="$CLANG_BIN" \
                    --with-cc-opt="-g -O0 -fPIC" \
                    2>&1 | tail -10 || \
                bash auto/configure 2>&1 | tail -10 || true
            fi
            if command -v bear &>/dev/null; then
                bear -- make -j$(nproc) 2>&1 | tail -10 || true
            else
                make -j$(nproc) 2>&1 | tail -10 || true
            fi
            log "  auto/configure + build done"
            ;;
        configure-py)
            # Botan-style: --cc=clang --cc-bin=clang-18
            python3 configure.py --cc=clang --cc-bin="$CLANG_BIN" \
                2>&1 | tail -10 || \
            python3 configure.py --cc="$CLANG_BIN" --cxx="$CLANGPP_BIN" \
                2>&1 | tail -10 || \
            python3 configure.py 2>&1 | tail -10 || true
            if command -v bear &>/dev/null; then
                bear -- make -j$(nproc) 2>&1 | tail -10 || true
            else
                make -j$(nproc) 2>&1 | tail -10 || true
            fi
            log "  configure.py + build done"
            ;;
        make)
            if command -v bear &>/dev/null; then
                bear -- make -j$(nproc) CC="$CLANG_BIN" CXX="$CLANGPP_BIN" \
                    CFLAGS="-g -O0 -fPIC" CXXFLAGS="-g -O0 -fPIC" \
                    2>&1 | tail -10 || true
            else
                make -j$(nproc) CC="$CLANG_BIN" CXX="$CLANGPP_BIN" \
                    CFLAGS="-g -O0 -fPIC" CXXFLAGS="-g -O0 -fPIC" \
                    2>&1 | tail -10 || true
            fi
            log "  Make build done"
            ;;
    esac

    # Restore CFLAGS with -emit-llvm for direct compilation step
    export CFLAGS="$_saved_cflags"
    export CXXFLAGS="$_saved_cxxflags"
}

# Run configure + build (with timeout)
# We write BUILD_DIR to a file so it survives the subshell
_BD_FILE="/tmp/_build_dir.txt"
echo "$BUILD_DIR" > "$_BD_FILE"

_run_configure_wrapper() {
    _run_configure
    # Persist BUILD_DIR change
    echo "$BUILD_DIR" > "$_BD_FILE"
}

timeout "$MAX_BUILD_TIME" bash -c "
    export PATH='$PATH'
    export DEBIAN_FRONTEND=noninteractive
    BUILD_DIR='$BUILD_DIR'
    BUILD_SYSTEM='$BUILD_SYSTEM'
    PROJECT_SRC='$PROJECT_SRC'
    CLANG_BIN='$CLANG_BIN'
    CLANGPP_BIN='$CLANGPP_BIN'
    $(declare -f log)
    $(declare -f _run_configure)
    _run_configure
    echo \"\$BUILD_DIR\" > '$_BD_FILE'
" 2>&1 || {
    log "  WARNING: Configure step failed or timed out (continuing with direct compilation)"
}

# Read back BUILD_DIR (may have been changed by cmake to _build/)
BUILD_DIR=$(cat "$_BD_FILE" 2>/dev/null || echo "$BUILD_DIR")
log "  BUILD_DIR=$BUILD_DIR"

# ── Step 3: Compile all source files to bitcode ──────────────────────────────

log "=== [3/5] Compiling source files to bitcode ==="

# Collect all C/C++ source files (excluding tests, examples, benchmarks, fuzz)
SOURCE_FILES=""
SOURCE_COUNT=0

# Build include path list — comprehensive discovery
INCLUDE_PATHS="-I${PROJECT_SRC} -I${PROJECT_SRC}/include -I${PROJECT_SRC}/src"
[ -d "$PROJECT_SRC/lib" ] && INCLUDE_PATHS="$INCLUDE_PATHS -I${PROJECT_SRC}/lib"
[ -d "$BUILD_DIR" ] && INCLUDE_PATHS="$INCLUDE_PATHS -I${BUILD_DIR}"

# Add directories containing generated .h files (from cmake/autotools/meson)
if [ -d "$BUILD_DIR" ]; then
    for _d in $(find "$BUILD_DIR" -name "*.h" -exec dirname {} \; 2>/dev/null | sort -u | head -30); do
        INCLUDE_PATHS="$INCLUDE_PATHS -I$_d"
    done
fi

# Add all 'include' directories in the project tree
for _d in $(find "$PROJECT_SRC" -maxdepth 4 -type d -name "include" 2>/dev/null | head -20); do
    INCLUDE_PATHS="$INCLUDE_PATHS -I$_d"
done

# Add directories containing .h files in the source tree (for flat-layout projects)
for _d in $(find "$PROJECT_SRC" -maxdepth 2 -name "*.h" -exec dirname {} \; 2>/dev/null | sort -u | head -20); do
    INCLUDE_PATHS="$INCLUDE_PATHS -I$_d"
done

# Extract compile_commands.json include paths if available
if [ -f "$BUILD_DIR/compile_commands.json" ]; then
    _cc_includes=$(grep -oP '(?<=-I)\S+' "$BUILD_DIR/compile_commands.json" 2>/dev/null | sort -u | head -30 || true)
    for _d in $_cc_includes; do
        [ -d "$_d" ] && INCLUDE_PATHS="$INCLUDE_PATHS -I$_d"
    done
fi

# Add -DHAVE_CONFIG_H for projects that ran configure (generates config.h)
EXTRA_DEFINES=""
if [ -f "$PROJECT_SRC/config.h" ] || [ -f "$BUILD_DIR/config.h" ]; then
    EXTRA_DEFINES="-DHAVE_CONFIG_H"
fi
case "$BUILD_SYSTEM" in
    autotools|autotools-configured|perl-configure)
        EXTRA_DEFINES="-DHAVE_CONFIG_H"
        ;;
esac

log "  Include paths: $INCLUDE_PATHS"
[ -n "$EXTRA_DEFINES" ] && log "  Extra defines: $EXTRA_DEFINES"

# Find source files — exclude tests, examples, benchmarks, third-party
_exclude_pattern="(/test/|/tests/|/testing/|/testbed/|/example/|/examples/|/bench/|/benchmark/|/third.party/|/third_party/|/vendor/|/deps/|/doc/|/docs/|/fuzz/|/fuzzing/|/\.git/|/contrib/|/utils/)"

BC_DIR="/tmp/bc-output"
mkdir -p "$BC_DIR"

BC_FILES=""
BC_COUNT=0
COMPILE_ERRORS=0

# Strategy 1: Use compile_commands.json if available (most reliable)
# Check build dir first, then source dir (bear generates it in source root)
_CC_JSON=""
for _cc_candidate in "$BUILD_DIR/compile_commands.json" "$PROJECT_SRC/compile_commands.json"; do
    if [ -f "$_cc_candidate" ]; then
        _CC_JSON="$_cc_candidate"
        break
    fi
done
_used_cc_json=0

if [ -n "$_CC_JSON" ]; then
    log "  Using compile_commands.json for precise compilation..."
    # Parse compile_commands.json and recompile each file with -emit-llvm
    # Format: [{"directory":"...", "command":"clang ... -c file.c -o file.o", "file":"..."}]
    _cc_result_file="/tmp/_cc_compile_result.txt"
    echo "0 0" > "$_cc_result_file"
    python3 -c "
import json, sys, os, subprocess, re, shlex

cc_json = json.load(open('$_CC_JSON'))
bc_dir = '$BC_DIR'
clang = '$CLANG_BIN'
clangpp = '$CLANGPP_BIN'
project_src = '$PROJECT_SRC'
exclude_re = re.compile(r'$_exclude_pattern')
bc_count = 0
errors = 0

for entry in cc_json:
    src = entry.get('file', '')
    directory = entry.get('directory', '.')

    # Fix 2: Resolve relative paths using the directory field
    if src and not os.path.isabs(src):
        src = os.path.normpath(os.path.join(directory, src))
    if not src or not os.path.isfile(src):
        continue
    if exclude_re.search(src):
        continue

    # Extract flags from command or arguments array
    cmd = entry.get('command', '')
    if cmd:
        try:
            parts = shlex.split(cmd)
        except ValueError:
            parts = cmd.split()
    else:
        # Fix 7: Use arguments array directly (no join+split)
        parts = entry.get('arguments', [])
        if not parts:
            continue

    flags = []
    skip_next = False
    for i, p in enumerate(parts):
        if skip_next:
            skip_next = False
            continue
        if p in ('-o', '-MF', '-MT', '-MQ', '-MJ'):
            skip_next = True
            continue
        if p == '-c' or p == '-MD' or p == '-MP':
            continue
        # Skip source file and output file references
        if p == src or os.path.basename(p) == os.path.basename(src):
            continue
        if p.endswith(('.o', '.d')):
            continue
        if i == 0:  # compiler path
            continue
        # Skip non-clang-compatible flags
        if p.startswith(('-fdiagnostics-color',)):
            continue
        flags.append(p)

    # Add -emit-llvm and replace optimization
    flags = [f for f in flags if not f.startswith('-O')]
    flags.extend(['-emit-llvm', '-g', '-O0', '-Wno-everything'])

    # Determine compiler (C vs C++)
    is_cpp = src.endswith(('.cc', '.cpp', '.cxx', '.C'))
    compiler = clangpp if is_cpp else clang

    rel = os.path.relpath(src, project_src) if src.startswith(project_src) else os.path.basename(src)
    bc_name = rel.replace('/', '_').rsplit('.', 1)[0] + '.bc'
    bc_out = os.path.join(bc_dir, bc_name)

    cmd_list = [compiler] + flags + ['-c', src, '-o', bc_out]
    try:
        result = subprocess.run(cmd_list, capture_output=True, timeout=60,
                                cwd=directory)
        if result.returncode == 0 and os.path.isfile(bc_out) and os.path.getsize(bc_out) > 100:
            bc_count += 1
        else:
            errors += 1
    except Exception:
        errors += 1

with open('$_cc_result_file', 'w') as f:
    f.write(f'{bc_count} {errors}')
print(f'compile_commands.json: {bc_count} compiled, {errors} errors')
" 2>&1 | tail -5 || true

    read _cc_ok _cc_err < "$_cc_result_file" 2>/dev/null || true
    if [ -n "$_cc_ok" ] && [ "$_cc_ok" -gt 0 ] 2>/dev/null; then
        BC_COUNT=$_cc_ok
        COMPILE_ERRORS=${_cc_err:-0}
        # Collect bc files
        BC_FILES=$(find "$BC_DIR" -name "*.bc" -size +100c -type f 2>/dev/null | tr '\n' ' ')
        _used_cc_json=1
        log "  compile_commands.json: $BC_COUNT compiled, $COMPILE_ERRORS errors"
    fi
fi

# Strategy 2: Direct compilation with discovered include paths (fallback)
if [ "$_used_cc_json" -eq 0 ] || [ "$BC_COUNT" -eq 0 ]; then
    if [ "$_used_cc_json" -eq 1 ]; then
        log "  compile_commands.json produced 0 files, falling back to direct compilation..."
    fi
    # Reset
    rm -f "$BC_DIR"/*.bc 2>/dev/null
    BC_FILES=""
    BC_COUNT=0
    COMPILE_ERRORS=0

    # Compile C files
    while IFS= read -r src_file; do
        [ -f "$src_file" ] || continue
        rel_path=$(realpath --relative-to="$PROJECT_SRC" "$src_file" 2>/dev/null || basename "$src_file")
        bc_name=$(echo "$rel_path" | tr '/' '_' | sed 's/\.[^.]*$/.bc/')
        bc_out="$BC_DIR/$bc_name"

        if $CLANG_BIN -emit-llvm -c -g -O0 -fPIC $EXTRA_DEFINES $INCLUDE_PATHS \
            -Wno-everything "$src_file" -o "$bc_out" 2>/dev/null; then
            if [ -f "$bc_out" ] && [ "$(stat -c%s "$bc_out" 2>/dev/null || echo 0)" -gt 100 ]; then
                BC_FILES="$BC_FILES $bc_out"
                BC_COUNT=$((BC_COUNT + 1))
            fi
        else
            COMPILE_ERRORS=$((COMPILE_ERRORS + 1))
        fi
    done < <(find "$PROJECT_SRC" -name "*.c" -type f 2>/dev/null | grep -vE "$_exclude_pattern" | sort)

    # Compile C++ files
    while IFS= read -r src_file; do
        [ -f "$src_file" ] || continue
        rel_path=$(realpath --relative-to="$PROJECT_SRC" "$src_file" 2>/dev/null || basename "$src_file")
        bc_name=$(echo "$rel_path" | tr '/' '_' | sed 's/\.[^.]*$/.bc/')
        bc_out="$BC_DIR/$bc_name"

        if $CLANGPP_BIN -emit-llvm -c -g -O0 -fPIC -std=c++17 $EXTRA_DEFINES $INCLUDE_PATHS \
            -Wno-everything "$src_file" -o "$bc_out" 2>/dev/null; then
            if [ -f "$bc_out" ] && [ "$(stat -c%s "$bc_out" 2>/dev/null || echo 0)" -gt 100 ]; then
                BC_FILES="$BC_FILES $bc_out"
                BC_COUNT=$((BC_COUNT + 1))
            fi
        else
            COMPILE_ERRORS=$((COMPILE_ERRORS + 1))
        fi
    done < <(find "$PROJECT_SRC" -type f \( -name "*.cc" -o -name "*.cpp" -o -name "*.cxx" \) 2>/dev/null | grep -vE "$_exclude_pattern" | sort)
fi

log "  Compiled: $BC_COUNT files, $COMPILE_ERRORS errors"

[ "$BC_COUNT" -gt 0 ] || die "No source files compiled to bitcode"

# Filter out non-bitcode files (e.g., .S assembly produces ELF .o, not bitcode)
# Bitcode files start with 'BC' magic bytes (0x42 0x43)
_VALID_BC=""
_VALID_COUNT=0
_INVALID_COUNT=0
for bc in $BC_FILES; do
    if [ -f "$bc" ] && head -c2 "$bc" 2>/dev/null | grep -q "BC"; then
        _VALID_BC="$_VALID_BC $bc"
        _VALID_COUNT=$((_VALID_COUNT + 1))
    else
        _INVALID_COUNT=$((_INVALID_COUNT + 1))
    fi
done
if [ "$_INVALID_COUNT" -gt 0 ]; then
    log "  Filtered out $_INVALID_COUNT non-bitcode files (assembly/ELF)"
fi
BC_FILES="$_VALID_BC"
BC_COUNT=$_VALID_COUNT

[ "$BC_COUNT" -gt 0 ] || die "No valid bitcode files after filtering"

# ── Step 4: Link all bitcode ─────────────────────────────────────────────────

log "=== [4/5] Linking bitcode ==="

LLVM_LINK=$(command -v "llvm-link-${LLVM_VER}" 2>/dev/null || command -v llvm-link)

if [ "$BC_COUNT" -eq 1 ]; then
    cp $BC_FILES "$OUTPUT_DIR/library.bc"
elif $LLVM_LINK --suppress-warnings $BC_FILES -o "$OUTPUT_DIR/library.bc" 2>/dev/null; then
    log "  Batch link succeeded"
elif $LLVM_LINK $BC_FILES -o "$OUTPUT_DIR/library.bc" 2>&1; then
    log "  Batch link succeeded (with warnings)"
else
    # Hierarchical link — batch files into groups, link groups, then merge
    log "  Batch link failed, trying hierarchical merge..."
    MERGE_DIR="/tmp/bc-merge"
    mkdir -p "$MERGE_DIR"
    BATCH_SIZE=50
    BATCH_NUM=0
    BATCH_FILES=""
    BATCH_COUNT=0
    TOTAL_LINKED=0
    TOTAL_SKIPPED=0

    for bc in $BC_FILES; do
        BATCH_FILES="$BATCH_FILES $bc"
        BATCH_COUNT=$((BATCH_COUNT + 1))

        if [ "$BATCH_COUNT" -ge "$BATCH_SIZE" ]; then
            BATCH_OUT="$MERGE_DIR/batch_${BATCH_NUM}.bc"
            if $LLVM_LINK --suppress-warnings $BATCH_FILES -o "$BATCH_OUT" 2>/dev/null; then
                TOTAL_LINKED=$((TOTAL_LINKED + BATCH_COUNT))
            else
                # Incremental link within the batch (only for conflicting batches)
                FIRST_IN_BATCH=1
                for bc_inner in $BATCH_FILES; do
                    if [ "$FIRST_IN_BATCH" -eq 1 ]; then
                        cp "$bc_inner" "$BATCH_OUT"
                        FIRST_IN_BATCH=0
                        TOTAL_LINKED=$((TOTAL_LINKED + 1))
                    else
                        cp "$BATCH_OUT" "$BATCH_OUT.prev"
                        if $LLVM_LINK --suppress-warnings "$BATCH_OUT.prev" "$bc_inner" \
                                -o "$BATCH_OUT" 2>/dev/null; then
                            TOTAL_LINKED=$((TOTAL_LINKED + 1))
                        else
                            cp "$BATCH_OUT.prev" "$BATCH_OUT"
                            TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
                        fi
                        rm -f "$BATCH_OUT.prev"
                    fi
                done
            fi
            BATCH_NUM=$((BATCH_NUM + 1))
            BATCH_FILES=""
            BATCH_COUNT=0
            log "  Linked batch $BATCH_NUM ($TOTAL_LINKED files so far)"
        fi
    done

    # Handle remaining files
    if [ "$BATCH_COUNT" -gt 0 ]; then
        BATCH_OUT="$MERGE_DIR/batch_${BATCH_NUM}.bc"
        if [ "$BATCH_COUNT" -eq 1 ]; then
            cp $BATCH_FILES "$BATCH_OUT"
            TOTAL_LINKED=$((TOTAL_LINKED + 1))
        elif $LLVM_LINK --suppress-warnings $BATCH_FILES -o "$BATCH_OUT" 2>/dev/null; then
            TOTAL_LINKED=$((TOTAL_LINKED + BATCH_COUNT))
        else
            FIRST_IN_BATCH=1
            for bc_inner in $BATCH_FILES; do
                if [ "$FIRST_IN_BATCH" -eq 1 ]; then
                    cp "$bc_inner" "$BATCH_OUT"
                    FIRST_IN_BATCH=0
                    TOTAL_LINKED=$((TOTAL_LINKED + 1))
                else
                    cp "$BATCH_OUT" "$BATCH_OUT.prev"
                    if $LLVM_LINK --suppress-warnings "$BATCH_OUT.prev" "$bc_inner" \
                            -o "$BATCH_OUT" 2>/dev/null; then
                        TOTAL_LINKED=$((TOTAL_LINKED + 1))
                    else
                        cp "$BATCH_OUT.prev" "$BATCH_OUT"
                        TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
                    fi
                    rm -f "$BATCH_OUT.prev"
                fi
            done
        fi
        BATCH_NUM=$((BATCH_NUM + 1))
    fi

    log "  $BATCH_NUM batches created, merging..."

    # Final merge of all batch files
    ALL_BATCHES=$(find "$MERGE_DIR" -name "batch_*.bc" -size +100c 2>/dev/null | sort | tr '\n' ' ')
    if [ -n "$ALL_BATCHES" ]; then
        if $LLVM_LINK --suppress-warnings $ALL_BATCHES -o "$OUTPUT_DIR/library.bc" 2>/dev/null; then
            log "  Final merge succeeded"
        else
            # Incremental merge of batches (much fewer files)
            FIRST_BATCH=1
            for batch in $ALL_BATCHES; do
                if [ "$FIRST_BATCH" -eq 1 ]; then
                    cp "$batch" "$OUTPUT_DIR/library.bc"
                    FIRST_BATCH=0
                else
                    cp "$OUTPUT_DIR/library.bc" "$OUTPUT_DIR/library.bc.prev"
                    if $LLVM_LINK --suppress-warnings "$OUTPUT_DIR/library.bc.prev" "$batch" \
                            -o "$OUTPUT_DIR/library.bc" 2>/dev/null; then
                        true
                    else
                        cp "$OUTPUT_DIR/library.bc.prev" "$OUTPUT_DIR/library.bc"
                    fi
                    rm -f "$OUTPUT_DIR/library.bc.prev"
                fi
            done
            log "  Incremental batch merge done"
        fi
    fi
    rm -rf "$MERGE_DIR"
    log "  Hierarchical link: $TOTAL_LINKED/$BC_COUNT linked, $TOTAL_SKIPPED skipped"
fi

# Validate
[ -f "$OUTPUT_DIR/library.bc" ] || die "library.bc not produced"
BC_SIZE=$(du -h "$OUTPUT_DIR/library.bc" 2>/dev/null | cut -f1)
log "  library.bc: $BC_SIZE"

# ── Step 5: Disassemble ─────────────────────────────────────────────────────

log "=== [5/5] Disassembling to .ll ==="

LLVM_DIS=$(command -v "llvm-dis-${LLVM_VER}" 2>/dev/null || command -v llvm-dis)
if $LLVM_DIS "$OUTPUT_DIR/library.bc" -o "$OUTPUT_DIR/library.ll" 2>&1; then
    LL_SIZE=$(du -h "$OUTPUT_DIR/library.ll" 2>/dev/null | cut -f1)
    log "  library.ll: $LL_SIZE"
else
    log "  WARNING: llvm-dis failed"
    touch "$OUTPUT_DIR/library.ll"
fi

# ── Write metadata ───────────────────────────────────────────────────────────

PIPELINE_END=$(date +%s)
PIPELINE_DURATION=$((PIPELINE_END - PIPELINE_START))

cat > "$OUTPUT_DIR/metadata.json" << METAEOF
{
    "project_name": "$PROJECT_NAME",
    "mode": "source",
    "repo_url": "$REPO_URL",
    "build_system": "$BUILD_SYSTEM",
    "bc_count": $BC_COUNT,
    "compile_errors": $COMPILE_ERRORS,
    "bc_size": "$(stat -c%s "$OUTPUT_DIR/library.bc" 2>/dev/null || echo 0)",
    "pipeline_duration_sec": $PIPELINE_DURATION,
    "llvm_version": "$LLVM_VER"
}
METAEOF

log ""
log "================================================================"
log " SUCCESS: ${PROJECT_NAME} (source mode)"
log "   library.bc: $BC_SIZE ($BC_COUNT files linked)"
log "   Build system: $BUILD_SYSTEM"
log "   Compile errors: $COMPILE_ERRORS"
log "   Duration: ${PIPELINE_DURATION}s"
log "================================================================"
