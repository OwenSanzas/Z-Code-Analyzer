#!/bin/bash
# =============================================================================
# Auto SVF Bitcode Pipeline — works inside ANY oss-fuzz Docker image
# =============================================================================
# Fully automated: detects build.sh, injects wllvm, extracts library bitcode,
# runs SVF call graph analysis, produces DOT + metadata.
#
# Usage:
#   auto-pipeline.sh [options]
#
# Required environment:
#   PROJECT_NAME   — oss-fuzz project name (e.g. "libpng")
#   SRC            — source root (default: /src)
#
# Optional environment:
#   BUILD_SH_PATH    — explicit path to build.sh (default: auto-detect)
#   SKIP_SVF         — if "1", skip SVF analysis (only produce bitcode)
#   OUTPUT_DIR       — output directory (default: /output)
#   MAX_BUILD_TIME   — max build time in seconds (default: 600)
#   FUZZER_NAMES     — comma-separated fuzzer names to look for
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

PROJECT_NAME="${PROJECT_NAME:?PROJECT_NAME is required}"
SRC="${SRC:-/src}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
BUILD_SH_PATH="${BUILD_SH_PATH:-}"
SKIP_SVF="${SKIP_SVF:-0}"
MAX_BUILD_TIME="${MAX_BUILD_TIME:-600}"
FUZZER_NAMES="${FUZZER_NAMES:-}"

PIPELINE_START=$(date +%s)

mkdir -p "$OUTPUT_DIR"
exec > >(tee -a "${OUTPUT_DIR}/pipeline.log") 2>&1

log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { log "FATAL: $*"; exit 1; }

log "================================================================"
log " Auto SVF Pipeline: ${PROJECT_NAME}"
log " SRC=${SRC}  OUTPUT=${OUTPUT_DIR}"
log "================================================================"

# ── Step 0: Validate environment & find project source ───────────────────────

# Try exact match first, then common variants
PROJECT_SRC=""
for _candidate in \
    "${SRC}/${PROJECT_NAME}" \
    "${SRC}/${PROJECT_NAME#*-}" \
    "${SRC}/${PROJECT_NAME//-/_}" \
; do
    if [ -d "$_candidate" ]; then
        PROJECT_SRC="$_candidate"
        break
    fi
done

# Fallback: find the largest non-engine directory under $SRC
if [ -z "$PROJECT_SRC" ]; then
    # Skip known engine/tool directories
    _skip_dirs="aflplusplus|honggfuzz|fuzztest|centipede|libfuzzer|fuzzing-headers"
    _best="" _best_count=0
    for _d in "$SRC"/*/; do
        [ -d "$_d" ] || continue
        _name=$(basename "$_d")
        echo "$_name" | grep -qiE "^($_skip_dirs)$" && continue
        _count=$(find "$_d" -maxdepth 3 -name '*.c' -o -name '*.cc' -o -name '*.cpp' 2>/dev/null | wc -l)
        if [ "$_count" -gt "$_best_count" ]; then
            _best="$_d"
            _best_count="$_count"
        fi
    done
    if [ -n "$_best" ]; then
        PROJECT_SRC="${_best%/}"
        log "  Auto-detected project source: $PROJECT_SRC (${_best_count} source files)"
    fi
fi

[ -n "$PROJECT_SRC" ] && [ -d "$PROJECT_SRC" ] || die "Project source not found under $SRC for $PROJECT_NAME"
log "  PROJECT_SRC=$PROJECT_SRC"

# ── Step 1: Install toolchain ────────────────────────────────────────────────

log "=== [1/7] Installing wllvm + llvm tools ==="

# Detect Python version (f-strings not available on 3.5)
_pyver=$(python3 -c 'import sys; print("%d.%d" % (sys.version_info.major, sys.version_info.minor))' 2>/dev/null || echo "3.6")
_pymajmin=$(echo "$_pyver" | tr -d '.')
log "  Python version: $_pyver"

# Ensure pip3 is available
if ! command -v pip3 &>/dev/null; then
    log "  pip3 not found, installing python3-pip..."
    apt-get update -qq 2>/dev/null
    apt-get install -y -qq python3-pip python3-setuptools 2>/dev/null || {
        curl -sSk https://bootstrap.pypa.io/get-pip.py 2>/dev/null | python3 2>/dev/null || true
    }
fi

# Install wllvm — robust strategy for all Python versions
_install_wllvm() {
    # Strategy 1: pip install (latest, works on Python >= 3.6)
    if command -v pip3 &>/dev/null; then
        pip3 install --break-system-packages wllvm 2>/dev/null | tail -3 || \
            pip3 install wllvm 2>/dev/null | tail -3 || true
    fi
    # Check if it actually works (latest wllvm has f-strings, breaks on 3.5)
    if command -v wllvm &>/dev/null && wllvm --version &>/dev/null 2>&1; then
        return 0
    fi
    # Verify wllvm actually RUNS (not just installed) — wllvm 1.3.1 uses f-strings
    # which crash on Python 3.5
    if command -v wllvm &>/dev/null && wllvm --version &>/dev/null; then
        return 0
    fi

    # Strategy 2: Download + setup.py install of older version (works on Python 3.5)
    log "  Trying wllvm==1.2.8 via setup.py install..."
    _wllvm_tmp=$(mktemp -d)
    if command -v pip3 &>/dev/null; then
        pip3 download "wllvm==1.2.8" --no-binary :all: -d "$_wllvm_tmp" 2>/dev/null | tail -3 || true
    fi
    # If pip3 download failed, try curl
    if ! ls "$_wllvm_tmp"/wllvm-*.tar.gz &>/dev/null; then
        curl -sSLk "https://files.pythonhosted.org/packages/ed/d3/10bd23fac9353f7957cafb106d351e40eaf3a6fa75b42074c6c262983220/wllvm-1.2.8.tar.gz" \
            -o "$_wllvm_tmp/wllvm-1.2.8.tar.gz" 2>/dev/null || true
    fi
    if ls "$_wllvm_tmp"/wllvm-*.tar.gz &>/dev/null; then
        cd "$_wllvm_tmp"
        tar xzf wllvm-*.tar.gz 2>/dev/null
        cd wllvm-*/
        python3 setup.py install 2>&1 | tail -5 || true
        cd /
    fi
    rm -rf "$_wllvm_tmp"

    if command -v wllvm &>/dev/null; then
        return 0
    fi

    # Strategy 3: python -m pip (sometimes pip3 binary doesn't exist but module does)
    python3 -m pip install --break-system-packages wllvm 2>/dev/null | tail -3 || \
        python3 -m pip install wllvm 2>/dev/null | tail -3 || true
    if command -v wllvm &>/dev/null; then
        return 0
    fi

    return 1
}

_install_wllvm

# Ensure wllvm is in PATH (pip may install to various locations)
for _bp in /usr/local/bin ~/.local/bin /root/.local/bin; do
    if [ -f "$_bp/wllvm" ]; then
        export PATH="$_bp:$PATH"
        break
    fi
done
command -v wllvm &>/dev/null || die "wllvm not found in PATH after installation"

# Strategy: We need clang + llvm-link + llvm-dis all from the SAME LLVM version.
# oss-fuzz images often have clang-22 (git build) without llvm-link/llvm-dis.
# Bitcode format is NOT compatible across major versions.
# Solution: install a matching clang+llvm toolchain from apt and use THAT for wllvm.

WLLVM_LLVM_VER=""

# First check if we already have a matching set (clang + llvm-link + llvm-dis)
if command -v clang &>/dev/null && command -v llvm-link &>/dev/null && command -v llvm-dis &>/dev/null; then
    CLANG_VER=$(clang --version 2>/dev/null | grep -oP 'clang version \K[0-9]+' || echo "")
    LINK_VER=$(llvm-link --version 2>/dev/null | grep -oP 'LLVM version \K[0-9]+' || echo "")
    if [ "$CLANG_VER" = "$LINK_VER" ] && [ -n "$CLANG_VER" ]; then
        WLLVM_LLVM_VER=$CLANG_VER
        log "  Using existing matched toolchain: clang-$CLANG_VER + llvm-link-$LINK_VER"
    fi
fi

# If no matched set, install one from apt
if [ -z "$WLLVM_LLVM_VER" ]; then
    log "  No matched clang/llvm-link pair found, installing from apt..."
    apt-get update -qq 2>/dev/null

    for v in 18 17 16 15 14; do
        if apt-cache show "clang-${v}" &>/dev/null 2>&1 && \
           apt-cache show "llvm-${v}" &>/dev/null 2>&1; then
            log "  Installing clang-${v} + llvm-${v}..."
            apt-get install -y -qq "clang-${v}" "llvm-${v}" 2>&1 | tail -5
            if [ -f "/usr/bin/clang-${v}" ] && [ -f "/usr/bin/llvm-link-${v}" ]; then
                WLLVM_LLVM_VER=$v
                # Symlink the matched set
                ln -sf "/usr/bin/clang-${v}" /usr/local/bin/wllvm-clang
                ln -sf "/usr/bin/clang++-${v}" /usr/local/bin/wllvm-clang++
                ln -sf "/usr/bin/llvm-link-${v}" /usr/local/bin/llvm-link
                ln -sf "/usr/bin/llvm-dis-${v}" /usr/local/bin/llvm-dis
                ln -sf "/usr/bin/llvm-ar-${v}" /usr/local/bin/llvm-ar 2>/dev/null || true
                log "  Installed matched toolchain: clang-${v} + llvm-link-${v}"
                break
            fi
        fi
    done
fi

[ -n "$WLLVM_LLVM_VER" ] || die "Could not install matching clang + llvm-link pair"
log "  LLVM version for wllvm: ${WLLVM_LLVM_VER}"

# Verify all tools
command -v llvm-link &>/dev/null || {
    # One more try: direct path
    for v in $WLLVM_LLVM_VER 18 17 16 15 14; do
        if [ -f "/usr/bin/llvm-link-${v}" ]; then
            ln -sf "/usr/bin/llvm-link-${v}" /usr/local/bin/llvm-link
            break
        fi
    done
}
command -v llvm-dis &>/dev/null || {
    for v in $WLLVM_LLVM_VER 18 17 16 15 14; do
        if [ -f "/usr/bin/llvm-dis-${v}" ]; then
            ln -sf "/usr/bin/llvm-dis-${v}" /usr/local/bin/llvm-dis
            break
        fi
    done
}

command -v llvm-link &>/dev/null || die "llvm-link not available"
command -v llvm-dis &>/dev/null || die "llvm-dis not available"
log "  llvm-link: $(which llvm-link) ($(llvm-link --version 2>&1 | head -1))"
log "  llvm-dis: $(which llvm-dis)"

# ── Step 2: Set up wllvm environment ─────────────────────────────────────────

log "=== [2/7] Setting up wllvm compiler wrappers ==="

# Configure wllvm to use our matched clang version
export LLVM_COMPILER=clang

# Point wllvm at our matched clang using ABSOLUTE paths
# CRITICAL: must NOT resolve to our wrapper dir (prevents infinite recursion)
if [ -f "/usr/local/bin/wllvm-clang" ]; then
    export LLVM_CC_NAME=/usr/local/bin/wllvm-clang
    export LLVM_CXX_NAME=/usr/local/bin/wllvm-clang++
elif [ -f "/usr/bin/clang-${WLLVM_LLVM_VER}" ]; then
    export LLVM_CC_NAME="/usr/bin/clang-${WLLVM_LLVM_VER}"
    export LLVM_CXX_NAME="/usr/bin/clang++-${WLLVM_LLVM_VER}"
else
    # Resolve the real clang path BEFORE we override PATH
    REAL_CLANG="$(which clang 2>/dev/null || echo /usr/bin/clang)"
    REAL_CLANGPP="$(which clang++ 2>/dev/null || echo /usr/bin/clang++)"
    export LLVM_CC_NAME="$REAL_CLANG"
    export LLVM_CXX_NAME="$REAL_CLANGPP"
fi
log "  LLVM_CC_NAME=$LLVM_CC_NAME"
log "  LLVM_CXX_NAME=$LLVM_CXX_NAME"
export LLVM_LINK_NAME=llvm-link
export LLVM_AR_NAME=llvm-ar

# Create wrappers that force -g for debug info
WRAPPER_DIR="/tmp/z-wllvm-bin"
mkdir -p "$WRAPPER_DIR"

# Resolve wllvm path before PATH changes
WLLVM_BIN="$(which wllvm)"
WLLVMPP_BIN="$(which wllvm++)"

cat > "$WRAPPER_DIR/z-wllvm" << WEOF
#!/bin/bash
export LLVM_COMPILER=clang
export LLVM_CC_NAME=$LLVM_CC_NAME
export LLVM_CXX_NAME=$LLVM_CXX_NAME
export LLVM_LINK_NAME=$LLVM_LINK_NAME
export WLLVM_BC_STORE=/tmp/wllvm-bc-store
exec $WLLVM_BIN -g "\$@"
WEOF

cat > "$WRAPPER_DIR/z-wllvm++" << WEOF
#!/bin/bash
export LLVM_COMPILER=clang
export LLVM_CC_NAME=$LLVM_CC_NAME
export LLVM_CXX_NAME=$LLVM_CXX_NAME
export LLVM_LINK_NAME=$LLVM_LINK_NAME
export WLLVM_BC_STORE=/tmp/wllvm-bc-store
exec $WLLVMPP_BIN -g "\$@"
WEOF

chmod +x "$WRAPPER_DIR/z-wllvm" "$WRAPPER_DIR/z-wllvm++"

# Also create cc/c++/gcc/g++/clang/clang++ symlinks so cmake and other build systems find wllvm
ln -sf "$WRAPPER_DIR/z-wllvm" "$WRAPPER_DIR/cc"
ln -sf "$WRAPPER_DIR/z-wllvm" "$WRAPPER_DIR/gcc"
ln -sf "$WRAPPER_DIR/z-wllvm" "$WRAPPER_DIR/clang"
ln -sf "$WRAPPER_DIR/z-wllvm++" "$WRAPPER_DIR/c++"
ln -sf "$WRAPPER_DIR/z-wllvm++" "$WRAPPER_DIR/g++"
ln -sf "$WRAPPER_DIR/z-wllvm++" "$WRAPPER_DIR/clang++"

# Put wrapper dir at front of PATH so cmake/configure/make all find our wrappers
export PATH="$WRAPPER_DIR:$PATH"

# NOTE: We do NOT replace system compiler binaries — too risky (can cause fork bombs).
# Instead we rely on PATH + CC/CXX + CMAKE overrides, and robust .bc extraction.

# Override compiler env vars that oss-fuzz build.sh uses
export CC="$WRAPPER_DIR/z-wllvm"
export CXX="$WRAPPER_DIR/z-wllvm++"
export CFLAGS="${CFLAGS:-} -O0 -g -fPIC"
export CXXFLAGS="${CXXFLAGS:-} -O0 -g -fPIC"

# CMAKE overrides — critical for cmake-based projects
export CMAKE_C_COMPILER="$WRAPPER_DIR/z-wllvm"
export CMAKE_CXX_COMPILER="$WRAPPER_DIR/z-wllvm++"

# Disable sanitizers (they interfere with bitcode extraction)
export SANITIZER="none"
export SANITIZER_FLAGS=""
export SANITIZER_FLAGS_introspector=""
export SANITIZER_LDFLAGS=""
export COVERAGE_FLAGS=""
export ARCHITECTURE="${ARCHITECTURE:-x86_64}"
export FUZZING_ENGINE="${FUZZING_ENGINE:-libfuzzer}"
export FUZZING_LANGUAGE="${FUZZING_LANGUAGE:-c++}"

# Set up OUT and WORK dirs that oss-fuzz build.sh expects
export OUT="${OUT:-/out}"
export WORK="${WORK:-/tmp/ossfuzz-work}"
mkdir -p "$OUT" "$WORK"

# Create stub fuzzing engine library
log "  Creating stub fuzzing engine..."
echo 'int main(int argc, char **argv){return 0;}' > /tmp/stub_engine.c
$CC -c /tmp/stub_engine.c -o /tmp/stub_engine.o 2>/dev/null || \
    clang -c /tmp/stub_engine.c -o /tmp/stub_engine.o
ar rcs /tmp/libFuzzingEngine.a /tmp/stub_engine.o
export LIB_FUZZING_ENGINE="/tmp/libFuzzingEngine.a"

log "  CC=$CC  CXX=$CXX"

# Set WLLVM_BC_STORE so all bitcode goes to a known directory
export WLLVM_BC_STORE="/tmp/wllvm-bc-store"
mkdir -p "$WLLVM_BC_STORE"

# Pre-build verification: compile a test file and check for bitcode
log "  Verifying wllvm bitcode generation..."
echo 'int z_wllvm_test_func(int x){return x+1;}' > /tmp/z_wllvm_test.c
if $CC -c /tmp/z_wllvm_test.c -o /tmp/z_wllvm_test.o 2>/dev/null; then
    if readelf -S /tmp/z_wllvm_test.o 2>/dev/null | grep -q '\.llvm_bc'; then
        _bc_path=$(readelf -p .llvm_bc /tmp/z_wllvm_test.o 2>/dev/null | grep -oP '\]\s+\K/.*')
        if [ -n "$_bc_path" ] && [ -f "$_bc_path" ]; then
            log "  WLLVM OK: bitcode at $_bc_path"
        else
            log "  WARNING: .llvm_bc section exists but .bc file not found at '$_bc_path'"
            # Try to find it in WLLVM_BC_STORE
            _bc_in_store=$(find "$WLLVM_BC_STORE" -name "*.bc" -type f 2>/dev/null | head -1)
            if [ -n "$_bc_in_store" ]; then
                log "  WLLVM OK: bitcode found in store: $_bc_in_store"
            fi
        fi
    else
        log "  WARNING: wllvm did NOT embed .llvm_bc section in test .o file"
        log "  This means extract-bc will not work. Will use direct .bc search fallback."
    fi
else
    log "  WARNING: wllvm wrapper compilation test FAILED"
fi
rm -f /tmp/z_wllvm_test.c /tmp/z_wllvm_test.o

# ── Step 3: Find and execute build.sh ────────────────────────────────────────

log "=== [3/7] Building project with wllvm ==="

if [ -n "$BUILD_SH_PATH" ] && [ -f "$BUILD_SH_PATH" ]; then
    BUILD_SCRIPT="$BUILD_SH_PATH"
elif [ -f "${SRC}/build.sh" ]; then
    BUILD_SCRIPT="${SRC}/build.sh"
elif [ -f "/src/build.sh" ]; then
    BUILD_SCRIPT="/src/build.sh"
else
    die "No build.sh found"
fi

log "  Using build script: $BUILD_SCRIPT"

# Install libc++ for clang-18 (build.sh often uses -stdlib=libc++)
apt-get install -y -qq libc++-dev libc++abi-dev 2>/dev/null || \
    apt-get install -y -qq "libc++-${WLLVM_LLVM_VER}-dev" "libc++abi-${WLLVM_LLVM_VER}-dev" 2>/dev/null || true

# Remove -stdlib=libc++ from flags if libc++ isn't available (use libstdc++ instead)
if ! echo 'int main(){}' | $CXX -x c++ -stdlib=libc++ - -o /dev/null 2>/dev/null; then
    log "  libc++ not available for wllvm-clang++, stripping -stdlib=libc++ from flags"
    export CXXFLAGS="$(echo "$CXXFLAGS" | sed 's/-stdlib=libc++//g')"
    export LDFLAGS="$(echo "${LDFLAGS:-}" | sed 's/-stdlib=libc++//g')"
fi

# Run build with timeout
# oss-fuzz build.sh scripts expect to run from the project source dir (container WORKDIR)
# Detect: if build.sh starts with cd/pushd, it handles its own directory.
# Otherwise, cd to PROJECT_SRC (like oss-fuzz does).
BUILD_EXIT=0
_build_cwd="$SRC"
if ! head -20 "$BUILD_SCRIPT" | grep -qE '^\s*cd\s|^\s*pushd\s'; then
    _build_cwd="$PROJECT_SRC"
fi
log "  Build working dir: $_build_cwd"
cd "$_build_cwd"
timeout "$MAX_BUILD_TIME" bash "$BUILD_SCRIPT" 2>&1 || BUILD_EXIT=$?

if [ "$BUILD_EXIT" -ne 0 ]; then
    log "WARNING: Build exited with code $BUILD_EXIT (non-fatal, continuing with what we have)"
fi

log "  Build completed (exit=$BUILD_EXIT)"

# ── Step 4: Extract bitcode from all compiled objects ────────────────────────

log "=== [4/7] Extracting bitcode ==="

# Strategy:
#   1. Find .a files ONLY in the project source dir (not fuzzer engines etc.)
#   2. If no .a files, find .o files in the project source dir
#   3. extract-bc each file (only works if compiled with wllvm)
#   4. Validate each .bc with llvm-dis before accepting it

BC_FILES=""
BC_COUNT=0

# Helper: validate a .bc file is real LLVM bitcode (not garbage)
_valid_bc() {
    local bcf="$1"
    [ -f "$bcf" ] || return 1
    local sz=$(stat -c%s "$bcf" 2>/dev/null || echo 0)
    [ "$sz" -gt 100 ] || return 1
    # Quick validate: try llvm-dis to stdout and check first bytes
    head -c 4 "$bcf" | od -A n -t x1 2>/dev/null | grep -q "42 43" && return 0
    # Also accept LLVM IR archives
    file "$bcf" 2>/dev/null | grep -qi "llvm\|bitcode\|LLVM" && return 0
    return 1
}

# 4a: Extract from .a files — search project source, work dir, and common build dirs
_search_dirs="$PROJECT_SRC"
# Add common cmake/build directories
for _sd in "$PROJECT_SRC/build" "$PROJECT_SRC/out" "$WORK" "${SRC}/build" \
           "$PROJECT_SRC/cmake-build" "$PROJECT_SRC/_build" ; do
    [ -d "$_sd" ] && _search_dirs="$_search_dirs $_sd"
done
# Add INSTALL_PREFIX if set
if [ -n "${INSTALL_PREFIX:-}" ] && [ -d "${INSTALL_PREFIX:-}" ]; then
    _search_dirs="$_search_dirs $INSTALL_PREFIX"
fi

STATIC_LIBS=""
for _sd in $_search_dirs; do
    _found=$(find "$_sd" -name "*.a" \
        -not -name "libFuzzingEngine.a" \
        -not -name "libgtest*" \
        -not -path '*/.git/*' \
        -not -path '*/testdata/*' \
        -not -path '*/tests/*' \
        -type f 2>/dev/null | sort -u || true)
    STATIC_LIBS="$STATIC_LIBS $_found"
done

for lib in $STATIC_LIBS; do
    log "  Extracting: $lib"
    _extract_err=$(extract-bc "$lib" 2>&1) || true
    bca="${lib%.a}.bca"
    bc="${lib%.a}.bc"
    if [ -f "$bca" ]; then
        _link_rc=0
        _link_err=$(llvm-link "$bca" -o "$bc" 2>&1) || _link_rc=$?
        if [ "$_link_rc" -eq 0 ] && _valid_bc "$bc"; then
            log "    -> $bc ($(du -h "$bc" 2>/dev/null | cut -f1))"
            BC_FILES="$BC_FILES $bc"
            BC_COUNT=$((BC_COUNT + 1))
        else
            log "    -> llvm-link failed (rc=$_link_rc): $(echo "$_link_err" | tail -1)"
        fi
    elif [ -f "$bc" ] && _valid_bc "$bc"; then
        log "    -> $bc ($(du -h "$bc" 2>/dev/null | cut -f1))"
        BC_FILES="$BC_FILES $bc"
        BC_COUNT=$((BC_COUNT + 1))
    else
        log "    -> extract-bc produced no .bca/.bc: $(echo "$_extract_err" | tail -1)"
    fi
done

# 4b: If no .a files, try .o files in project source + build dirs
if [ "$BC_COUNT" -eq 0 ]; then
    log "  No valid library .bc from .a files, trying .o files..."
    _obj_search_dirs="$PROJECT_SRC"
    for _sd in "$PROJECT_SRC/build" "$WORK" "${SRC}/build" "$PROJECT_SRC/cmake-build"; do
        [ -d "$_sd" ] && _obj_search_dirs="$_obj_search_dirs $_sd"
    done
    for _sd in $_obj_search_dirs; do
        OBJ_FILES=$(find "$_sd" -name "*.o" \
            -not -name "stub*" \
            -not -name "*.test.*" \
            -not -path '*/.git/*' \
            -not -path '*/test*' \
            -type f 2>/dev/null | head -500 || true)
        for obj in $OBJ_FILES; do
            bc="${obj%.o}.bc"
            if extract-bc "$obj" 2>/dev/null && _valid_bc "$bc"; then
                BC_FILES="$BC_FILES $bc"
                BC_COUNT=$((BC_COUNT + 1))
            fi
        done
    done
fi

# 4c: Last resort — check if build.sh produced .o files elsewhere (e.g. $WORK, /tmp)
if [ "$BC_COUNT" -eq 0 ]; then
    log "  No .bc from project .o files, scanning $OUT and $WORK..."
    for search_dir in "$OUT" "$WORK" /tmp; do
        [ -d "$search_dir" ] || continue
        OBJ_FILES=$(find "$search_dir" -name "*.o" -newer /tmp/stub_engine.o \
            -not -name "stub*" \
            -type f 2>/dev/null | head -200 || true)
        for obj in $OBJ_FILES; do
            bc="${obj%.o}.bc"
            if extract-bc "$obj" 2>/dev/null && _valid_bc "$bc"; then
                BC_FILES="$BC_FILES $bc"
                BC_COUNT=$((BC_COUNT + 1))
            fi
        done
    done
fi

# 4d: Direct .bc file search — wllvm stores .bc files as .name.o.bc alongside .o files
#     Also check WLLVM_BC_STORE directory
if [ "$BC_COUNT" -eq 0 ]; then
    log "  Trying direct .bc file search (WLLVM_BC_STORE and build dirs)..."
    _bc_search_dirs="$WLLVM_BC_STORE"
    for _sd in "$PROJECT_SRC" "$WORK" "${SRC}/build" "$PROJECT_SRC/build" \
               "$PROJECT_SRC/cmake-build" "$PROJECT_SRC/_build" "$OUT"; do
        [ -d "$_sd" ] && _bc_search_dirs="$_bc_search_dirs $_sd"
    done
    DIRECT_BC_FILES=""
    DIRECT_BC_COUNT=0
    # First: check WLLVM_BC_STORE which uses hash filenames (no .bc extension)
    if [ -d "$WLLVM_BC_STORE" ]; then
        _store_count=$(ls "$WLLVM_BC_STORE" 2>/dev/null | wc -l)
        log "  WLLVM_BC_STORE has $_store_count files"
        if [ "$_store_count" -gt 0 ]; then
            for bcf in "$WLLVM_BC_STORE"/*; do
                [ -f "$bcf" ] || continue
                _sz=$(stat -c%s "$bcf" 2>/dev/null || echo 0)
                [ "$_sz" -gt 100 ] || continue
                if _valid_bc "$bcf"; then
                    DIRECT_BC_FILES="$DIRECT_BC_FILES $bcf"
                    DIRECT_BC_COUNT=$((DIRECT_BC_COUNT + 1))
                fi
            done
        fi
    fi
    # Second: search build dirs for .bc files (hidden or not)
    for _sd in $_bc_search_dirs; do
        [ "$_sd" = "$WLLVM_BC_STORE" ] && continue  # already searched
        _found=$(find "$_sd" -name "*.bc" -type f -size +100c \
            -not -name "library.bc" -not -name "stub*" \
            2>/dev/null | head -1000 || true)
        for bcf in $_found; do
            if _valid_bc "$bcf"; then
                DIRECT_BC_FILES="$DIRECT_BC_FILES $bcf"
                DIRECT_BC_COUNT=$((DIRECT_BC_COUNT + 1))
            fi
        done
    done
    if [ "$DIRECT_BC_COUNT" -gt 0 ]; then
        log "  Found $DIRECT_BC_COUNT direct .bc files"
        BC_FILES="$DIRECT_BC_FILES"
        BC_COUNT="$DIRECT_BC_COUNT"
    fi
fi

log "  Total valid .bc files found: $BC_COUNT"

if [ "$BC_COUNT" -eq 0 ]; then
    # Last diagnostic: show what files exist
    log "  DIAGNOSTIC: .o files in project/work dirs:"
    find "$PROJECT_SRC" "$WORK" -name "*.o" -type f 2>/dev/null | head -5 | while read f; do
        _has_sec=$(readelf -S "$f" 2>/dev/null | grep -c '\.llvm_bc' || echo 0)
        log "    $f (llvm_bc=$_has_sec)"
    done
    log "  DIAGNOSTIC: .bc files anywhere:"
    find /src /work /tmp /out -name "*.bc" -type f 2>/dev/null | head -10 | while read f; do
        log "    $f ($(stat -c%s "$f" 2>/dev/null || echo '?') bytes)"
    done
    die "No bitcode files extracted. Build may not have produced objects with wllvm."
fi

# ── Step 5: Link all bitcode into library.bc ─────────────────────────────────

log "=== [5/7] Linking library bitcode ==="

if [ "$BC_COUNT" -eq 1 ]; then
    cp $BC_FILES "$OUTPUT_DIR/library.bc"
else
    # Try batch link first (fastest)
    if llvm-link --suppress-warnings $BC_FILES -o "$OUTPUT_DIR/library.bc" 2>/dev/null; then
        log "  Batch link succeeded"
    elif llvm-link $BC_FILES -o "$OUTPUT_DIR/library.bc" 2>&1; then
        log "  Batch link succeeded (with warnings)"
    else
        # Fallback: incremental link, skip conflicting files
        log "  Batch link failed, trying incremental link..."
        FIRST=1
        LINKED=0
        for bc in $BC_FILES; do
            if [ "$FIRST" -eq 1 ]; then
                cp "$bc" "$OUTPUT_DIR/library.bc"
                FIRST=0
                LINKED=1
            else
                cp "$OUTPUT_DIR/library.bc" "$OUTPUT_DIR/library.bc.prev"
                if llvm-link --suppress-warnings "$OUTPUT_DIR/library.bc.prev" "$bc" \
                        -o "$OUTPUT_DIR/library.bc" 2>/dev/null; then
                    LINKED=$((LINKED + 1))
                else
                    log "    Skipped (link conflict): $(basename $bc)"
                    cp "$OUTPUT_DIR/library.bc.prev" "$OUTPUT_DIR/library.bc"
                fi
                rm -f "$OUTPUT_DIR/library.bc.prev"
            fi
        done
        log "  Incremental link: $LINKED/$BC_COUNT files linked"
    fi
fi

# Validate the final library.bc
if ! _valid_bc "$OUTPUT_DIR/library.bc"; then
    die "library.bc is not valid LLVM bitcode"
fi

BC_SIZE=$(du -h "$OUTPUT_DIR/library.bc" 2>/dev/null | cut -f1)
log "  library.bc: $BC_SIZE"

# ── Step 6: Disassemble to .ll for metadata extraction ───────────────────────

log "=== [6/7] Disassembling to .ll ==="

if llvm-dis "$OUTPUT_DIR/library.bc" -o "$OUTPUT_DIR/library.ll" 2>&1; then
    LL_SIZE=$(du -h "$OUTPUT_DIR/library.ll" 2>/dev/null | cut -f1)
    log "  library.ll: $LL_SIZE"
else
    log "  WARNING: llvm-dis failed (metadata will be limited)"
    touch "$OUTPUT_DIR/library.ll"
fi

# ── Step 7: Collect fuzzer sources ───────────────────────────────────────────

log "=== [7/7] Collecting fuzzer sources ==="

FUZZER_OUT="$OUTPUT_DIR/fuzzer_sources"
mkdir -p "$FUZZER_OUT"

# Collect from $OUT (compiled fuzzers) — filter out shared libs and non-fuzzer files
FUZZER_BINARIES=$(find "$OUT" -maxdepth 1 -type f -executable \
    ! -name "*.so" ! -name "*.so.*" ! -name "*.a" ! -name "*.o" \
    ! -name "*.py" ! -name "*.sh" ! -name "*.dict" ! -name "*.zip" \
    ! -name "*.options" ! -name "*.cfg" ! -name "*.txt" \
    2>/dev/null || true)
FUZZER_COUNT=0
for f in $FUZZER_BINARIES; do
    FUZZER_COUNT=$((FUZZER_COUNT + 1))
done
log "  Fuzzer binaries in \$OUT: $FUZZER_COUNT"

# Find fuzzer source files — search $SRC subdirectories but SKIP known
# fuzzing framework directories (centipede, aflplusplus, fuzztest, honggfuzz,
# libfuzzer, fuzzing-headers, etc.) that also define LLVMFuzzerTestOneInput.
FUZZER_SOURCES=""
_framework_re="^(aflplusplus|honggfuzz|fuzztest|centipede|libfuzzer|fuzzing-headers|libprotobuf-mutator|FuzzedDataProvider)$"

# 1. Search each $SRC subdirectory, skipping framework dirs
for _d in "$SRC"/*/; do
    [ -d "$_d" ] || continue
    _dirname=$(basename "$_d")
    echo "$_dirname" | grep -qiE "$_framework_re" && continue
    _found=$(grep -rl "LLVMFuzzerTestOneInput" "$_d" \
        --include="*.c" --include="*.cc" --include="*.cpp" --include="*.cxx" \
        2>/dev/null | head -50 || true)
    [ -n "$_found" ] && FUZZER_SOURCES=$(printf '%s\n%s' "$FUZZER_SOURCES" "$_found")
done

# 2. Check top-level $SRC files (many build.sh scripts put fuzzers directly in $SRC/)
for _ext in c cc cpp cxx; do
    for _f in "$SRC"/*."$_ext"; do
        [ -f "$_f" ] || continue
        grep -q "LLVMFuzzerTestOneInput" "$_f" 2>/dev/null && \
            FUZZER_SOURCES=$(printf '%s\n%s' "$FUZZER_SOURCES" "$_f")
    done
done

for src in $FUZZER_SOURCES; do
    [ -f "$src" ] && cp "$src" "$FUZZER_OUT/" 2>/dev/null || true
done

FUZZER_SRC_COUNT=$(ls "$FUZZER_OUT" 2>/dev/null | wc -l)
log "  Fuzzer source files collected: $FUZZER_SRC_COUNT"

# ── Write metadata ───────────────────────────────────────────────────────────

PIPELINE_END=$(date +%s)
PIPELINE_DURATION=$((PIPELINE_END - PIPELINE_START))

# Write list of fuzzer binary names (already filtered by find above)
echo "" > "$OUTPUT_DIR/fuzzer_names.txt"
for f in $FUZZER_BINARIES; do
    fname=$(basename "$f")
    echo "$fname" >> "$OUTPUT_DIR/fuzzer_names.txt"
done

# Write build metadata
cat > "$OUTPUT_DIR/metadata.json" << METAEOF
{
    "project_name": "$PROJECT_NAME",
    "bc_count": $BC_COUNT,
    "bc_size": "$(stat -c%s "$OUTPUT_DIR/library.bc" 2>/dev/null || echo 0)",
    "fuzzer_binary_count": $FUZZER_COUNT,
    "fuzzer_source_count": $FUZZER_SRC_COUNT,
    "build_exit_code": $BUILD_EXIT,
    "pipeline_duration_sec": $PIPELINE_DURATION,
    "llvm_version": "$WLLVM_LLVM_VER"
}
METAEOF

log ""
log "================================================================"
log " SUCCESS: ${PROJECT_NAME}"
log "   library.bc: $BC_SIZE"
log "   Fuzzers: $FUZZER_COUNT binaries, $FUZZER_SRC_COUNT sources"
log "   Duration: ${PIPELINE_DURATION}s"
log "================================================================"
