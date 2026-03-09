#!/bin/bash
# Rebuild Docker images for projects that need re-running
set -u

OSSFUZZ="/data2/ze/poc-workspace/oss-fuzz"
PROJECTS=(
    bloaty boringssl brotli capstone casync clamav curl dav1d dropbear
    envoy expat ffmpeg giflib gnutls gstreamer
    freetype2 gdal git glib gnupg graphicsmagick
)

echo "Rebuilding ${#PROJECTS[@]} Docker images..."
OK=0
FAIL=0

for p in "${PROJECTS[@]}"; do
    img="gcr.io/oss-fuzz/$p"
    if docker image inspect "$img" &>/dev/null; then
        echo "[$p] Already exists, skipping"
        OK=$((OK + 1))
        continue
    fi
    echo "[$p] Building..."
    if cd "$OSSFUZZ" && python3 infra/helper.py build_image "$p" --no-pull 2>&1 | tail -5; then
        if docker image inspect "$img" &>/dev/null; then
            echo "[$p] OK"
            OK=$((OK + 1))
        else
            echo "[$p] FAILED (image not created)"
            FAIL=$((FAIL + 1))
        fi
    else
        echo "[$p] FAILED (build error)"
        FAIL=$((FAIL + 1))
    fi
done

echo ""
echo "Done: OK=$OK FAIL=$FAIL"
