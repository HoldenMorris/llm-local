#!/bin/bash

# Deobfuscate JavaScript with webcrack, inside a locked-down container.
# webcrack does STATIC AST analysis -- it never executes the input -- but we sandbox it
# anyway (--network none, all caps dropped, read-only rootfs) as defence in depth, since
# the input is attacker-controlled page JS.
#
# Usage:  ./js-deobfuscate.sh <file.js>      # or:  cat file.js | ./js-deobfuscate.sh
# Output: deobfuscated JS on stdout. On failure/timeout, prints the ORIGINAL unchanged and
#         exits non-zero, so callers can still scan something and degrade gracefully.

set -u
IMAGE="local-llm-webcrack"
WEBCRACK_VER="2.16.0"

IN="${1:-}"
TMP=""
trap '[ -n "$TMP" ] && rm -f "$TMP"' EXIT
if [ -z "$IN" ] || [ "$IN" = "-" ]; then
    TMP="$(mktemp --suffix=.js)"; cat > "$TMP"; IN="$TMP"
fi
[ -f "$IN" ] || { echo "js-deobfuscate: no such file: $IN" >&2; exit 2; }

# Build the sandbox image once (like page-fetch pulls the puppeteer image).
if ! docker image inspect "$IMAGE" &>/dev/null; then
    echo "Building $IMAGE (first run, ~1 min)..." >&2
    docker build -q -t "$IMAGE" - >/dev/null <<EOF
FROM node:22-alpine
RUN npm i -g webcrack@${WEBCRACK_VER}
EOF
fi

INDIR="$(cd "$(dirname "$IN")" && pwd)"
INFILE="$(basename "$IN")"
OUT=$(timeout 60 docker run --rm \
    --network none --cap-drop ALL --security-opt no-new-privileges \
    --memory 1g --cpus 1 --read-only --tmpfs /tmp -w /tmp \
    -v "$INDIR/$INFILE":/in/script.js:ro \
    "$IMAGE" webcrack /in/script.js 2>/dev/null)
RC=$?

# Degrade gracefully: emit the original so callers still have text to scan.
if [ "$RC" -ne 0 ] || [ -z "$OUT" ]; then
    cat "$IN" 2>/dev/null
    exit 1
fi
printf '%s\n' "$OUT"
