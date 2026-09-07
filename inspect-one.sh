#!/usr/bin/env bash
#
# Run the deep inspection on ONE url and print what it found.
#
# inspect.sh holds the prompt and the parsers, but it is a library you source, and both its callers
# weave the result into a conversation with a person at a terminal — the `i` branch of
# url-analyze.sh and the Skip resolution in next-alert.sh. The web worker needs the same inspection
# as a plain command with a plain answer, and the alternative was a third copy of the prompt.
#
#   ./inspect-one.sh <url>
#
# Reads only the CACHED artifacts of that url's scan: read-only tools, no live fetch. The arguments
# deep_inspect wants (the landed url, the machine verdict, the smells, the host) all come out of
# `verdict.json`, which is exactly what that file was added for — before it, this script would have
# had to re-derive them or scrape the banner.
#
# Exits 1 when there is nothing cached to read, because an inspection of no artifacts is not an
# inspection, it is a guess with a citation.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source "$SCRIPT_DIR/colors.sh"
source "$SCRIPT_DIR/inspect.sh"

URL="${1:?usage: $0 <url>}"
CACHE_DIR="$SCRIPT_DIR/.cache/$(printf '%s' "$URL" | sha256sum | cut -c1-16)"

[ -d "$CACHE_DIR" ] || { echo_red "no cached scan for this url -- scan it first"; exit 1; }

V="$CACHE_DIR/verdict.json"
if [ -s "$V" ]; then
    LANDED=$(jq -r '.final_url // .url // ""' "$V")
    VERDICT=$(jq -r '.verdict // ""' "$V")
    HOST=$(jq -r '.host // ""' "$V")
    SMELLS=$(jq -r '(.smells // []) | join(", ")' "$V")
else
    # A scan older than verdict.json still has its page.json, so the inspection can still run --
    # with less context, which is the honest degradation rather than a refusal.
    echo_grey "no verdict.json (scan predates it) -- inspecting from page.json alone"
    LANDED=$(jq -r '.finalUrl // ""' "$CACHE_DIR/page.json" 2>/dev/null)
    VERDICT=""
    HOST=$(jq -r '.domain // ""' "$CACHE_DIR/page.json" 2>/dev/null)
    SMELLS=$(jq -r '(.phishingSmells // []) | join(", ")' "$CACHE_DIR/page.json" 2>/dev/null)
fi

echo_grey "reading the cached artifacts of $URL ..."
OUT=$(deep_inspect "$URL" "${LANDED:-$URL}" "$VERDICT" "$SMELLS" "$CACHE_DIR" "$HOST" 2>&1)
[ -n "$OUT" ] || { echo_red "the inspection returned nothing (is 'claude' on PATH?)"; exit 1; }

printf '%s\n' "$OUT"
