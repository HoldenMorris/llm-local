#!/bin/bash

# ==============================================================================
# URL Verdict Benchmark
# Runs a labeled corpus of URLs through url-analyze.sh for each engine and
# compares accuracy vs speed. "none" = no model, just the verdict.sh
# decision table (the "good-guess if-then matrix"). Every other engine is an
# Ollama model. The page is fetched once per URL and cached, so comparing N
# models costs one fetch, not N.
#
# Usage:  ./url-benchmark.sh [model ...]        (default: gemma2:2b)
#         ./url-benchmark.sh gemma2:2b minicpm4.1:8b
#         CORPUS=my-urls.txt ./url-benchmark.sh
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS="${CORPUS:-$SCRIPT_DIR/url-corpus.txt}"
RESULTS_DIR="$SCRIPT_DIR/results"
ANALYZE="$SCRIPT_DIR/url-analyze.sh"

# -c mono disables color (see colors.sh); strip it before the rest become model names.
[ "$1" = "-c" ] && { [ "$2" = mono ] && MONO=1; shift 2; }
source "$SCRIPT_DIR/colors.sh"

[ -f "$CORPUS" ] || { echo "Corpus not found: $CORPUS"; exit 1; }

# Engines: "none" (heuristic baseline) first, then the models given (default gemma2:2b).
ENGINES=("none" "${@:-gemma2:2b}")

# Read corpus into parallel arrays (skip blanks/comments).
EXP=() URLS=()
while read -r verdict url _; do
    [[ -z "$verdict" || "$verdict" == \#* ]] && continue
    EXP+=("$verdict"); URLS+=("$url")
done < "$CORPUS"
[ ${#URLS[@]} -gt 0 ] || { echo "No URLs in corpus."; exit 1; }

echo "${BOLD}${CYAN}=============================================="
echo "URL VERDICT BENCHMARK"
echo "==============================================${RESET}"
echo "Corpus:   $CORPUS  (${#URLS[@]} urls)"
echo "Engines:  ${ENGINES[*]}"
echo "Date:     $(date '+%Y-%m-%d %H:%M:%S')"
echo "=============================================="

# Pull the final banner verdict; normalize empty/UNCLEAR to a SAFE guess so the
# the baseline competes as a real 3-way classifier (nothing fired -> guess SAFE).
parse_verdict() {
    local v
    v=$(grep -oE 'VERDICT:[[:space:]]*(SAFE|SUSPICIOUS|DANGEROUS|UNCLEAR)' | tail -1 | grep -oE '(SAFE|SUSPICIOUS|DANGEROUS|UNCLEAR)')
    [ -z "$v" ] || [ "$v" = UNCLEAR ] && v=SAFE
    echo "$v"
}

declare -A CORRECT TIME
for e in "${ENGINES[@]}"; do CORRECT["$e"]=0; TIME["$e"]="0"; done

for i in "${!URLS[@]}"; do
    url="${URLS[$i]}"; expected="${EXP[$i]}"
    echo ""
    echo "-- $url  (expect $expected)"
    # Warm the cache once (fetch + screenshot + domain meta) so per-engine timing
    # measures the verdict step, not the shared fetch.
    "$ANALYZE" -H "$url" </dev/null >/dev/null 2>&1

    for e in "${ENGINES[@]}"; do
        [ "$e" = none ] && FLAGS=(-H) || FLAGS=(-m "$e")
        START=$(date +%s.%N)
        OUT=$("$ANALYZE" "${FLAGS[@]}" "$url" </dev/null 2>/dev/null)
        DUR=$(echo "$(date +%s.%N) - $START" | bc)
        got=$(printf '%s' "$OUT" | parse_verdict)
        if [ "$got" = "$expected" ]; then mark="${GREEN}[+]${RESET}"; ((CORRECT["$e"]++)); else mark="${RED}[-]${RESET}"; fi
        TIME["$e"]=$(echo "${TIME[$e]} + $DUR" | bc)
        printf "   %s %-22s -> %-10s (%.1fs)\n" "$mark" "$e" "$got" "$DUR"
    done
done

N=${#URLS[@]}
TS=$(date '+%Y-%m-%d %H:%M:%S')
CSV="$RESULTS_DIR/url_benchmark.csv"
mkdir -p "$RESULTS_DIR"
[ -f "$CSV" ] || echo "timestamp,engine,total,correct,accuracy,avg_time" > "$CSV"

echo ""
echo "${BOLD}${CYAN}=============================================="
echo "MATRIX  (accuracy vs avg time, $N urls)"
echo "==============================================${RESET}"
printf "   %-22s %-8s %-9s %s\n" "ENGINE" "ACC" "CORRECT" "AVG_TIME"
for e in "${ENGINES[@]}"; do
    c=${CORRECT["$e"]}
    acc=$(echo "scale=0; $c * 100 / $N" | bc)
    avg=$(echo "scale=2; ${TIME[$e]} / $N" | bc)
    printf "   %-22s %-8s %-9s %ss\n" "$e" "${acc}%" "$c/$N" "$avg"
    echo "$TS,$e,$N,$c,${acc}%,${avg}s" >> "$CSV"
done
echo "=============================================="
echo "Saved to: $CSV"
