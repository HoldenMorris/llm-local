#!/bin/bash

# Mine analyst feedback (url-analyze.sh's "Do you agree?" prompt) into a review report.
# Reads every .cache/*/feedback.txt (TSV: timestamp <TAB> verdict <TAB> state <TAB> url [<TAB> note])
# where state is agree|disagree|skip|flag|inspected.
#   ./feedback-report.sh              # human report
#   ./feedback-report.sh -f           # just the OPEN flagged URLs, one per line (a worklist)
#   ./feedback-report.sh -i <url> <note>   # record a deep inspection; closes the flag
#   ./feedback-report.sh -c mono      # no color
#   ./feedback-report.sh --self-test  # exercise the state logic, no real cache touched
#
# Rows are append-only: an inspection never rewrites the flag it closes. The LATEST row for a URL
# is its current state, so an `inspected` row supersedes an open `flag` while both stay in the
# history. That keeps "what did we think at the time" auditable, which a mutating flag would lose.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ "$1" = "-c" ] && [ "$2" = "mono" ] && { MONO=1; shift 2; }
FLAGS_ONLY=""; [ "$1" = "-f" ] && { FLAGS_ONLY=1; shift; }
INSPECT="";    [ "$1" = "-i" ] && { INSPECT=1; shift; }
SELFTEST="";   [ "$1" = "--self-test" ] && { SELFTEST=1; shift; }
source "$SCRIPT_DIR/colors.sh"

# Overridable so --self-test can point at a throwaway tree instead of the real cache.
FB_ROOT="${FB_ROOT:-$SCRIPT_DIR/.cache}"

# _fb_dir <url> -> the cache dir for a URL (same sha256 prefix url-analyze.sh uses).
_fb_dir() { printf '%s/%s' "$FB_ROOT" "$(printf '%s' "$1" | sha256sum | cut -c1-16)"; }

# --self-test: the "latest row wins" rule is the whole contract here (an inspection must close a
# flag, a re-flag after an inspection must re-open it), so pin it against a throwaway tree.
if [ -n "$SELFTEST" ]; then
    _t=$(mktemp -d); trap 'rm -rf "$_t"' EXIT
    _row() { local d; d=$(FB_ROOT="$_t" _fb_dir "$1"); mkdir -p "$d"; shift
             printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "${5:-}" >> "$d/feedback.txt"; }
    _row https://open.example   2026-01-01T00:00:00Z SUSPICIOUS flag      https://open.example
    _row https://closed.example 2026-01-01T00:00:00Z SUSPICIOUS flag      https://closed.example
    _row https://closed.example 2026-01-02T00:00:00Z SUSPICIOUS inspected https://closed.example "false positive, brand verified"
    _row https://requeued.example 2026-01-01T00:00:00Z SAFE      flag      https://requeued.example
    _row https://requeued.example 2026-01-02T00:00:00Z SAFE      inspected https://requeued.example "looked ok"
    _row https://requeued.example 2026-01-03T00:00:00Z SAFE      flag      https://requeued.example
    _got=$(FB_ROOT="$_t" NO_COLOR=1 "$0" -f | sort | tr '\n' ' ')
    _want="https://open.example https://requeued.example "
    _fails=0
    [ "$_got" = "$_want" ] || { echo "FAIL -f open flags: want [$_want] got [$_got]"; _fails=1; }
    _rep=$(FB_ROOT="$_t" NO_COLOR=1 "$0")
    printf '%s' "$_rep" | grep -q 'open flags 2' || { echo "FAIL open-flag count"; _fails=1; }
    printf '%s' "$_rep" | grep -q 'inspected 1'  || { echo "FAIL inspected count"; _fails=1; }
    printf '%s' "$_rep" | grep -q 'false positive, brand verified' || { echo "FAIL note not shown"; _fails=1; }
    # -i on an unscanned URL must refuse rather than invent a cache dir
    FB_ROOT="$_t" "$0" -i https://never.scanned "note" >/dev/null 2>&1 \
        && { echo "FAIL -i accepted an unscanned URL"; _fails=1; }
    [ "$_fails" -eq 0 ] && echo "self-test: OK" || echo "self-test: FAILED"
    exit "$_fails"
fi

# -i <url> <note...>: append an `inspected` row carrying what the inspection concluded. The
# verdict column repeats the verdict that was inspected, so the row is readable on its own.
if [ -n "$INSPECT" ]; then
    _url="$1"; shift; _note="$*"
    if [ -z "$_url" ] || [ -z "$_note" ]; then
        echo "usage: $0 -i <url> <note>" >&2; exit 2
    fi
    _d=$(_fb_dir "$_url")
    if [ ! -d "$_d" ]; then
        echo_yellow "no scan cached for $_url -- scan it before recording an inspection"; exit 1
    fi
    _v=$(awk -F'\t' 'NF>=4 { v=$2 } END { print (v ? v : "?") }' "$_d/feedback.txt" 2>/dev/null)
    # tabs/newlines would break the TSV, so flatten them into spaces
    printf '%s\t%s\tinspected\t%s\t%s\n' "$(date -u +%FT%TZ)" "${_v:-?}" "$_url" \
        "$(printf '%s' "$_note" | tr '\t\n' '  ')" >> "$_d/feedback.txt"
    echo_green "inspected: $_url"
    exit 0
fi

shopt -s nullglob
FILES=("$FB_ROOT"/*/feedback.txt)
if [ ${#FILES[@]} -eq 0 ]; then
    [ -n "$FLAGS_ONLY" ] && exit 0
    echo_grey "No feedback yet ($FB_ROOT/*/feedback.txt empty)."; exit 0
fi

# -f: bare URL list of OPEN flags only, newest first, deduped -- meant to be piped or pasted, so
# no color and no headings even on a terminal. sort -r puts the newest row for each URL first
# (ISO-8601 sorts chronologically), so the first row seen per URL is its current state: print it
# only if that state is still `flag`. An inspected URL therefore drops off the worklist by itself.
if [ -n "$FLAGS_ONLY" ]; then
    cat "${FILES[@]}" | awk -F'\t' 'NF>=4 { print $1"\t"$3"\t"$4 }' \
        | sort -r | awk -F'\t' '!seen[$3]++ && $2=="flag" { print $3 }'
    exit 0
fi

# sort: chronological, so "last row wins" below is genuinely the latest state per URL.
cat "${FILES[@]}" | sort | awk -F'\t' -v R="$RED" -v G="$GREEN" -v Y="$YELLOW" -v C="$CYAN" -v GY="$GREY" -v B="$BOLD" -v X="$RESET" '
NF < 4 { next }
{ tot++; v=$2; fb=$3; u=$4
  seen[v]++
  if (fb=="agree")         { agree++; aV[v]++ }
  else if (fb=="disagree") { dis[v]++; disN++; DL[disN]=$1" "v" "u }
  # flag = "needs a deeper look", not a verdict judgement: kept OUT of the agree/disagree rate so
  # it can neither inflate nor depress the measured accuracy. Same for inspected.
  # (No apostrophes in here -- the whole awk program is inside single quotes.)
  else if (fb=="flag" || fb=="inspected") { }
  else                     { skipN++ }
  # current state per URL: last row wins (input is sorted chronologically)
  state[u]=fb; when[u]=$1; verd[u]=v; note[u]=(NF>=5 ? $5 : "")
  if (!(u in ord)) { ord[u]= ++nURL; URLS[nURL]=u }
}
END {
  if (tot==0) { print GY "No parseable feedback rows." X; exit }
  openN=0; inspN=0
  for (i=1;i<=nURL;i++) { u=URLS[i]
    if (state[u]=="flag")      { openN++;  OP[openN]=when[u]" "verd[u]" "u }
    if (state[u]=="inspected") { inspN++;  IN[inspN]=when[u]" "verd[u]" "u"\n      " note[u] }
  }
  printf "%s%s== Analyst feedback: %d responses ==%s\n", B, C, tot, X
  printf "  %sagree %d   disagree %d   skip %d   open flags %d   inspected %d%s\n\n", GY, agree+0, disN+0, skipN+0, openN, inspN, X
  print B "Agreement by verdict" X
  for (v in seen) {
    scored = aV[v]+dis[v]        # skips/flags excluded from the rate
    rate = scored ? (100*aV[v]/scored) : 0
    col = (dis[v] ? Y : G)
    printf "  %s%-10s%s %s%3d%%%s agree  (%d agree, %d disagree, %d total)\n", B, v, X, col, rate, X, aV[v]+0, dis[v]+0, seen[v]
  }
  if (disN) {
    printf "\n%s%sDisagreements (retune these)%s\n", B, R, X
    for (i=1;i<=disN;i++) print "  " R "x" X " " DL[i]
  }
  if (openN) {
    printf "\n%s%sOpen flags -- awaiting deeper inspection%s %s(./feedback-report.sh -f for a bare URL list)%s\n", B, Y, X, GY, X
    for (i=1;i<=openN;i++) print "  " Y "?" X " " OP[i]
  }
  if (inspN) {
    printf "\n%s%sInspected%s %s(flag closed; note is what the inspection found)%s\n", B, G, X, GY, X
    for (i=1;i<=inspN;i++) print "  " G "*" X " " IN[i]
  }
}'
