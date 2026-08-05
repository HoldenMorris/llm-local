#!/bin/bash

# Mine analyst feedback (url-analyze.sh's "Do you agree?" prompt) into a review report.
# Reads every .cache/*/feedback.txt
# (TSV: timestamp <TAB> verdict <TAB> state <TAB> url [<TAB> note [<TAB> category]])
# where state is agree|disagree|skip|flag|inspected (judgement) or gone|alive (liveness).
#   ./feedback-report.sh              # human report
#   ./feedback-report.sh -f           # just the OPEN flagged URLs, one per line (a worklist)
#   ./feedback-report.sh -i <url> <note>   # record a deep inspection; closes the flag
#   ./feedback-report.sh --corpus     # labeled corpus of every settled LIVE url, for url-benchmark.sh
#   ./feedback-report.sh --host <host> [exclude-url]   # what we already know about this exact host
#   ./feedback-report.sh --apex <apex> [exclude-url]   # ... widened to every host under one domain
#   ./feedback-report.sh -c mono      # no color
#   ./feedback-report.sh --self-test  # exercise the state logic, no real cache touched
#
# Rows are append-only: an inspection never rewrites the flag it closes. The LATEST row for a URL
# is its current state, so an `inspected` row supersedes an open `flag` while both stay in the
# history. That keeps "what did we think at the time" auditable, which a mutating flag would lose.
#
# Liveness (gone/alive, written by url-analyze.sh when a fetch fails or recovers) is a SEPARATE
# axis from judgement: a phishing URL that dies must drop out of the replay corpus, but it must not
# take its hard-won inspected label with it, and it must not fall off the -f worklist either --
# the cached page.json and screenshot are still there to inspect.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ "$1" = "-c" ] && [ "$2" = "mono" ] && { MONO=1; shift 2; }
FLAGS_ONLY=""; [ "$1" = "-f" ] && { FLAGS_ONLY=1; shift; }
INSPECT="";    [ "$1" = "-i" ] && { INSPECT=1; shift; }
CORPUS="";     [ "$1" = "--corpus" ] && { CORPUS=1; shift; }
HOSTQ="";      [ "$1" = "--host" ] && { HOSTQ=1; shift; }
APEXQ="";      [ "$1" = "--apex" ] && { APEXQ=1; shift; }
SELFTEST="";   [ "$1" = "--self-test" ] && { SELFTEST=1; shift; }
source "$SCRIPT_DIR/colors.sh"
source "$SCRIPT_DIR/verdict.sh"   # VERDICT_CATEGORIES / is_category: the ledger owns no vocabulary of its own

# Overridable so --self-test can point at a throwaway tree instead of the real cache.
FB_ROOT="${FB_ROOT:-$SCRIPT_DIR/.cache}"

# _fb_dir <url> -> the cache dir for a URL (same sha256 prefix url-analyze.sh uses).
_fb_dir() { printf '%s/%s' "$FB_ROOT" "$(printf '%s' "$1" | sha256sum | cut -c1-16)"; }

# --self-test: the "latest row wins" rule is the whole contract here (an inspection must close a
# flag, a re-flag after an inspection must re-open it), so pin it against a throwaway tree.
if [ -n "$SELFTEST" ]; then
    _t=$(mktemp -d); trap 'rm -rf "$_t"' EXIT
    _row() { local d; d=$(FB_ROOT="$_t" _fb_dir "$1"); mkdir -p "$d"; shift
             printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "${5:-}" "${6:-}" >> "$d/feedback.txt"; }
    _row https://open.example   2026-01-01T00:00:00Z SUSPICIOUS flag      https://open.example
    _row https://closed.example 2026-01-01T00:00:00Z SUSPICIOUS flag      https://closed.example
    _row https://closed.example 2026-01-02T00:00:00Z SUSPICIOUS inspected https://closed.example "false positive, brand verified"
    _row https://requeued.example 2026-01-01T00:00:00Z SAFE      flag      https://requeued.example
    _row https://requeued.example 2026-01-02T00:00:00Z SAFE      inspected https://requeued.example "looked ok"
    _row https://requeued.example 2026-01-03T00:00:00Z SAFE      flag      https://requeued.example
    # liveness: dead.example died, revived.example came back, agreed.example was never judged deeper
    _row https://agreed.example  2026-01-01T00:00:00Z SAFE      agree     https://agreed.example
    _row https://dead.example    2026-01-01T00:00:00Z DANGEROUS inspected https://dead.example "credential harvester"
    _row https://dead.example    2026-01-02T00:00:00Z ?         gone      https://dead.example
    _row https://revived.example 2026-01-01T00:00:00Z DANGEROUS inspected https://revived.example "kit"
    _row https://revived.example 2026-01-02T00:00:00Z ?         gone      https://revived.example
    _row https://revived.example 2026-01-03T00:00:00Z ?         alive     https://revived.example
    # same host, different paths -- the --host rollup; plus two tenants on one multi-tenant apex
    _row https://kit.example/login  2026-01-01T00:00:00Z DANGEROUS  inspected https://kit.example/login "harvester" phishing
    _row https://kit.example/verify 2026-01-01T00:00:00Z SUSPICIOUS agree     https://kit.example/verify
    _row https://a.pages.dev/x      2026-01-01T00:00:00Z DANGEROUS  inspected https://a.pages.dev/x "kit"
    _got=$(FB_ROOT="$_t" NO_COLOR=1 "$0" -f | sort | tr '\n' ' ')
    _want="https://open.example https://requeued.example "
    _fails=0
    [ "$_got" = "$_want" ] || { echo "FAIL -f open flags: want [$_want] got [$_got]"; _fails=1; }
    _rep=$(FB_ROOT="$_t" NO_COLOR=1 "$0")
    printf '%s' "$_rep" | grep -q 'open flags 2' || { echo "FAIL open-flag count"; _fails=1; }
    printf '%s' "$_rep" | grep -q "inspected 5"  || { echo "FAIL inspected count"; _fails=1; }
    # gone/alive are liveness, not responses: only dead.example is still down, and neither state
    # may leak into the agree/disagree tallies
    printf '%s' "$_rep" | grep -q 'gone 1'       || { echo "FAIL gone count"; _fails=1; }
    printf '%s' "$_rep" | grep -q "12 responses"  || { echo "FAIL liveness rows counted as responses"; _fails=1; }
    printf '%s' "$_rep" | grep -q 'false positive, brand verified' || { echo "FAIL note not shown"; _fails=1; }
    # -i on an unscanned URL must refuse rather than invent a cache dir
    FB_ROOT="$_t" "$0" -i https://never.scanned "note" >/dev/null 2>&1 \
        && { echo "FAIL -i accepted an unscanned URL"; _fails=1; }
    # FB_VERDICT is what a re-scan reports, so pin that -i writes it (and rejects junk)
    FB_ROOT="$_t" FB_VERDICT=DANGEROUS "$0" -i https://open.example "claude: credential harvester" >/dev/null
    grep -q "DANGEROUS	inspected" "$(FB_ROOT="$_t" _fb_dir https://open.example)/feedback.txt" \
        || { echo "FAIL FB_VERDICT not recorded"; _fails=1; }
    FB_ROOT="$_t" FB_VERDICT=NONSENSE "$0" -i https://open.example "note" >/dev/null 2>&1 \
        && { echo "FAIL -i accepted a junk FB_VERDICT"; _fails=1; }
    # --corpus: settled + live only. open/requeued = re-opened flags, dead = gone, revived = back.
    # (open.example was just inspected DANGEROUS above, so it is settled and belongs in the corpus.)
    _got=$(FB_ROOT="$_t" NO_COLOR=1 "$0" --corpus | grep -v '^#' | sort | tr '\n' '|')
    _want="DANGEROUS https://a.pages.dev/x|DANGEROUS https://kit.example/login phishing|DANGEROUS https://open.example|DANGEROUS https://revived.example|SAFE https://agreed.example|SUSPICIOUS https://closed.example|SUSPICIOUS https://kit.example/verify|"
    [ "$_got" = "$_want" ] || { echo "FAIL --corpus: want [$_want] got [$_got]"; _fails=1; }
    # --host: other settled urls on the SAME host, the queried url itself excluded
    _got=$(FB_ROOT="$_t" NO_COLOR=1 "$0" --host kit.example https://kit.example/verify | tr '\t' ' ')
    _want="DANGEROUS inspected https://kit.example/login harvester phishing"
    [ "$_got" = "$_want" ] || { echo "FAIL --host: want [$_want] got [$_got]"; _fails=1; }
    # a multi-tenant apex confers nothing: one tenant's kit must not reach the next tenant
    [ -z "$(FB_ROOT="$_t" NO_COLOR=1 "$0" --host b.pages.dev)" ] \
        || { echo "FAIL --host leaked across tenants of a multi-tenant apex"; _fails=1; }
    # --apex: siblings under one registrable domain, matched on a label boundary only
    _row https://a.kit.example/x 2026-01-01T00:00:00Z DANGEROUS inspected https://a.kit.example/x "sibling kit"
    _row https://notkit.example/x 2026-01-01T00:00:00Z DANGEROUS inspected https://notkit.example/x "unrelated"
    _got=$(FB_ROOT="$_t" NO_COLOR=1 "$0" --apex kit.example https://kit.example/verify | cut -f3 | sort | tr '\n' ' ')
    _want="https://a.kit.example/x https://kit.example/login "
    [ "$_got" = "$_want" ] || { echo "FAIL --apex: want [$_want] got [$_got]"; _fails=1; }
    # a dead URL keeps its label and its worklist slot, it is only held out of the corpus
    grep -q "DANGEROUS	inspected" "$(FB_ROOT="$_t" _fb_dir https://dead.example)/feedback.txt" \
        || { echo "FAIL gone row clobbered the label"; _fails=1; }
    # FB_CATEGORY: recorded in column 6, and only from the fixed vocabulary (run last: it settles
    # agreed.example, which the corpus check above still expects to be a bare agree row)
    FB_ROOT="$_t" FB_VERDICT=SAFE FB_CATEGORY=marketing "$0" -i https://agreed.example "promo landing page" >/dev/null
    grep -q "	marketing\$" "$(FB_ROOT="$_t" _fb_dir https://agreed.example)/feedback.txt" \
        || { echo "FAIL FB_CATEGORY not recorded"; _fails=1; }
    FB_ROOT="$_t" FB_CATEGORY=nonsense "$0" -i https://agreed.example "note" >/dev/null 2>&1 \
        && { echo "FAIL -i accepted a junk FB_CATEGORY"; _fails=1; }
    [ "$_fails" -eq 0 ] && echo "self-test: OK" || echo "self-test: FAILED"
    exit "$_fails"
fi

# -i <url> <note...>: append an `inspected` row carrying what the inspection concluded. The
# verdict column repeats the verdict that was inspected, so the row is readable on its own --
# unless FB_VERDICT says otherwise, which is how an inspection records the CORRECTED verdict
# (the scan said SAFE, the inspection found a phish). url-analyze.sh reports that on a re-scan.
# FB_CATEGORY records WHAT it is (phishing, scam, adult, ...) alongside how bad it is.
if [ -n "$INSPECT" ]; then
    _url="$1"; shift; _note="$*"
    if [ -z "$_url" ] || [ -z "$_note" ]; then
        echo "usage: $0 -i <url> <note>   (FB_VERDICT=<SAFE|SUSPICIOUS|DANGEROUS>, FB_CATEGORY=<$(printf '%s' "$VERDICT_CATEGORIES" | tr ' ' '|')>)" >&2; exit 2
    fi
    case "${FB_VERDICT:-SAFE}" in SAFE|SUSPICIOUS|DANGEROUS) ;;
        *) echo "FB_VERDICT must be SAFE, SUSPICIOUS or DANGEROUS" >&2; exit 2 ;; esac
    [ -n "${FB_CATEGORY:-}" ] && ! is_category "$FB_CATEGORY" \
        && { echo "FB_CATEGORY must be one of: $VERDICT_CATEGORIES" >&2; exit 2; }
    _d=$(_fb_dir "$_url")
    if [ ! -d "$_d" ]; then
        echo_yellow "no scan cached for $_url -- scan it before recording an inspection"; exit 1
    fi
    _v="${FB_VERDICT:-$(awk -F'\t' 'NF>=4 { v=$2 } END { print (v ? v : "?") }' "$_d/feedback.txt" 2>/dev/null)}"
    # tabs/newlines would break the TSV, so flatten them into spaces
    printf '%s\t%s\tinspected\t%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "${_v:-?}" "$_url" \
        "$(printf '%s' "$_note" | tr '\t\n' '  ')" "${FB_CATEGORY:-}" >> "$_d/feedback.txt"
    echo_green "inspected: $_url${FB_CATEGORY:+  [$FB_CATEGORY]}"
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
    cat "${FILES[@]}" | awk -F'\t' 'NF>=4 && $3!="gone" && $3!="alive" { print $1"\t"$3"\t"$4 }' \
        | sort -r | awk -F'\t' '!seen[$3]++ && $2=="flag" { print $3 }'
    exit 0
fi

# --corpus: the settled rows ARE labeled data -- an `inspected` row carries the corrected verdict
# and an `agree` row carries an analyst-confirmed one. Emitted in url-corpus.txt format
# (EXPECTED_VERDICT<space>URL) so the weekly replay is just the existing benchmark:
#   ./feedback-report.sh --corpus > url-corpus-live.txt
#   CORPUS=url-corpus-live.txt ./url-benchmark.sh
# Unsettled states (flag, disagree, skip) have no trustworthy label, so they are dropped -- and a
# re-flag after an inspection drops that URL again, because the case re-opened. Dead URLs (gone)
# are held back until a scan sees them alive, which keeps the score about detection, not uptime.
# --host <host> [exclude-url]: the settled judgements recorded for OTHER urls on this exact host.
# --apex <apex> [exclude-url]: the same, widened to every host UNDER that registrable domain.
# One line each: VERDICT<TAB>state<TAB>url<TAB>note<TAB>category. This is what url-analyze.sh knows
# about where a url lives before it fetches anything: kits rotate paths, query strings AND
# subdomains behind one registered domain, so a harvester settled at lxu438.kit.example is evidence
# about tyu620.kit.example tomorrow.
# The caller decides which of the two to ask for, because widening to the apex is only safe when
# the apex means one owner -- see is_tenant_suffix in verdict.sh.
# Dead urls are NOT filtered out here: a gone phishing page is still evidence about its host.
# "settled" = inspected|agree, same rule as --corpus below -- keep the two in sync.
if [ -n "$HOSTQ" ] || [ -n "$APEXQ" ]; then
    _want="$1"; _excl="${2:-}"
    [ -n "$_want" ] || { echo "usage: $0 --host <host> | --apex <apex>  [exclude-url]" >&2; exit 2; }
    cat "${FILES[@]}" | sort | awk -F'\t' -v want="$(printf '%s' "$_want" | tr 'A-Z' 'a-z')" \
                                          -v excl="$_excl" -v apex="$APEXQ" '
    function host(u) { sub(/^[a-zA-Z]+:\/\//, "", u); sub(/[\/?#].*$/, "", u)
                       sub(/^[^@]*@/, "", u); sub(/:[0-9]+$/, "", u); return tolower(u) }
    # apex mode matches the apex itself and anything below it, and only on a label boundary:
    # "notgetnew.space" must not match "getnew.space"
    function matches(h,   p) { if (!apex) return h==want
                               if (h==want) return 1
                               p = index(h, "." want)            # 0 when absent, and 0 would
                               return p > 0 && p == length(h)-length(want) }   # collide with it
    NF < 4 || $3=="gone" || $3=="alive" { next }
    { if (!($4 in ord)) { ord[$4] = ++n; URLS[n]=$4 }
      lab[$4] = (($3=="inspected" || $3=="agree") ? $2 : ""); st[$4]=$3
      note[$4]=(NF>=5 ? $5 : ""); cat[$4]=(NF>=6 ? $6 : "") }
    END { for (i=1; i<=n; i++) { u=URLS[i]
            if (u==excl || lab[u]=="" || !matches(host(u))) continue
            print lab[u]"\t"st[u]"\t"u"\t"note[u]"\t"cat[u] } }'
    exit 0
fi

if [ -n "$CORPUS" ]; then
    cat "${FILES[@]}" | sort | awk -F'\t' -v when="$(date -u +%FT%TZ)" '
    NF < 4 { next }
    $3=="gone"  { dead[$4]=1; next }
    $3=="alive" { dead[$4]=0; next }
    { if (!($4 in ord)) { ord[$4] = ++n; URLS[n]=$4 }
      # last judgement row wins; anything unsettled clears the label
      lab[$4] = (($3=="inspected" || $3=="agree") ? $2 : ""); cat[$4]=(NF>=6 ? $6 : "") }
    END {
      printf "# generated by feedback-report.sh --corpus at %s\n", when
      printf "# EXPECTED_VERDICT<space>URL[<space>category] -- from settled, live analyst feedback\n"
      for (i=1; i<=n; i++) { u=URLS[i]; v=lab[u]
        if (dead[u] || v=="") continue
        if (v!="SAFE" && v!="SUSPICIOUS" && v!="DANGEROUS") continue
        # url-benchmark.sh reads the first two fields and ignores the rest, so the category rides
        # along for a human reading the corpus without changing what the benchmark scores
        print v" "u (cat[u] ? " "cat[u] : ""); kept++ }
      printf "# %d urls\n", kept+0
    }'
    exit 0
fi

# sort: chronological, so "last row wins" below is genuinely the latest state per URL.
cat "${FILES[@]}" | sort | awk -F'\t' -v R="$RED" -v G="$GREEN" -v Y="$YELLOW" -v C="$CYAN" -v GY="$GREY" -v B="$BOLD" -v X="$RESET" '
NF < 4 { next }
# liveness is not a response: it never counts toward the totals or the current judgement state
$3=="gone"  { dead[$4]=1; next }
$3=="alive" { dead[$4]=0; next }
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
  state[u]=fb; when[u]=$1; verd[u]=v; note[u]=(NF>=5 ? $5 : ""); cat[u]=(NF>=6 ? $6 : "")
  if (!(u in ord)) { ord[u]= ++nURL; URLS[nURL]=u }
}
END {
  if (tot==0) { print GY "No parseable feedback rows." X; exit }
  openN=0; inspN=0; deadN=0
  for (i=1;i<=nURL;i++) { u=URLS[i]
    tag = (dead[u] ? " " GY "[gone]" X : ""); if (dead[u]) deadN++
    if (cat[u] != "") { ctally[cat[u]]++; catN++ }
    kind = (cat[u] ? "/" cat[u] : "")
    if (state[u]=="flag")      { openN++;  OP[openN]=when[u]" "verd[u] kind" "u tag }
    if (state[u]=="inspected") { inspN++;  IN[inspN]=when[u]" "verd[u] kind" "u tag "\n      " note[u] }
  }
  printf "%s%s== Analyst feedback: %d responses ==%s\n", B, C, tot, X
  printf "  %sagree %d   disagree %d   skip %d   open flags %d   inspected %d   gone %d%s\n\n", GY, agree+0, disN+0, skipN+0, openN, inspN, deadN, X
  print B "Agreement by verdict" X
  for (v in seen) {
    scored = aV[v]+dis[v]        # skips/flags excluded from the rate
    rate = scored ? (100*aV[v]/scored) : 0
    col = (dis[v] ? Y : G)
    printf "  %s%-10s%s %s%3d%%%s agree  (%d agree, %d disagree, %d total)\n", B, v, X, col, rate, X, aV[v]+0, dis[v]+0, seen[v]
  }
  # What the corpus is made OF -- severity says how bad, this says what kind. A weekly look here
  # shows which classes the toolkit actually meets, and which ones it has never once labelled.
  if (catN) {
    printf "%sBy category%s %s(%d labelled)%s\n", B, X, GY, catN, X
    for (c in ctally) printf "  %s%-14s%s %d\n", C, c, X, ctally[c]
    printf "\n"
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
