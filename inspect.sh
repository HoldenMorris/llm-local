#!/usr/bin/env bash
# Deep inspection: headless `claude -p` reads the CACHED artifacts of one scan and says whether
# the verdict is right. Read-only tools, so it never prompts mid-run and never touches the live
# site. `source` it, then call deep_inspect / inspect_verdict / inspect_category / inspect_note.
#
# Shared because two callers need the SAME prompt: the `i` (inspect now) branch of
# url-analyze.sh, where a human asked for it, and next-alert.sh, which runs it automatically to
# resolve a SKIP. A prompt is load-bearing here -- two copies would drift and the two paths would
# start disagreeing about the same page for no reason anyone could see.
#
# Run ./inspect.sh for the self-check (parsers only: pure, no claude, no network).

INSPECT_SH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# is_category and VERDICT_CATEGORIES live in verdict.sh; only source it if we were not sourced
# after it already (url-analyze.sh sources both).
declare -F is_category >/dev/null 2>&1 || source "$INSPECT_SH_DIR/verdict.sh"

# deep_inspect <url> <landed_url> <verdict> <smells> <cache_dir> <host_dir>
# Prints claude's raw reply on stdout; returns non-zero if the call failed.
deep_inspect() {
    local url="$1" landed="$2" verdict="$3" smells="$4" cache="$5" host="$6"
    command -v claude >/dev/null 2>&1 || { echo "claude not on PATH" >&2; return 127; }
    claude -p "Deep-inspect one phishing scan from this repo ($INSPECT_SH_DIR).

URL:      $url
Landed:   ${landed:-$url}
Verdict:  $verdict
Signals:  ${smells:-none}
Cache:    $cache
Host facts: $host/meta.env

Read the cached artifacts (page.json, page-login.json, meta.env, scripts/,
deob-signals.txt, vision.txt, virustotal.json, urlscan.json -- whichever exist) and say
whether $verdict is right. Cite concrete evidence from the artifacts, never guess. If it
is wrong, name the heuristic gap in verdict.sh / page-fetch.sh that let it through.
Do not fetch the live URL and do not edit any file.
End your reply with exactly these three lines:
VERDICT: <SAFE|SUSPICIOUS|DANGEROUS -- the TRUE verdict, which future scans will report>
CATEGORY: <what the page IS, one of: $VERDICT_CATEGORIES>
NOTE: <one-line conclusion, max 200 chars>" \
        --allowedTools "Read,Grep,Glob" 2>&1
}

# The corrected verdict is the POINT of an inspection, so an unparseable reply yields nothing
# rather than a guess -- the caller then keeps the verdict it already had.
inspect_verdict() {
    printf '%s\n' "$1" | grep -m1 '^VERDICT:' | grep -oiE 'SAFE|SUSPICIOUS|DANGEROUS' \
        | head -1 | tr 'a-z' 'A-Z'
}

# Only ever a value from the fixed vocabulary: these get mined later and free text does not group.
inspect_category() {
    local c
    c=$(printf '%s\n' "$1" | grep -m1 '^CATEGORY:' | sed 's/^CATEGORY:[[:space:]]*//' \
        | tr -d ' ' | tr 'A-Z' 'a-z')
    is_category "$c" && printf '%s' "$c"
}

# Falls back to the last non-empty line: a reply that reasoned well but forgot the NOTE: prefix
# still carries its conclusion there, and losing it would throw away the whole inspection.
inspect_note() {
    local n
    n=$(printf '%s\n' "$1" | grep -m1 '^NOTE:' | sed 's/^NOTE:[[:space:]]*//')
    [ -z "$n" ] && n=$(printf '%s\n' "$1" | grep -v '^[[:space:]]*$' | tail -1)
    printf '%s' "$n"
}

# --- self-check (parsers only) ---
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    _f=0
    _ok() { [ "$2" = "$3" ] && printf 'ok   %s\n' "$1" || { printf 'FAIL %s: want [%s] got [%s]\n' "$1" "$2" "$3"; _f=1; }; }
    R='Looked at page.json: a password field posts off-domain.

VERDICT: DANGEROUS
CATEGORY: phishing
NOTE: credential form posting to an unrelated host'
    _ok "verdict parsed"   DANGEROUS "$(inspect_verdict "$R")"
    _ok "category parsed"  phishing  "$(inspect_category "$R")"
    _ok "note parsed"      "credential form posting to an unrelated host" "$(inspect_note "$R")"
    _ok "lowercase verdict" SAFE     "$(inspect_verdict 'VERDICT: safe')"
    _ok "junk verdict -> empty" ""   "$(inspect_verdict 'VERDICT: probably fine')"
    _ok "no verdict line -> empty" "" "$(inspect_verdict 'I think it is bad')"
    _ok "junk category -> empty" ""  "$(inspect_category 'CATEGORY: dodgy')"
    # A reply that forgot the prefix must still surrender its conclusion.
    _ok "note falls back to last line" "it is a parked domain" "$(inspect_note 'blah'$'\n\n''it is a parked domain')"
    [ "$_f" = 0 ] && echo "self-test ok"
    exit "$_f"
fi
