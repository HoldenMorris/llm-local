#!/bin/bash

# Deterministic verdict model for url-analyze.sh.
# Source this file, then call classify_verdict. This is the single source of
# truth for the risky-TLD list and the red-flag decision table, so the Phase 1
# display and the final verdict can never silently diverge.

# Canonical high-risk TLDs (space-separated). Union of the two lists this
# replaces, so every historical flag is preserved.
RISKY_TLDS="cfd xyz top lol sbs icu buzz surf monster click link gq ml tk cf ga work zip mov"

# is_risky_tld <tld> -> exit 0 if the bare TLD (no dot) is high-risk.
is_risky_tld() {
    case " $RISKY_TLDS " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

# is_unsub_url <url> -> exit 0 if it is a mailing-list / unsubscribe endpoint.
# A click on one mainly confirms the address is live (list validation).
is_unsub_url() {
    printf '%s' "$1" | grep -qiE 'unsub|opt[-_]?out|list[-_]?manage|/remove|mailpref|newsletter'
}

# count_red_flags <tld> <age_days> <final_url> <smells> <susp_js>
#   Echoes the number of deterministic red flags in the extracted signals.
#   The signals are already computed deterministically upstream, so we never
#   ask a small model to do this boolean counting.
count_red_flags() {
    local tld="$1" age="$2" final_url="$3" smells="$4" susp_js="$5"
    local n=0
    # one flag per phishing smell the scraper reported
    [ -n "$smells" ] && n=$(( n + $(printf '%s' "$smells" | tr ',' '\n' | grep -c .) ))
    # suspicious JS present
    [ -n "$susp_js" ] && n=$(( n + 1 ))
    # risky TLD
    is_risky_tld "$tld" && n=$(( n + 1 ))
    # young domain (<90 days); empty age = unknown -> not counted
    [ -n "$age" ] && [ "$age" -lt 90 ] 2>/dev/null && n=$(( n + 1 ))
    # redirect into a compromised WordPress tree
    printf '%s' "$final_url" | grep -qiE 'wp-content|wp-include' && n=$(( n + 1 ))
    printf '%s' "$n"
}

# _severity <verdict> -> numeric rank so verdicts can be compared. Empty/unknown
# ranks 0 so a real verdict always beats "no opinion".
_severity() {
    case "$1" in
        DANGEROUS)  echo 3 ;;
        SUSPICIOUS) echo 2 ;;
        SAFE)       echo 1 ;;
        *)          echo 0 ;;
    esac
}

# classify_verdict <has_login> <tld> <age_days> <final_url> <url> <smells> <susp_js> <llm_verdict>
#   The deterministic core. Computes the minimum verdict the signals demand (the
#   "safety floor") and returns the more severe of that floor and the LLM's
#   verdict -- it escalates but never downgrades, so it can never mask a threat
#   the LLM caught. Echoes SAFE|SUSPICIOUS|DANGEROUS (or the LLM verdict verbatim,
#   which may be empty -> caller shows UNCLEAR) to stdout. When the floor
#   overrides the LLM, an explanatory notice is written to stderr.
classify_verdict() {
    local has_login="$1" tld="$2" age="$3" final_url="$4" url="$5" smells="$6" susp_js="$7" llm="$8"
    local flags unsub=""
    flags=$(count_red_flags "$tld" "$age" "$final_url" "$smells" "$susp_js")
    is_unsub_url "$url" && unsub=1

    # Floor: the minimum severity the signals demand. Empty = impose nothing.
    local floor=""
    if [ "$has_login" = "true" ] && [ "$flags" -ge 1 ]; then
        # login form + any red flag = credential harvesting
        floor=DANGEROUS
    elif [ "$flags" -ge 1 ] || [ -n "$unsub" ]; then
        # red flags / list-validation without a login form
        floor=SUSPICIOUS
    fi

    if [ -n "$floor" ] && [ "$(_severity "$floor")" -gt "$(_severity "$llm")" ]; then
        if [ "$floor" = DANGEROUS ]; then
            echo "⚙️  Safety floor: login form + $flags red flag(s) -> forcing DANGEROUS (LLM said ${llm:-UNCLEAR})" >&2
        else
            echo "⚙️  Safety floor: $flags red flag(s)${unsub:+ + unsubscribe endpoint} -> forcing SUSPICIOUS (LLM said ${llm:-UNCLEAR})" >&2
        fi
        printf '%s' "$floor"
    else
        printf '%s' "$llm"
    fi
}
