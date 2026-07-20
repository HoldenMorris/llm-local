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

# count_red_flags <tld> <age_days> <final_url> <smells> <susp_js> <deobfus_signals>
#   Echoes the number of deterministic red flags in the extracted signals.
#   The signals are already computed deterministically upstream, so we never
#   ask a small model to do this boolean counting.
count_red_flags() {
    local tld="$1" age="$2" final_url="$3" smells="$4" susp_js="$5" deobfus="$6"
    local n=0
    # one flag per phishing smell the scraper reported, EXCEPT hidden-field count:
    # legit sites (GitHub has 40) routinely exceed the scraper's threshold, so it must
    # not by itself force the DANGEROUS floor. Still shown to the LLM as context.
    [ -n "$smells" ] && n=$(( n + $(printf '%s' "$smells" | tr ',' '\n' | grep -viE 'hidden form field|third-party hosts referenced' | grep -c .) ))
    # suspicious JS present -- but it's only the TRIGGER for deobfuscation (Phase 3.5). When that
    # ran (deobfus non-empty), line 38 scores the malicious findings and same-domain-only output
    # means the marker was cleared; count the raw marker itself only when deob did NOT adjudicate it
    # (skipped via -D, no inline scripts, or empty). Else minified bundles (Vite/webpack
    # String.fromCharCode) false-flag every login page to DANGEROUS.
    # Only STRONG markers count. hex escapes / String.fromCharCode / location redirect are ordinary
    # MINIFIER output (Closure emits all three), so alone they are LLM context, never a red flag --
    # they also no longer trigger deob, so counting them would just move the same false positive
    # here. eval/atob/document.write/_0x still count when deob did not adjudicate them.
    [ -n "$susp_js" ] && [ -z "$deobfus" ] \
        && [ "$(printf '%s' "$susp_js" | tr ',' '\n' \
             | grep -viE 'hex-encoded strings|String\.fromCharCode|location redirect' \
             | grep -c .)" -gt 0 ] \
        && n=$(( n + 1 ))
    # deobfuscated JS revealed real malicious intent: off-domain exfil, JS redirect, or
    # crypto address. Same-domain URLs / storage access alone do NOT count (false-positive guard).
    printf '%s' "$deobfus" | grep -qiE 'off-domain URL|JS redirect|crypto wallet' && n=$(( n + 1 ))
    # risky TLD
    is_risky_tld "$tld" && n=$(( n + 1 ))
    # young domain (<90 days); empty age = unknown -> not counted
    [ -n "$age" ] && [ "$age" -lt 90 ] 2>/dev/null && n=$(( n + 1 ))
    # Redirect into a compromised WordPress tree. Mirrors page-fetch.sh's `wpSuspicious`: a random
    # segment under wp-content/wp-includes, but NOT the plugins/themes/uploads trees -- those are
    # where every legit WordPress site serves its own media, so bare 'wp-content|wp-include' scored
    # a real gov PDF (siu.org.za/wp-content/uploads/.../Judgment-...pdf) as a red flag.
    # Two greps because ERE has no negative lookahead (keep in sync with wpSuspicious).
    if printf '%s' "$final_url" | grep -qiE '/wp-(includes?|content)/[a-z0-9]{3,}/' \
       && ! printf '%s' "$final_url" | grep -qiE '/wp-(includes?|content)/(plugins|themes|uploads)/'; then
        n=$(( n + 1 ))
    fi
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

# classify_verdict <has_login> <tld> <age_days> <final_url> <url> <smells> <susp_js> <deobfus_signals> <llm_verdict>
#   The deterministic core. Computes the minimum verdict the signals demand (the
#   "safety floor") and returns the more severe of that floor and the LLM's
#   verdict -- it escalates but never downgrades, so it can never mask a threat
#   the LLM caught. Echoes SAFE|SUSPICIOUS|DANGEROUS (or the LLM verdict verbatim,
#   which may be empty -> caller shows UNCLEAR) to stdout. When the floor
#   overrides the LLM, an explanatory notice is written to stderr.
classify_verdict() {
    local has_login="$1" tld="$2" age="$3" final_url="$4" url="$5" smells="$6" susp_js="$7" deobfus="$8" llm="$9"
    local flags unsub="" exfil=""
    flags=$(count_red_flags "$tld" "$age" "$final_url" "$smells" "$susp_js" "$deobfus")
    is_unsub_url "$url" && unsub=1
    # Active data exfil -- an obfuscated network call, or an off-domain exfil URL revealed by
    # deobfuscation -- IS credential/data harvesting on its own, even if no <input
    # type=password> was detected (kits use non-password inputs to dodge that check).
    printf '%s' "$smells" | grep -qiE 'exfil|obfuscated network call' && exfil=1
    printf '%s' "$deobfus" | grep -qiE 'off-domain URL' && exfil=1
    # A LOGIN page pulling scripts/fonts/forms from an off-apex, non-CDN host is abnormal -- it is
    # the kit-copied-from-a-compromised-host / off-origin-fingerprinting pattern. The smell is
    # already CDN/analytics/captcha-filtered upstream (page-fetch.sh cdnRe), so what's left here is
    # the suspicious remainder. NOT counted as a red flag on content pages (line 33 excludes it --
    # legit sites embed off-CDN widgets all the time); only floors a credential page to SUSPICIOUS.
    local offhost=""
    [ "$has_login" = "true" ] && printf '%s' "$smells" | grep -qi 'third-party hosts referenced' && offhost=1

    # Floor: the minimum severity the signals demand. Empty = impose nothing.
    local floor="" reason=""
    if [ -n "$exfil" ]; then
        floor=DANGEROUS; reason="data exfil (obfuscated / off-domain network call)"
    elif [ "$has_login" = "true" ] && [ "$flags" -ge 1 ]; then
        floor=DANGEROUS; reason="login form + $flags red flag(s)"
    elif [ "$flags" -ge 1 ] || [ -n "$unsub" ] || [ -n "$offhost" ]; then
        floor=SUSPICIOUS
        reason="$flags red flag(s)${unsub:+ + unsubscribe endpoint}${offhost:+ + login form loading off-CDN third-party host}"
    fi

    if [ -n "$floor" ] && [ "$(_severity "$floor")" -gt "$(_severity "$llm")" ]; then
        echo "${CYAN:-}[floor] Safety floor: $reason -> forcing $floor (LLM said ${llm:-UNCLEAR})${RESET:-}" >&2
        printf '%s' "$floor"
    else
        printf '%s' "$llm"
    fi
}
