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

# WHAT a page is, independent of how bad it is. Severity answers "how much should this scare me",
# the category answers "what am I looking at", and the two really are independent: a scam
# storefront and a credential harvester are both DANGEROUS, a survey and a login page are both
# SAFE. Every verdict carries one, so the ledger can be mined by kind ("show me every rating page
# we called SAFE") and not only by severity. Fixed vocabulary, because free text would not group.
VERDICT_CATEGORIES="phishing email-harvest scam malware adult spam unsubscribe marketing questionnaire poll rating login content other"

# is_category <name> -> exit 0 if it is one of the fixed categories above.
is_category() { case " $VERDICT_CATEGORIES " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# category_of <verdict> <has_login> <url> <smells> <deobfus_signals> [title] -> the deterministic
# guess. Only a guess from evidence already extracted: an analyst answer or a deep inspection
# overrides it, and it is deliberately NOT fed back to the LLM (it is derived from the same
# signals the LLM already has, so it would only give a small model more to miscount).
category_of() {
    local verdict="$1" has_login="$2" url="$3" smells="$4" deobfus="$5" title="${6:-}"
    local text="$url $title"
    # UNCLEAR / empty: the scan could not judge the page (blank fetch, dead host, no LLM), so it
    # does not get to name it either. A category is a claim, and we have nothing to claim from.
    case "$verdict" in SAFE|SUSPICIOUS|DANGEROUS) ;; *) return 0 ;; esac
    if [ "$verdict" = "SUSPICIOUS" ] || [ "$verdict" = "DANGEROUS" ]; then
        # A credential form is the definition of phishing, and it outranks the rest: a kit that
        # also exfils and also spoofs a brand is still, first, after the password.
        if [ "$has_login" = "true" ] \
           || printf '%s' "$smells" | grep -qiE 'exfil|obfuscated network call' \
           || printf '%s' "$deobfus" | grep -qi 'off-domain URL'; then
            echo phishing; return 0
        fi
        # No form to steal from, so the click itself is the payload: it confirms a live address.
        is_unsub_url "$url" && { echo email-harvest; return 0; }
        printf '%s' "$smells" | grep -qi 'link-redirection service' && { echo spam; return 0; }
        # Money rather than credentials -- a wallet address is the payment rail of a scam page.
        printf '%s' "$deobfus" | grep -qi 'crypto wallet' && { echo scam; return 0; }
        printf '%s' "$smells" | grep -qiE 'crypto wallet|flagged malicious' && { echo scam; return 0; }
        # adult and malware have no reliable signal in what the scraper extracts, so they are never
        # guessed here -- they only ever come from an analyst answer or a deep inspection.
        echo other; return 0
    fi
    # Benign shapes. Same evidence, read for what the page is FOR rather than what it steals.
    [ "$has_login" = "true" ] && { echo login; return 0; }
    is_unsub_url "$url" && { echo unsubscribe; return 0; }
    # \brate\b, not bare rate: corporate/accurate would swallow half the web
    printf '%s' "$text" | grep -qiE '\brate\b|rating|review|nps|satisf' && { echo rating; return 0; }
    printf '%s' "$text" | grep -qiE '\bpoll\b|/vote|ballot' && { echo poll; return 0; }
    printf '%s' "$text" | grep -qiE 'survey|questionnaire|feedback|quiz|form' && { echo questionnaire; return 0; }
    printf '%s' "$text" | grep -qiE 'utm_|campaign|promo|newsletter|/track|offer' && { echo marketing; return 0; }
    echo content
}

# Suffixes where the registrable domain confers NO identity: every customer gets a subdomain, so
# one tenant's kit says nothing about the next tenant's page. Anything that reasons across an apex
# (the prior-judgement rollup in url-analyze.sh) must stop here.
# The Public Suffix List already covers most of these -- github.io, pages.dev, netlify.app,
# azurewebsites.net and friends are public suffixes, so apex_of already returns the tenant host.
# This list is for the ones it MISSES (awsapprunner.com is not in the PSL, and we have scans from
# two different tenants of it), plus a deliberate belt-and-braces repeat of the PSL ones, because
# psl.sh degrades to a last-two-labels heuristic when the list cannot be fetched.
# Bias: listing a single-owner domain here only loses a rollup, while omitting a multi-tenant one
# contaminates an innocent tenant. When unsure, list it.
TENANT_SUFFIXES="amazonaws.com awsapprunner.com azurewebsites.net cloudfront.net appspot.com
github.io pages.dev netlify.app vercel.app web.app workers.dev base44.app sealos.app
qlikcloud.com oraclecloud.com wasabisys.com filestackcontent.com myportfolio.com
maillist-manage.in zohosecure.com mjt.lu beak.host irontree.cloud ayai.live"

# is_tenant_suffix <apex> -> exit 0 if that apex is shared hosting rather than one owner.
is_tenant_suffix() { case " $(printf '%s' "$TENANT_SUFFIXES" | tr '\n' ' ') " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# url_decode <string> -> one percent-decoding pass. %XX only; a bare % is left alone, and literal
# backslashes are escaped first so printf %b cannot reinterpret them.
url_decode() {
    local s="${1//\\/\\\\}"
    s=$(printf '%s' "$s" | sed 's/%\([0-9A-Fa-f][0-9A-Fa-f]\)/\\x\1/g')
    printf '%b' "$s"
}

# url_decode_deep <string> -> decode until it stops changing (kits double-encode), max 3 rounds.
url_decode_deep() {
    local cur="$1" prev="" i=0
    while [ "$cur" != "$prev" ] && [ "$i" -lt 3 ]; do
        prev="$cur"; cur=$(url_decode "$cur"); i=$((i+1))
    done
    printf '%s' "$cur"
}

# is_random_label <label> -> exit 0 if it looks machine-generated rather than chosen: long, purely
# alphanumeric, and carrying at least two digits. Case-insensitive, because hostnames are.
is_random_label() {
    local s="${1,,}"; s="${s//[.-]/}"
    [ "${#s}" -gt 8 ] || return 1
    case "$s" in *[!a-z0-9]*) return 1 ;; esac
    case "$s" in *[0-9]*[0-9]*) return 0 ;; esac
    return 1
}

# Query parameters that carry a whole URL. An open redirect through one of these is how a phish
# borrows a trusted host: the landing domain really is accounts.google.com, and the destination is
# hidden in the parameter.
REDIRECT_PARAMS="redirect_uri redirect_url redirect redir redirecturl url u next continue return returnto return_to dest destination target goto to r relaystate callback forward image_url"

# redirect_raw <url> -> the RAW (still-encoded) value of the first redirect parameter that decodes
# to an http(s) URL. Raw, because the encoding itself is the evidence.
redirect_raw() {
    local q pair k v oldifs found=""
    q="${1#*\?}"
    [ "$q" = "$1" ] && return 0
    q="${q%%#*}"
    oldifs="$IFS"; IFS='&'
    for pair in $q; do
        k="${pair%%=*}"; v="${pair#*=}"
        [ "$v" = "$pair" ] && continue
        case " $REDIRECT_PARAMS " in *" ${k,,} "*) ;; *) continue ;; esac
        case "$(url_decode_deep "$v")" in http://*|https://*) found="$v"; break ;; esac
    done
    IFS="$oldifs"
    printf '%s' "$found"
}

# redirect_target <url> -> the host the redirect parameter really points at, decoded and lowercased.
redirect_target() {
    local d
    d=$(url_decode_deep "$(redirect_raw "$1")")
    [ -z "$d" ] && return 0
    d="${d#*://}"; d="${d%%[/?#]*}"; d="${d##*@}"; d="${d%%:*}"
    printf '%s' "${d,,}"
}

# has_gratuitous_encoding <string> -> exit 0 if an UNRESERVED character was percent-encoded.
# RFC 3986 says unreserved characters (A-Z a-z 0-9 - . _ ~) must not be encoded, and no normal
# tool does it. "h%74tps://" is a plain 't' hidden from anything that reads the url as text, which
# is evasion and nothing else. Decodes every %XX in one pass rather than forking per pair.
has_gratuitous_encoding() {
    local pairs decoded
    pairs=$(printf '%s' "$1" | grep -oE '%[0-9A-Fa-f]{2}' | tr -d '\n')
    [ -z "$pairs" ] && return 1
    decoded=$(url_decode "$pairs")
    case "$decoded" in *[a-zA-Z0-9._~-]*) return 0 ;; esac
    return 1
}

# campaign_key <url> -> the campaign tag carried in the query string, or nothing.
#
# One operator runs one kit across many registered domains, and the affiliate/sub-id tag in the
# link is what survives the rotation: ul590.getmypair.space/?s1=upg12 and
# lxu438.getnew.space/?s1=upg12 are ten different domains and one campaign. Neither the host nor
# the apex rollup can see that, because nothing about the domains is shared.
#
# A tag qualifies only if its VALUE is an opaque short token -- letters AND digits, nothing else,
# 3..16 chars. That one rule does the filtering: "unsubscribe", "en", "1" and long per-recipient
# tokens all fail it, so ?p=unsubscribe and ?token=cec793b0... never group. utm_* and the obvious
# per-recipient keys are dropped outright: utm_campaign really is shared by unrelated legitimate
# sites in one mailshot, which is the one false grouping this could produce.
# Pure bash, no forks: this runs once per ledger row.
# ponytail: pairs keep their url order rather than being sorted, so ?a=x1&b=y2 and ?b=y2&a=x1 do
# not group. Sort them if a kit ever shuffles its own query order.
campaign_key() {
    local url="$1" q pair k v out="" oldifs
    q="${url#*\?}"
    [ "$q" = "$url" ] && return 0        # no query string at all
    q="${q%%#*}"
    oldifs="$IFS"; IFS='&'
    for pair in $q; do
        k="${pair%%=*}"; v="${pair#*=}"
        if [ "$v" = "$pair" ] || [ -z "$v" ] || [ -z "$k" ]; then continue; fi
        case "$k" in utm_*|e|email|mail|to|token|hash|sig|key|id|uid|od|upd) continue ;; esac
        [ "${#v}" -ge 3 ] && [ "${#v}" -le 16 ] || continue
        case "$v" in *[!a-zA-Z0-9]*) continue ;; esac      # opaque means alnum only
        case "$v" in *[a-zA-Z]*) ;; *) continue ;; esac    # ... with letters
        case "$v" in *[0-9]*) ;; *) continue ;; esac       # ... and digits
        out="${out:+$out&}$k=$v"
    done
    # Nothing matched by value? Try SHAPE. A kit that mints a fresh token per victim can never be
    # grouped by an exact value, but its generator still leaves a fingerprint: both hops of the
    # Google-OAuth chain carried state=<25 alnum>-<26..56 digits>, a format nothing else emits.
    # Shape keys must stay generator-specific. A carrier shape -- "any SendGrid /ls/click link" --
    # is deliberately NOT one: it would group every legitimate mailshot on the platform with the
    # phish, and one bad inspection would taint them all.
    if [ -z "$out" ]; then
        for pair in $q; do
            k="${pair%%=*}"; v="${pair#*=}"
            [ "$v" = "$pair" ] && continue
            case "$k" in utm_*) continue ;; esac
            printf '%s' "$v" | grep -qE '^[A-Za-z0-9]{20,32}-[0-9]{20,}$' \
                && { out="shape:$k=alnum-digits"; break; }
        done
    fi
    IFS="$oldifs"
    printf '%s' "$out"
}

# is_unsub_url <url> -> exit 0 if it is a mailing-list / unsubscribe endpoint.
# A click on one mainly confirms the address is live (list validation).
is_unsub_url() {
    printf '%s' "$1" | grep -qiE 'unsub|opt[-_]?out|list[-_]?manage|/remove|mailpref|newsletter'
}

# is_blank_page <http_status> <element_count> -> exit 0 when the fetch produced nothing
# assessable: an error status, or a DOM with zero links/forms/scripts/images/iframes.
# Scoring either yields a phantom "clean" verdict -- the scanner saw NO page, which is not
# the same as seeing a safe one (healthlynotes.com: HTTP 500 "Database Error", empty DOM,
# zero smells -> SAFE). Callers must degrade the verdict to UNCLEAR; the floor still runs,
# so static signals (risky TLD, young domain) can still escalate over it.
# status 0 is NOT blank: operator attach has no response object but a full live DOM.
is_blank_page() {
    [ -n "$1" ] && [ "$1" -ge 400 ] 2>/dev/null && return 0
    [ "${2:-0}" -eq 0 ] 2>/dev/null && return 0
    return 1
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
    [ -n "$smells" ] && n=$(( n + $(printf '%s' "$smells" | tr ',' '\n' | grep -viE 'hidden form field|third-party hosts referenced|hotlinked brand image|previously inspected as suspicious' | grep -c .) ))
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
    # A CREDENTIAL page displaying a brand's own hotlinked artwork is the cloned-kit shape: copied
    # from the real login page, still pulling the logo off the brand's CDN. Legit pages embed brand
    # artwork too (PayPal buttons, dealer/partner logos), so like offhost above this earns
    # SUSPICIOUS only alongside a login form, and nothing at all without one -- which is why
    # count_red_flags excludes it. Cap is deliberate: it is display evidence, not proof of theft.
    local hotlink=""
    [ "$has_login" = "true" ] && printf '%s' "$smells" | grep -qi 'hotlinked brand image' && hotlink=1
    # A multi-vendor VirusTotal consensus is stronger evidence than anything these local
    # heuristics produce, and it does NOT need a credential form to be real -- scam storefronts
    # and malware droppers harvest money, not passwords, so the login-gated DANGEROUS rule below
    # capped trencraft.com (11 VT vendors malicious) at SUSPICIOUS. Quorum of 5 because one or
    # two vendors is routinely stale or a lone heuristic engine.
    # A sibling url on this same registered domain that a HUMAN (or a deep inspection) already
    # settled as SUSPICIOUS. Real evidence -- not this tool's own uncertainty, which is why only
    # `inspected` rows reach here and never `agree` ones. Capped at its own severity: it says the
    # domain has hosted something bad, not that THIS page is harvesting, so it is excluded from
    # count_red_flags and can never combine with a login form to reach DANGEROUS. A settled
    # DANGEROUS sibling arrives as an ordinary smell instead, and does count.
    local priorsusp=""
    printf '%s' "$smells" | grep -qi 'previously inspected as suspicious' && priorsusp=1
    # The page's own JavaScript probing for automation, trapping devtools, filtering datacentre
    # IPs or deleting itself. A page that checks whether it is being analysed before it will show
    # itself has something to hide -- and it explains our blank fetches, which are the kit refusing
    # us rather than a broken site.
    # Capped at SUSPICIOUS and kept out of the red-flag count, because commercial bot-protection
    # (Akamai, DataDome) does some of this on legitimate login pages. It says "this page is hiding
    # from analysis", which is not the same claim as "this page is harvesting credentials".
    local antianalysis=""
    printf '%s' "$deobfus" | grep -qi 'anti-analysis' && antianalysis=1
    local vtquorum="" _vtn
    _vtn=$(printf '%s' "$smells" | grep -oiE 'VirusTotal flagged malicious \([0-9]+ vendors?\)' \
           | grep -oE '[0-9]+' | head -1)
    [ -n "$_vtn" ] && [ "$_vtn" -ge 5 ] 2>/dev/null && vtquorum="$_vtn"

    # Floor: the minimum severity the signals demand. Empty = impose nothing.
    local floor="" reason=""
    if [ -n "$exfil" ]; then
        floor=DANGEROUS; reason="data exfil (obfuscated / off-domain network call)"
    elif [ -n "$vtquorum" ]; then
        floor=DANGEROUS; reason="$vtquorum VirusTotal vendors flagged this URL malicious"
    elif [ "$has_login" = "true" ] && [ "$flags" -ge 1 ]; then
        floor=DANGEROUS; reason="login form + $flags red flag(s)"
    elif [ "$flags" -ge 1 ] || [ -n "$unsub" ] || [ -n "$offhost" ] || [ -n "$hotlink" ] || [ -n "$priorsusp" ] || [ -n "$antianalysis" ]; then
        floor=SUSPICIOUS
        reason="$flags red flag(s)${unsub:+ + unsubscribe endpoint}${offhost:+ + login form loading off-CDN third-party host}${hotlink:+ + login form displaying hotlinked brand artwork}${priorsusp:+ + a url on this domain or campaign was already inspected and found suspicious}${antianalysis:+ + page javascript actively resists analysis}"
    fi

    if [ -n "$floor" ] && [ "$(_severity "$floor")" -gt "$(_severity "$llm")" ]; then
        echo "${CYAN:-}[floor] Safety floor: $reason -> forcing $floor (LLM said ${llm:-UNCLEAR})${RESET:-}" >&2
        printf '%s' "$floor"
    else
        printf '%s' "$llm"
    fi
}
