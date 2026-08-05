#!/bin/bash

# URL Analyzer - combines page-fetch signals with LLM analysis

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/ollama-up.sh"
source "$SCRIPT_DIR/verdict.sh"
source "$SCRIPT_DIR/psl.sh"
source "$SCRIPT_DIR/js-signals.sh"
source "$SCRIPT_DIR/machine.sh"
# colors.sh is sourced further down, after args are parsed (so -c mono can disable color)

# best_model -> the top-scoring model from the url-benchmark.sh CSV, FOR THIS MACHINE
# (highest accuracy, then fastest). Excludes the "none" baseline and other machines'
# rows -- timings only compare within one hardware fingerprint. Empty if no data.
best_model() {
    local csv="$SCRIPT_DIR/results/url_benchmark.csv"
    [ -f "$csv" ] || return 0
    awk -F, -v m="$(machine_id)" 'NR>1 && $2==m && $3!="none" && $3!="heuristic" {
        acc=$6; sub(/%/,"",acc); t=$7; sub(/s/,"",t)
        if (acc+0>ba || (acc+0==ba && t+0<bt)) { ba=acc+0; bt=t+0; bm=$3 }
    } END { print bm }' "$csv"
}

# domain_dns <domain> -> one line "<domain> -> <ip> (country, org), age Nd" for an off-domain
# exfil target. Uses a general RDAP bootstrap (rdap.org) so arbitrary TLDs (.cc, .no, ...) get
# a registration age. The caller parses ", age Nd" to flag very-new domains.
domain_dns() {
    local d="$1" ip country org created cts age=""
    ip=$(dig +short "$d" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    if [ -n "$ip" ]; then
        local info; info=$(curl -s --max-time 5 "http://ip-api.com/json/$ip?fields=country,org,isp" 2>/dev/null)
        country=$(echo "$info" | jq -r '.country // "?"' 2>/dev/null)
        org=$(echo "$info" | jq -r '.org // .isp // "?"' 2>/dev/null)
    fi
    created=$(curl -s --max-time 6 "https://rdap.org/domain/$d" 2>/dev/null \
        | jq -r '.events[]? | select(.eventAction=="registration") | .eventDate' 2>/dev/null | head -1 | cut -dT -f1)
    if [ -n "$created" ] && [ "$created" != "null" ]; then
        cts=$(date -d "$created" +%s 2>/dev/null)
        [ -n "$cts" ] && age=$(( ($(date +%s) - cts) / 86400 ))
    fi
    printf '%s' "$d"
    [ -n "$ip" ] && printf ' -> %s (%s, %s)' "$ip" "${country:-?}" "${org:-?}" || printf ' (unresolvable)'
    [ -n "$age" ] && printf ', age %sd' "$age"
    printf '\n'
}

usage() {
    cat <<EOF
Usage: $(basename "$0") [options] <url>

Analyze a URL for phishing signals (static + DNS + page fetch + optional LLM verdict).

Options:
  -m <model>  verdict LLM (-m auto = best benchmarked model; -m none = no LLM)
  -H          heuristic only: no LLM, verdict from the decision table
  -s          skip the page fetch (static + DNS only)
  -V          no vision (skip the login-form screenshot brand-check)
  -D          skip JS deobfuscation
  -t          third-party reputation (VirusTotal + urlscan.io); off by default, needs .env
  -p <tor>    route the scanner's egress through Tor (free geo-target / blacklist-dodge)
  -g <cc>     Tor exit country (ISO code: us, gb, de, ...); use with -p tor
  -r          ignore cache, re-fetch
  -c mono     disable color output
  -h, --help  show this help

Examples:
  $(basename "$0") -m auto https://example.com
  $(basename "$0") -H https://suspicious.example

With no URL it prompts for one; the interactive menu lists 0: [Pure Heuristic] plus models.
EOF
}

MODEL=""
URL=""
SKIP_FETCH=""
NO_VISION=""
HEURISTIC=""
REFRESH=""
NO_DEOBFUS=""
VT=""
PROXY=""
EXIT_CC=""
VISION_MODEL="${VISION_MODEL:-openbmb/minicpm-v4.6:q4_K_M}"

# Help as the first arg (getopts won't catch bare `help` or long `--help`).
case "${1:-}" in -h|--help|help) usage; exit 0 ;; esac

while getopts "m:sVHrc:Dhtp:g:" opt; do
    case $opt in
        m) MODEL="$OPTARG" ;;
        s) SKIP_FETCH=1 ;;
        V) NO_VISION=1 ;;
        H) HEURISTIC=1 ;;     # heuristic-only: no LLM, verdict from verdict.sh decision table
        r) REFRESH=1 ;;       # ignore any cached page/screenshot/metadata and re-fetch
        c) case "$OPTARG" in mono|none|off|no) MONO=1 ;; esac ;;  # -c mono = no color
        D) NO_DEOBFUS=1 ;;    # skip JS deobfuscation escalation
        t) VT=1 ;;            # opt-in third-party reputation (VirusTotal + urlscan.io)
        p) PROXY="$OPTARG" ;; # scanner egress: tor (or none). Geo-target / dodge blacklists.
        g) EXIT_CC="$OPTARG" ;; # Tor exit country (ISO code, e.g. us, gb) -- only with -p tor
        h) usage; exit 0 ;;
        *) usage >&2; exit 1 ;;
    esac
done
# A bare run -- no flags at all -- is the interactive analyst path, and it is the only one that
# asks about the cache. Any flag at all means the caller has told us how to behave, and the
# benchmarks always pass flags, so they can never be stopped by a prompt.
BARE_RUN=""; [ "$OPTIND" -eq 1 ] && BARE_RUN=1
shift $((OPTIND-1))

# -m none is an alias for -H (pure heuristic: no LLM, verdict from the decision table)
[ "$MODEL" = none ] && { HEURISTIC=1; MODEL=""; }

# Now that -c mono is known, load the shared color helpers.
source "$SCRIPT_DIR/colors.sh"

# === Claude (Anthropic API) backend ===
# -m claude-<id> (or -m claude, an alias for claude-opus-4-8) runs the verdict LLM through the
# Anthropic Messages API instead of local Ollama; VISION_MODEL=claude-<id> does the same for the
# screenshot reader. Opt-in only (needs ANTHROPIC_API_KEY in .env) -- sends page text/screenshots of
# live-suspect pages to the API, so it's off by default and the benchmarks never use it.
_is_claude()  { case "$1" in claude|claude-*) return 0 ;; *) return 1 ;; esac; }
_claude_id()  { [ "$1" = claude ] && echo claude-opus-4-8 || echo "$1"; }
_ENV_LOADED=""
_load_env()   { [ -n "$_ENV_LOADED" ] && return; [ -f "$SCRIPT_DIR/.env" ] && { set -a; . "$SCRIPT_DIR/.env"; set +a; }; _ENV_LOADED=1; }

# One Anthropic Messages call for the current MODEL/SYSTEM_PROMPT/CONTEXT. Echoes the reply text (or
# the "Error: No response" stub, matching the Ollama path so caching/retry treat it the same). $1
# (temperature) is ignored -- current Claude models reject the sampling params.
_claude_infer() {
    _load_env
    if [ -z "${ANTHROPIC_API_KEY:-}" ]; then printf 'Error: No response from model'; return; fi
    local resp txt
    resp=$(jq -n --arg m "$(_claude_id "$MODEL")" --arg s "$SYSTEM_PROMPT" --arg p "$CONTEXT" \
             '{model:$m,max_tokens:512,system:$s,messages:[{role:"user",content:$p}]}' \
         | curl -s --max-time 60 https://api.anthropic.com/v1/messages \
             -H 'content-type: application/json' -H "x-api-key: $ANTHROPIC_API_KEY" \
             -H 'anthropic-version: 2023-06-01' -d @-)
    txt=$(printf '%s' "$resp" | jq -r '[.content[]?|select(.type=="text")|.text]|join("\n")' 2>/dev/null)
    [ -n "$txt" ] && printf '%s' "$txt" || printf 'Error: No response from model'
}

# Anthropic vision: reads screenshot $1 with prompt $2, echoes the reply text (empty on error).
_claude_vision() {
    _load_env
    [ -z "${ANTHROPIC_API_KEY:-}" ] && return
    jq -n --arg m "$(_claude_id "$VISION_MODEL")" --arg p "$2" --arg img "$(base64 -w0 "$1")" \
       '{model:$m,max_tokens:300,messages:[{role:"user",content:[{type:"image",source:{type:"base64",media_type:"image/jpeg",data:$img}},{type:"text",text:$p}]}]}' \
     | curl -s --max-time 60 https://api.anthropic.com/v1/messages \
         -H 'content-type: application/json' -H "x-api-key: $ANTHROPIC_API_KEY" \
         -H 'anthropic-version: 2023-06-01' -d @- \
     | jq -r '[.content[]?|select(.type=="text")|.text]|join(" ")' 2>/dev/null
}

# ponytail: attention ping before we open a window / ask a risky prompt. `\a` to the terminal is
# the portable bell, but its audibility depends on the terminal's bell setting (often off), so if a
# desktop sound player is present we also play a real system sound. Best-effort, never blocks.
_bell() {
    printf '\a' > /dev/tty 2>/dev/null
    if command -v canberra-gtk-play >/dev/null 2>&1; then
        canberra-gtk-play -i bell >/dev/null 2>&1 &
    elif command -v paplay >/dev/null 2>&1 && [ -f /usr/share/sounds/freedesktop/stereo/bell.oga ]; then
        paplay /usr/share/sounds/freedesktop/stereo/bell.oga >/dev/null 2>&1 &
    fi
}

URL="${1:-$URL}"

# Prompt for a URL when none was given (interactive only, so piped/benchmark runs don't hang)
if [ -z "$URL" ] && [ -t 0 ]; then
    read -r -p "${CYAN}Enter URL to analyze: ${RESET}" URL
fi
if [ -z "$URL" ]; then
    usage >&2
    exit 1
fi

# ponytail: content cache keyed by URL hash. Page fetch (Docker+Chrome), screenshot and
# domain lookups are the slow parts; cache them so re-scans and the model benchmark reuse
# one fetch across many models. -r wipes it.
CACHE_DIR="$SCRIPT_DIR/.cache/$(printf '%s' "$URL" | sha256sum | cut -c1-16)"
# _purge_cache: drop the DERIVED data (page, screenshot, scripts, LLM answers) and keep
# feedback.txt. That file is hand-entered analyst judgement, not something a re-scan can
# regenerate: wiping the whole dir silently erased the flag history of every URL re-scanned with
# -r, and the flags simply vanished from ./feedback-report.sh -f.
_purge_cache() {
    local keep; keep=$(cat "$CACHE_DIR/feedback.txt" 2>/dev/null)
    rm -rf "$CACHE_DIR"; mkdir -p "$CACHE_DIR"
    [ -n "$keep" ] && printf '%s\n' "$keep" > "$CACHE_DIR/feedback.txt"
    return 0
}

# A bare interactive run decides what to do about an existing scan instead of silently reusing it.
# Reuse is still the default (Enter), because it is free and the cached page is what the recorded
# verdict was made from -- but a phishing page changes under you, so "is this still what I saw
# yesterday" has to be one keypress away.
REUSED_CACHE=""
if [ -n "$BARE_RUN" ] && [ -t 0 ] && [ -d "$CACHE_DIR" ]; then
    _cached=$(find "$CACHE_DIR" -maxdepth 1 ! -name feedback.txt ! -path "$CACHE_DIR" \
              -printf '%T@\n' 2>/dev/null | sort -rn | head -1)
    if [ -n "$_cached" ]; then
        echo_grey "cached scan of this URL from $(date -d "@${_cached%.*}" '+%F %R' 2>/dev/null)"
        read -r -p "${CYAN}Re-use it, or update (re-fetch everything)? [R/u] ${RESET}" _ans
        case "$_ans" in [Uu]*) REFRESH=1 ;; *) REUSED_CACHE=1 ;; esac
    fi
fi

[ -n "$REFRESH" ] && _purge_cache
mkdir -p "$CACHE_DIR"

# === PHASE 1: Static URL Analysis (zero-day signals) ===
# Split host from an explicit :port -- a port glued to DOMAIN breaks dig/openssl (the non-standard
# high port is itself a tunneling/phishing signal, e.g. portmap.io:46801). PORT feeds the cert check.
# [^/?#] and not [^/]: a url may carry a query with NO path at all (https://host?state=...), and
# stopping only at '/' swallowed the whole query into DOMAIN. dig then failed, the fetch was
# skipped, and the scan produced a verdict from zero facts -- which is exactly how the middle hop
# of the Google-OAuth chain (m-365a63c9-....radiopanamericanapanama.com?state=...) read SAFE.
AUTHORITY=$(echo "$URL" | sed -E 's|https?://([^/?#]+).*|\1|')
# Strip any userinfo (user[:pass]@) -- the host is what follows the LAST '@'. A userinfo is also
# the classic 'http://paypal.com@evil.com' obfuscation, so note it (non-flooring; benign email pastes).
USERINFO=""
if [[ "$AUTHORITY" == *@* ]]; then USERINFO=${AUTHORITY%@*}; AUTHORITY=${AUTHORITY##*@}; fi
DOMAIN=${AUTHORITY%%:*}
PORT=${AUTHORITY##*:}; [ "$PORT" = "$AUTHORITY" ] && PORT=443
TLD=$(echo "$DOMAIN" | grep -oE '\.[a-z]+$' | tr -d '.')

# All signals collect here and print as one bullet list before the verdict, instead of
# being sprinkled through the phases. add_signal appends.
SIGNALS=()
add_signal() { SIGNALS+=("$1"); }

# Userinfo in the URL: the '@' hides the real host (host = what follows it). Note it for triage.
[ -n "$USERINFO" ] && add_signal "URL contains userinfo before '@' ('$USERINFO@') -- real host is $DOMAIN"

# ponytail: High-risk TLDs (list lives in verdict.sh, single source of truth)
if is_risky_tld "$TLD"; then
    add_signal "High-risk TLD: .$TLD"
fi

# ponytail: Typosquatting detection (brand in subdomain but not apex)
# Tech brands
TECH_BRANDS="google|facebook|microsoft|apple|amazon|paypal|netflix|instagram|linkedin|twitter|github|dropbox|adobe|zoom|slack|wix|salesforce|oracle|ibm|cisco|vmware"
# Crypto
CRYPTO_BRANDS="coinbase|binance|metamask|tronlink|trustwallet|kraken|gemini|blockchain|ledger|exodus|phantom|uniswap|opensea"
# US Banks
US_BANKS="chase|wellsfargo|bankofamerica|citibank|usbank|pnc|capitalone|tdbank|truist|ally|discover|schwab|fidelity|vanguard|americanexpress|amex"
# UK Banks
UK_BANKS="barclays|hsbc|lloyds|natwest|santander|halifax|nationwide|tsb|monzo|revolut|starling"
# EU Banks
EU_BANKS="ing|bnp|deutsche|commerzbank|rabobank|abn|unicredit|intesa|creditsuisse|ubs"
# African Banks
AFRICA_BANKS="nedbank|standardbank|fnb|absa|capitec|investec|firstrand|oldmutual|discovery|africanbank"
# APAC Banks
APAC_BANKS="dbs|ocbc|uob|maybank|cimb|icici|hdfc|sbi|kotak|axis|commonwealth|anz|westpac|nab"

BRANDS="$TECH_BRANDS|$CRYPTO_BRANDS|$US_BANKS|$UK_BANKS|$EU_BANKS|$AFRICA_BANKS|$APAC_BANKS"
# Long brand names (>=5 chars) are unambiguous as substrings (paypalsecure, microsoftlogin).
# Short ones (ing, dbs, ubs, anz, amex, citi, ally...) false-match inside ordinary words
# (stag'ing', bear'ings', 'ally'ourbase, 'dbs'chenker), so require them to be a whole dot/dash-
# delimited label. TSQ is the combined pattern; the apex-exclusion still uses the raw brand list.
SHORT_B=$(printf '%s' "$BRANDS" | tr '|' '\n' | awk 'length<5'  | paste -sd'|')
LONG_B=$(printf '%s'  "$BRANDS" | tr '|' '\n' | awk 'length>=5' | paste -sd'|')
TSQ="(^|[.-])(${SHORT_B})([.-]|\$)|(${LONG_B})"
# A brand's OWN domains are not typosquats. The exclusion must test the APEX, not the whole
# hostname: `^(www\.)?brand\.(com|org|net|io)$` matched ONLY the bare apex, so every brand
# subdomain (accounts.google.com, mail.paypal.com) and every brand ccTLD (barclays.co.uk,
# amazon.co.jp) read as typosquatting. Apex SLD, accounting for a ccTLD second level (co.uk):
BRAND_SLD=$(printf '%s' "$DOMAIN" | awk -F. '{ s=$(NF-1);
    if (NF >= 3 && s ~ /^(co|com|net|org|ac|gov|edu|ne|or|in)$/) s=$(NF-2); print tolower(s) }')
BRAND_OWNED=0
# 1. The TLD *is* the brand -> a brand gTLD (share.google, blog.google). Those are CLOSED
#    registries, so only the brand can hold a name there. EXCEPT .ing, an OPEN registry that
#    merely collides with the ING brand -- paypal.ing would be a real phish, so don't exclude it.
echo "$TLD" | grep -qiE "^($BRANDS)$" && ! echo "$TLD" | grep -qiE '^ing$' && BRAND_OWNED=1
# 2. The apex SLD is the brand on a reputable TLD (google.com, barclays.co.uk, paypal.me).
#    [a-z]{2} = any ccTLD. Deliberately NOT any TLD: paypal.top / paypal.xyz must still flag.
echo "$BRAND_SLD" | grep -qiE "^($BRANDS)$" \
    && echo "$TLD" | grep -qiE '^(com|org|net|io|[a-z]{2})$' && BRAND_OWNED=1
if [ "$BRAND_OWNED" -eq 0 ] && echo "$DOMAIN" | grep -qiE "$TSQ"; then
    MATCHED=$(echo "$DOMAIN" | grep -oiE "$TSQ" | grep -oiE "($BRANDS)" | head -1)
    add_signal "Possible typosquatting: contains '$MATCHED' but domain is $DOMAIN"
fi

# ponytail: Excessive subdomains (often used to hide real domain)
SUBDOMAIN_COUNT=$(echo "$DOMAIN" | tr '.' '\n' | wc -l)
if [ "$SUBDOMAIN_COUNT" -gt 4 ]; then
    add_signal "Excessive subdomains ($SUBDOMAIN_COUNT levels)"
fi

# ponytail: Homograph detection (mixed scripts in domain)
if echo "$DOMAIN" | grep -qP '[^\x00-\x7F]'; then
    add_signal "Homograph attack: non-ASCII characters in domain"
fi

# ponytail: Random-looking domain (high entropy). is_random_label lives in verdict.sh so the
# redirect-target check below judges a host by exactly the same rule.
DOMAIN_BASE=$(echo "$DOMAIN" | sed 's/\.[^.]*$//' | tr -d '.-')
if is_random_label "$DOMAIN_BASE"; then
    add_signal "Random-looking domain: $DOMAIN_BASE"
fi

# === Redirect parameter carrying a whole URL (open-redirect abuse) ===
# The strongest way to hide a phish is to not host it: point a redirect parameter on a trusted
# host at your own. The landing domain here really IS accounts.google.com -- aged, Google-owned,
# valid cert -- so every domain-based check passes and the scan reads UNCLEAR.
# An off-site redirect target is NOT suspicious by itself: that is what OAuth is for, and every
# legitimate sign-in flow does it. What is never legitimate is HIDING it:
#   * gratuitous percent-encoding of unreserved characters ("h%74tps" is a plain 't')
#   * a machine-generated hostname, or a high-risk TLD, at the far end
# Those score; the bare off-site target is context.
REDIR_TARGET=$(redirect_target "$URL")
REDIR_OBFUS=""; REDIR_BAD=""
if [ -n "$REDIR_TARGET" ] && [ "$(apex_of "$REDIR_TARGET")" != "$(apex_of "$DOMAIN")" ]; then
    add_signal "Redirect parameter points off-site to: $REDIR_TARGET"
    if has_gratuitous_encoding "$(redirect_raw "$URL")"; then
        REDIR_OBFUS=1
        add_signal "Redirect target is obfuscated: unreserved characters percent-encoded to hide $REDIR_TARGET"
    fi
    _rt_tld="${REDIR_TARGET##*.}"
    if is_risky_tld "$_rt_tld"; then
        REDIR_BAD="high-risk TLD .$_rt_tld"
    elif is_random_label "$(printf '%s' "$REDIR_TARGET" | sed 's/\.[^.]*$//' | tr -d '.-')"; then
        REDIR_BAD="machine-generated hostname"
    fi
    [ -n "$REDIR_BAD" ] && add_signal "Redirect target looks hostile: $REDIR_BAD ($REDIR_TARGET)"
fi

# ponytail: Abuse-prone tunneling / port-forwarding services. A random subdomain on one of these
# means the real operator is hidden behind a free tunnel -- classic phishing/C2 hosting. Counts as a
# red flag (appended to SMELLS after the fetch) so a tunnel URL reads SUSPICIOUS even when the tunnel
# is down and the page can't be fetched. (^|\.) boundary so 'notngrok.io' does not match ngrok.io.
TUNNEL_SERVICES='ngrok\.io|ngrok-free\.app|ngrok\.app|ngrok\.dev|trycloudflare\.com|portmap\.io|serveo\.net|loca\.lt|lhr\.life|localhost\.run|pagekite\.me|telebit\.io|bore\.pub|tunnelto\.dev'
TUNNEL_SVC=""
if echo "$DOMAIN" | grep -qiE "(^|\.)($TUNNEL_SERVICES)\$"; then
    TUNNEL_SVC=$(echo "$DOMAIN" | grep -oiE "($TUNNEL_SERVICES)\$" | head -1)
    add_signal "Hosted on tunneling service: $TUNNEL_SVC (real operator hidden behind a free tunnel)"
fi

# ponytail: Email link-tracking / redirection services (Mailjet mjt.lu, SendGrid, Mailchimp, ...).
# Phishing routinely enters through these: a live token 3xx/JS-redirects off-domain and we analyze
# the DESTINATION (host is re-anchored post-redirect). The problem case is a dead/expired/bare link
# -- the scraper lands on the service's own "this subdomain is for link redirection" placeholder,
# which previously scored SAFE. Detected here; whether it becomes a red flag is decided post-fetch
# (only when we NEVER left the service -- see below), so a resolved link isn't punished for its entry.
REDIRECT_SERVICES='mjt\.lu|sendgrid\.net|list-manage\.com|rs6\.net|hubspotlinks\.com|mailgun\.org|sparkpostmail\.com|sg-links\.net|mandrillapp\.com|klclick\.com|hubspotemail\.net|cmail[0-9]*\.com'
REDIRECT_SVC=""
if echo "$DOMAIN" | grep -qiE "(^|\.)($REDIRECT_SERVICES)\$"; then
    REDIRECT_SVC=$(echo "$DOMAIN" | grep -oiE "($REDIRECT_SERVICES)\$" | head -1)
    add_signal "Email link-redirection service: $REDIRECT_SVC (real destination reached via a tracked redirect)"
else
    # The host name hides the service. Every ESP sells "branded links": the customer publishes a
    # CNAME (url8083.calvis.com -> sendgrid.net) so the tracking url wears the customer's own
    # domain -- aged, reputable, and completely unlike the service it points at. Five consecutive
    # scans of one campaign walked past this list for exactly that reason.
    # So ask DNS what the name really is. One extra lookup, deterministic, and it covers every ESP
    # in the list at once instead of needing their branded suffixes enumerated.
    _cname=$(dig +short CNAME "$DOMAIN" 2>/dev/null | sed 's/\.$//' | head -3)
    if [ -n "$_cname" ] && printf '%s\n' "$_cname" | grep -qiE "(^|\.)($REDIRECT_SERVICES)\$"; then
        REDIRECT_SVC=$(printf '%s\n' "$_cname" | grep -oiE "($REDIRECT_SERVICES)\$" | head -1)
        add_signal "Email link-redirection service behind a branded CNAME: $DOMAIN -> $REDIRECT_SVC"
    elif printf '%s' "$URL" | grep -qE '/(ls|wf)/click\?upn='; then
        # DNS-free backstop, because these links are usually already dead by the time we look and
        # a dead name has no CNAME to read. The path is provider-specific (SendGrid's click
        # tracker), deliberately not a generic "looks like a tracker" guess: naming the wrong
        # service is worse than naming none.
        REDIRECT_SVC="sendgrid.net"
        add_signal "Email link-redirection service by url shape: SendGrid click tracker on $DOMAIN"
    fi
fi

# === Domain Info Lookup ===
# IP/geo, domain age, SSL and DNS are facts about the HOST -- nothing here depends on the path or
# the query string. So they cache per host, not per URL: a scan of a different path on a host we
# already know skips this whole block of serial network round-trips (dig, ip-api, RDAP, openssl).
# Facts do go stale (certs rotate, domains age, DNS moves), so the cache expires after
# META_TTL_DAYS; -r refreshes it now.
# ponytail: one file per host. AGE_DAYS is really apex-scoped, so sibling subdomains re-fetch it --
# that is one RDAP call, not worth a second cache tier keyed on the apex.
HOST_DIR="$SCRIPT_DIR/.cache/host/$(printf '%s' "$DOMAIN:$PORT" | tr -c 'a-zA-Z0-9.:_-' '_')"
META_TTL_DAYS=7
mkdir -p "$HOST_DIR"

# Registrable domain via the Public Suffix List (psl.sh). NOT the last two labels: for
# smithpower.autoit.za.com that gave "za.com", so the RDAP lookup below returned the CentralNic
# registry's 1998 registration and every *.za.com phish inherited a 28-year "aged domain" pass.
# When the host sits directly on a shared namespace, apex_of returns the host itself, RDAP has no
# record for it, and the age reads unknown -- which is the honest answer, and count_red_flags
# already treats an empty age as "not counted" rather than "old".
APEX_DOMAIN=$(apex_of "$DOMAIN")

if [ -z "$REFRESH" ] && [ -n "$(find "$HOST_DIR/meta.env" -mtime "-$META_TTL_DAYS" 2>/dev/null)" ]; then
    source "$HOST_DIR/meta.env"
    echo "${BOLD}Domain Info (cached for $DOMAIN)${RESET}"
else
echo "${BOLD}Domain Info${RESET}"

# DNS + IP info
IP=$(dig +short "$DOMAIN" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
if [ -n "$IP" ]; then
    IP_INFO=$(curl -s --max-time 5 "http://ip-api.com/json/$IP?fields=country,org,isp" 2>/dev/null)
    COUNTRY=$(echo "$IP_INFO" | jq -r '.country // "?"')
    ORG=$(echo "$IP_INFO" | jq -r '.org // .isp // "?"')
fi

# Domain age via RDAP (works for .com, .net, .org)
if echo "$TLD" | grep -qE '^(com|net|org)$'; then
    RDAP_URL="https://rdap.verisign.com/$TLD/v1/domain/$APEX_DOMAIN"
    RDAP=$(curl -s --max-time 5 "$RDAP_URL" 2>/dev/null)
    CREATED=$(echo "$RDAP" | jq -r '.events[] | select(.eventAction=="registration") | .eventDate' 2>/dev/null | head -1)
    if [ -n "$CREATED" ] && [ "$CREATED" != "null" ]; then
        CREATED_DATE=$(echo "$CREATED" | cut -d'T' -f1)
        # Calculate age in days
        CREATED_TS=$(date -d "$CREATED_DATE" +%s 2>/dev/null || echo "")
        [ -n "$CREATED_TS" ] && AGE_DAYS=$(( ($(date +%s) - CREATED_TS) / 86400 ))
    fi
fi

# === SSL Certificate Check (openssl) ===
if echo "$URL" | grep -q "^https://"; then
    SSL_INFO=$(echo | timeout 5 openssl s_client -connect "$DOMAIN:$PORT" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -dates -issuer 2>/dev/null)
    if [ -n "$SSL_INFO" ]; then
        CERT_START=$(echo "$SSL_INFO" | grep "notBefore" | cut -d= -f2)
        CERT_ISSUER=$(echo "$SSL_INFO" | grep "issuer" | sed 's/.*CN = //' | cut -d',' -f1)
        if [ -n "$CERT_START" ]; then
            CERT_TS=$(date -d "$CERT_START" +%s 2>/dev/null || echo "")
            [ -n "$CERT_TS" ] && CERT_AGE_DAYS=$(( ($(date +%s) - CERT_TS) / 86400 ))
        fi
    fi
fi

# === DNS Records Check ===
A_RECORDS=$(dig +short "$DOMAIN" A 2>/dev/null | grep -E '^[0-9]+\.' | wc -l)
TTL=$(dig +noall +answer "$DOMAIN" A 2>/dev/null | awk '{print $2}' | head -1)

# Persist the lookups for re-scans (only once we actually resolved something).
# printf %q keeps org names with spaces/quotes shell-safe when sourced back.
if [ -n "$IP" ]; then
    { printf 'IP=%q\n' "$IP";               printf 'COUNTRY=%q\n' "$COUNTRY"
      printf 'ORG=%q\n' "$ORG";             printf 'AGE_DAYS=%q\n' "$AGE_DAYS"
      printf 'CREATED_DATE=%q\n' "$CREATED_DATE"
      printf 'CERT_AGE_DAYS=%q\n' "$CERT_AGE_DAYS"; printf 'CERT_ISSUER=%q\n' "$CERT_ISSUER"
      printf 'A_RECORDS=%q\n' "$A_RECORDS"; printf 'TTL=%q\n' "$TTL"; } > "$HOST_DIR/meta.env"
fi
fi

# Signals are derived from the FACTS, outside the lookup, so a cached run and a fresh run produce
# the same signal list. They used to diverge: the cached branch re-added only the fast-flux signal,
# so every re-scan silently dropped the domain-age, new-cert and low-TTL signals from the LLM's
# context -- the same scan could read differently depending on whether the cache happened to be warm.
echo_grey "- IP: ${IP:-(unresolvable)}${IP:+ ($COUNTRY, $ORG)}"
if [ -n "$AGE_DAYS" ]; then
    if   [ "$AGE_DAYS" -lt 30 ] 2>/dev/null; then add_signal "Domain age: $AGE_DAYS days (VERY NEW - high risk)"
    elif [ "$AGE_DAYS" -lt 90 ] 2>/dev/null; then add_signal "Domain age: $AGE_DAYS days (new)"
    else echo_grey "- Domain age: $AGE_DAYS days${CREATED_DATE:+ (created $CREATED_DATE)}"
    fi
fi
if [ -n "$CERT_AGE_DAYS" ]; then
    if   [ "$CERT_AGE_DAYS" -lt 7 ] 2>/dev/null;  then add_signal "SSL cert age: $CERT_AGE_DAYS days (VERY NEW - suspicious)"
    elif [ "$CERT_AGE_DAYS" -lt 30 ] 2>/dev/null; then echo_grey "- SSL cert age: $CERT_AGE_DAYS days (recent)"
    else echo_grey "- SSL cert: $CERT_AGE_DAYS days old, issuer: $CERT_ISSUER"
    fi
fi
[ "${A_RECORDS:-0}" -gt 5 ] 2>/dev/null && add_signal "Fast-flux: $A_RECORDS A records (suspicious)"
[ -n "$TTL" ] && [ "$TTL" -lt 300 ] 2>/dev/null && add_signal "Low TTL: ${TTL}s (fast-flux indicator)"

# Don't spin up the fetch container if the domain has no DNS A record -- it would just
# time out. Static + DNS info above still stands. (data: URLs need no DNS, so exempt them.)
if [ -z "$SKIP_FETCH" ] && [ -z "$IP" ] && ! printf '%s' "$URL" | grep -q '^data:'; then
    add_signal "Domain does not resolve (no DNS A record)"
    SKIP_FETCH=1; NO_DNS=1
fi

# === PHASE 2: Page Fetch (dynamic signals) ===
if [ -z "$SKIP_FETCH" ]; then
    # Screenshot + page content live in the cache dir, so re-scans and the benchmark reuse
    # one fetch. The screenshot also feeds the Phase 3 vision escalation.
    [ -z "$NO_VISION" ] && SHOT="$CACHE_DIR/page.jpg"
    if [ -f "$CACHE_DIR/page.json" ]; then
        PAGE_DATA=$(cat "$CACHE_DIR/page.json")
    else
        echo_grey "- Fetching page content...${PROXY:+ (egress via $PROXY${EXIT_CC:+ /$EXIT_CC})}"
        # Cache full inline scripts too (page-fetch only dumps them when obfuscation fires),
        # so the JS-deobfuscation escalation can reuse them. -p/-g route the scanner's egress.
        _pf_out=$(PAGE_SHOT="$SHOT" PAGE_SCRIPTS_DIR="$CACHE_DIR/scripts" "$SCRIPT_DIR/page-fetch.sh" \
            ${PROXY:+-p "$PROXY"} ${EXIT_CC:+-g "$EXIT_CC"} "$URL" 2>&1)
        PAGE_DATA=$(printf '%s\n' "$_pf_out" | tail -1)
        # show the actual exit IP/geo the page saw (EGRESS line emitted by page-fetch when -p tor)
        _eg=$(printf '%s\n' "$_pf_out" | grep -m1 '^EGRESS ')
        [ -n "$_eg" ] && { read -r _ _eip _ecc _eorg <<< "$_eg"; echo_grey "- egress: $_eip ($_ecc, ${_eorg:-?})"; }
        # cache only a successful fetch, never an error stub
        echo "$PAGE_DATA" | jq -e '.error' >/dev/null 2>&1 || echo "$PAGE_DATA" > "$CACHE_DIR/page.json"
    fi

    # Liveness gets its own append-only row (gone/alive) in the feedback ledger, separate from the
    # judgement rows. Phishing kits die within days, so the weekly replay
    # (./feedback-report.sh --corpus) must drop a dead URL instead of scoring the scanner against a
    # page that no longer exists -- while the inspected label survives the outage and comes back
    # with the URL. One row per state change, never one per scan.
    _fb_live() { awk -F'\t' '$3=="gone"||$3=="alive" { s=$3 } END { print s }' "$CACHE_DIR/feedback.txt" 2>/dev/null; }
    _fb_mark() { printf '%s\t?\t%s\t%s\n' "$(date -u +%FT%TZ)" "$1" "$URL" >> "$CACHE_DIR/feedback.txt"; }

    if echo "$PAGE_DATA" | jq -e '.error' >/dev/null 2>&1; then
        # Keep the HTTP status out of the error stub before discarding the rest. "The server
        # answered 404" and "we could not reach it at all" are different facts, and on a
        # link-redirection service the difference is the whole finding (see below).
        PAGE_ERR_STATUS=$(echo "$PAGE_DATA" | jq -r '.status // 0' 2>/dev/null)
        echo_yellow "[!] Page unreachable or timeout${PAGE_ERR_STATUS:+ (HTTP $PAGE_ERR_STATUS)}"
        [ "$(_fb_live)" != "gone" ] && { _fb_mark gone; echo_grey "- marked gone in the feedback ledger (drops out of the replay corpus)"; }
        PAGE_DATA="{}"
    else
        [ "$(_fb_live)" = "gone" ] && { _fb_mark alive; echo_grey "- back up: cleared the gone mark"; }
        # Extract signals
        SMELLS=$(echo "$PAGE_DATA" | jq -r '.phishingSmells[]?' 2>/dev/null)
        HAS_LOGIN=$(echo "$PAGE_DATA" | jq -r '.hasLoginForm' 2>/dev/null)
        TITLE=$(echo "$PAGE_DATA" | jq -r '.title' 2>/dev/null)
        FINAL_URL=$(echo "$PAGE_DATA" | jq -r '.finalUrl' 2>/dev/null)
        THIRD_PARTY=$(echo "$PAGE_DATA" | jq -r '.thirdPartyDomains | length' 2>/dev/null)
        # Fed to is_blank_page at verdict time (see verdict.sh). PAGE_FETCHED marks that a real
        # page.json exists, so the -s / unreachable paths keep their own handling.
        PAGE_FETCHED=1
        PAGE_STATUS=$(echo "$PAGE_DATA" | jq -r '.status // 0' 2>/dev/null)
        PAGE_ELEMS=$(echo "$PAGE_DATA" | jq -r '[.counts | .links, .forms, .scripts, .images, .iframes] | add // 0' 2>/dev/null)

        if [ "$FINAL_URL" != "$URL" ] && [ -n "$FINAL_URL" ] && [ "$FINAL_URL" != "null" ]; then
            add_signal "Redirects to: $FINAL_URL"
        fi

        [ "$HAS_LOGIN" = "true" ] && add_signal "Login form detected"

        # Each scraper phishing smell becomes its own signal (here-string, not a pipe, so
        # the appends survive in the current shell).
        if [ -n "$SMELLS" ]; then
            while IFS= read -r smell; do
                [ -n "$smell" ] && add_signal "$smell"
            done <<< "$SMELLS"
        fi

        echo_grey "- Third-party domains: $THIRD_PARTY"

        # ponytail: Follow-the-login-link escalation. This page has no credential form, but a
        # marketing landing page or SPA shell routinely puts one a single click away -- and every
        # login-dependent floor stays a no-op until a password field is seen, so a kit with a clean
        # front page scored SAFE (icamis.icam.mw did exactly that). Spend ONE more fetch on the best
        # candidate page-fetch.sh surfaced, and only when this page really has no form.
        # The LINK is never a signal: having a login page is not suspicious. Only what the followed
        # page CONTAINS counts, merged below as if it had been seen on the landed page.
        # A page.json cached before loginLinks existed simply has no candidates; -r refreshes it.
        LOGIN_URL=""
        [ "$HAS_LOGIN" != "true" ] && LOGIN_URL=$(echo "$PAGE_DATA" | jq -r '.loginLinks[0] // empty' 2>/dev/null)
        if [ -n "$LOGIN_URL" ]; then
            if [ -f "$CACHE_DIR/page-login.json" ]; then
                LOGIN_DATA=$(cat "$CACHE_DIR/page-login.json")
            else
                echo_grey "- No form here; following login link: $LOGIN_URL"
                [ -z "$NO_VISION" ] && LOGIN_SHOT="$CACHE_DIR/login.jpg"
                LOGIN_DATA=$(PAGE_SHOT="$LOGIN_SHOT" "$SCRIPT_DIR/page-fetch.sh" \
                    ${PROXY:+-p "$PROXY"} ${EXIT_CC:+-g "$EXIT_CC"} "$LOGIN_URL" 2>/dev/null | tail -1)
                echo "$LOGIN_DATA" | jq -e '.error' >/dev/null 2>&1 \
                    || echo "$LOGIN_DATA" > "$CACHE_DIR/page-login.json"
            fi
            # Only a page that really does ask for credentials is worth merging. A "portal" link
            # that turns out to be a brochure page changes nothing, and costs one fetch to learn.
            if [ "$(echo "$LOGIN_DATA" | jq -r '.hasLoginForm // false' 2>/dev/null)" = "true" ]; then
                LOGIN_SMELLS=$(echo "$LOGIN_DATA" | jq -r '(.phishingSmells // []) | join(", ")' 2>/dev/null)
                add_signal "Credential form found one click away: $LOGIN_URL (landing page has none)"
                while IFS= read -r _ls; do
                    [ -n "$_ls" ] && add_signal "$_ls [on $LOGIN_URL]"
                done <<< "$(echo "$LOGIN_DATA" | jq -r '.phishingSmells[]?' 2>/dev/null)"
                # Point the VLM at the CREDENTIAL page, not the marketing shell that linked it --
                # the brand-vs-domain question is only meaningful where the password box is.
                [ -f "$CACHE_DIR/login.jpg" ] && SHOT="$CACHE_DIR/login.jpg"
            else
                LOGIN_URL=""    # nothing to merge; keep the verdict inputs untouched
            fi
        fi
    fi
else
    PAGE_DATA="{}"
    echo_grey "- (page fetch skipped)"
fi

# === Operator attach mode: clear the bot gate in a real browser, analyze the uncloaked DOM ===
# ponytail: our headless container is the weakest tier vs bot gates (see .planning/phases/
# anti-bot-rendering). When a Turnstile/hCaptcha/reCAPTCHA challenge gated the scraper, the
# reliable path is the operator's OWN Brave on their residential IP: the tool opens a visible
# Brave, the human clears the gate and lands on the real page, then we re-scan by CDP-attaching to
# that cleared tab. The tool opens AND closes the browser; the operator just solves + presses Enter.
# All gate smells end with "gated from the scraper", so one match covers every provider.
if [ -z "$SKIP_FETCH" ] && [ -t 0 ] \
   && printf '%s' "$PAGE_DATA" | jq -e '(.phishingSmells // []) | any(test("gated from the scraper"))' >/dev/null 2>&1; then
    _brave=""
    for _b in /snap/bin/brave brave brave-browser; do
        command -v "$_b" >/dev/null 2>&1 && { _brave=$(command -v "$_b"); break; }
    done
    _target=$(echo "$PAGE_DATA" | jq -r '.finalUrl // empty' 2>/dev/null); _target="${_target:-$URL}"
    # Name the gate for the prompt (e.g. "Cloudflare Turnstile", "hCaptcha", "reCAPTCHA").
    _gate=$(echo "$PAGE_DATA" | jq -r 'first(.phishingSmells[]? | select(test("gated from the scraper"))) // "Bot"' 2>/dev/null | sed 's/ challenge.*//')
    if [ -z "$_brave" ]; then
        echo_grey "- ${_gate} gate hit; no Brave found for operator attach (install Brave or open it manually)"
    else
        # Always confirm before opening a browser window, and ring the terminal bell for attention.
        _bell
        read -r -p "${CYAN}- ${_gate} gate blocked the scanner. Open it in Brave so YOU can clear it, then analyze the real page? [Y/n] ${RESET}" _a
        if [[ ! "$_a" =~ ^[Nn] ]]; then
            _prof=$(mktemp -d "${TMPDIR:-/tmp}/brave-attach.XXXXXX")
            _port=9222
            # unique throwaway profile forces a fresh instance that actually exposes the debug port
            "$_brave" --remote-debugging-port=$_port --user-data-dir="$_prof" \
                --no-first-run --no-default-browser-check --new-window "$_target" >/dev/null 2>&1 &
            _bpid=$!
            # the browser + temp profile die with us no matter how we exit (pkill by the unique
            # profile path is the reliable way to kill snap-wrapped Brave)
            _cleanup='kill '"$_bpid"' 2>/dev/null; pkill -f "'"$_prof"'" 2>/dev/null; rm -rf "'"$_prof"'"'
            trap "$_cleanup" EXIT INT TERM
            _ready=""
            for _i in $(seq 1 24); do
                curl -sf "http://127.0.0.1:$_port/json/version" >/dev/null 2>&1 && { _ready=1; break; }
                sleep 0.5
            done
            if [ -z "$_ready" ]; then
                echo_grey "- attach: Brave debug port never came up on $_port -- skipping"
            else
                echo_grey "- opened a Brave window at $_target"
                echo_grey "- solve the challenge / gate, land on the REAL page, then press Enter below"
                read -r -p "${CYAN}- press Enter here to analyze the uncloaked page... ${RESET}" _
                echo_grey "- re-scanning via CDP attach to your cleared tab..."
                _new=$(PAGE_ATTACH="http://127.0.0.1:$_port" PAGE_SHOT="$CACHE_DIR/page.jpg" \
                       PAGE_SCRIPTS_DIR="$CACHE_DIR/scripts" "$SCRIPT_DIR/page-fetch.sh" "$_target" 2>&1 | tail -1)
                if echo "$_new" | jq -e 'has("title") or has("hasLoginForm")' >/dev/null 2>&1; then
                    PAGE_DATA="$_new"
                    echo "$PAGE_DATA" > "$CACHE_DIR/page.json"   # cache the uncloaked page for re-scans
                    add_signal "Operator attach: analyzed the uncloaked page past the ${_gate} gate"
                else
                    echo_grey "- attach: re-scan returned no usable page ($(echo "$_new" | jq -r '.error // "unknown"' 2>/dev/null)) -- keeping the gated result"
                fi
            fi
            # close the operator's browser + wipe the throwaway profile, then drop the trap
            eval "$_cleanup"; trap - EXIT INT TERM
        fi
    fi
fi

# Extract explicit, pre-computed signals so the verdict logic (and the LLM) reason from
# facts, not raw JSON. Needed by classify_verdict below in BOTH LLM and heuristic modes.
HAS_LOGIN=$(echo "$PAGE_DATA" | jq -r '.hasLoginForm // false' 2>/dev/null)
FORMS=$(echo "$PAGE_DATA" | jq -r '.counts.forms // 0' 2>/dev/null)
LOGIN_FORMS=$(echo "$PAGE_DATA" | jq -r '.counts.loginForms // 0' 2>/dev/null)
FINAL_URL=$(echo "$PAGE_DATA" | jq -r '.finalUrl // ""' 2>/dev/null)
TITLE=$(echo "$PAGE_DATA" | jq -r '.title // ""' 2>/dev/null)
THIRD_PARTY=$(echo "$PAGE_DATA" | jq -r '.thirdPartyDomains | length' 2>/dev/null)
SUSP_JS=$(echo "$PAGE_DATA" | jq -r '(.suspiciousJs // []) | join(", ")' 2>/dev/null)
SMELLS=$(echo "$PAGE_DATA" | jq -r '(.phishingSmells // []) | join(", ")' 2>/dev/null)
# Tunneling-service host (detected in Phase 1) is a deterministic red flag, whether or not the page
# fetched -- append here so count_red_flags scores it (1 flag -> SUSPICIOUS floor on its own).
[ -n "$TUNNEL_SVC" ] && SMELLS="${SMELLS:+$SMELLS, }hosted on tunneling service $TUNNEL_SVC"
# Same for the hidden redirect target (Phase 1). One red flag each, and they stack: an obfuscated
# parameter pointing at a machine-generated host is two. Both are properties of the URL, so they
# score with no fetch at all -- which is the point, because the fetched page is the real login
# page of a real trusted brand and looks perfectly clean.
[ -n "$REDIR_OBFUS" ] && SMELLS="${SMELLS:+$SMELLS, }redirect target hidden by gratuitous percent-encoding ($REDIR_TARGET)"
[ -n "$REDIR_BAD" ] && SMELLS="${SMELLS:+$SMELLS, }redirect target is hostile-looking - $REDIR_BAD ($REDIR_TARGET)"

# Merge the followed credential page (see the escalation in Phase 2). Both lines re-derive from
# PAGE_DATA just above, so the override has to land HERE or it gets clobbered. HAS_LOGIN re-arms
# every login-gated floor -- off-CDN third-party host, hotlinked brand artwork, brand-lookalike --
# which is the entire point: the credential surface is what those rules were written to judge.
# Note it adds no red flag of its own; only the followed page's own smells score.
if [ -n "$LOGIN_URL" ]; then
    HAS_LOGIN=true
    [ -n "$LOGIN_SMELLS" ] && SMELLS="${SMELLS:+$SMELLS, }$LOGIN_SMELLS"
fi

# ponytail: An email-redirector link (detected in Phase 1) is only a red flag when we NEVER left it:
# the token was dead/expired/bare and we landed back on the service's own placeholder (or the fetch
# failed) instead of the real destination. A LIVE link redirects off-domain and the landed host's own
# signals carry the verdict, so this must not fire there. Flag = SUSPICIOUS floor (1 flag, no login),
# the honest "couldn't confirm where this actually goes" verdict -- not the phantom-SAFE placeholder.
if [ -n "$REDIRECT_SVC" ]; then
    _land_host=$(printf '%s' "${FINAL_URL:-$URL}" | sed -E 's#^[a-z]+://##;s#[/?].*##' | tr 'A-Z' 'a-z')
    if printf '%s' "$_land_host" | grep -qiE "(^|\.)($REDIRECT_SERVICES)\$"; then
        # A 4xx from the SERVICE ITSELF is not an expired link, it is a withdrawn one. An ESP does
        # not 404 a click id it issued hours ago; it 404s one whose destination its abuse team has
        # since cut off -- which means somebody has already reported this campaign. Verified on
        # this pair: the click link 404s while the OPEN pixel from the same message still answers
        # 200, so the account is alive and only the click-through was severed.
        # Either source of the status: the service usually SERVES its 404 page (so the fetch
        # succeeds and PAGE_STATUS holds it) and only sometimes fails outright.
        _svc_status="${PAGE_ERR_STATUS:-${PAGE_STATUS:-0}}"
        if [ "${_svc_status:-0}" -ge 400 ] 2>/dev/null && [ "${_svc_status:-0}" -lt 500 ] 2>/dev/null; then
            SMELLS="${SMELLS:+$SMELLS, }link-redirection service $REDIRECT_SVC returned HTTP $_svc_status for this link - withdrawn by the service (its destination was cut off) rather than expired"
        else
        SMELLS="${SMELLS:+$SMELLS, }link-redirection service $REDIRECT_SVC - destination unresolved (dead/expired link on a phishing-prone redirector)"
        fi
    fi
fi

# ponytail: Brand-lookalike subdomain on multi-tenant hosting. On these hosts the APEX confers no
# identity -- anyone can register any subdomain -- so a subdomain that spells out the page's OWN
# declared brand (its <title>) or a known brand is an impersonation lure
# (supportimmigrationadviceserviceorg.github.io presenting as "Immigration Advice Service"). The
# static typosquat check above can't catch these: github.io reads as brand-owned (github IS a brand,
# line 205), and its brand list is fixed. Feeds SMELLS -> deterministic floor (SUSPICIOUS; DANGEROUS
# with a login form), so the verdict holds regardless of the LLM.
LOOKALIKE_HOST=$(printf '%s' "${FINAL_URL:-$URL}" | sed -E 's#^[a-z]+://##;s#[/?].*##' | tr 'A-Z' 'a-z')
if printf '%s' "$LOOKALIKE_HOST" | grep -qE '\.(github\.io|pages\.dev|web\.app|firebaseapp\.com|netlify\.app|vercel\.app|workers\.dev|glitch\.me|repl\.co|onrender\.com|surge\.sh|blogspot\.com|wordpress\.com|weebly\.com)$'; then
    _la_apex=$(printf '%s' "$LOOKALIKE_HOST" | grep -oE '[^.]+\.[^.]+$')
    _la_sub=$(printf '%s' "${LOOKALIKE_HOST%.$_la_apex}" | tr -cd 'a-z0-9')  # subdomain, alnum-squashed
    _la_title=$(printf '%s' "$TITLE" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9')     # the page's declared identity
    # Identity to match: the page title (>=8 chars, specific enough) or a known long brand.
    _la_id=""
    if [ ${#_la_title} -ge 8 ] && printf '%s' "$_la_sub" | grep -qF "$_la_title"; then
        _la_id="$_la_title"
    elif printf '%s' "$_la_sub" | grep -qiE "($LONG_B)"; then
        _la_id=$(printf '%s' "$_la_sub" | grep -oiE "($LONG_B)" | head -1)
    fi
    # Fire only when the identity is wrapped in EXTRA lure text (subdomain strictly longer), so a
    # brand's own bare project page (facebook.github.io, johnsmith.github.io titled "John Smith")
    # does NOT trip -- only a dressed-up impersonation (support...org, ...secure-login) does.
    if [ -n "$_la_id" ] && [ ${#_la_sub} -gt ${#_la_id} ]; then
        _la_desc="${TITLE//,/}"   # strip commas: count_red_flags splits SMELLS on commas
        SMELLS="${SMELLS:+$SMELLS, }brand-lookalike subdomain - impersonates \"$_la_desc\" on shared host $_la_apex"
        add_signal "Brand-lookalike subdomain: '$LOOKALIKE_HOST' embeds its own identity \"$TITLE\" on shared host $_la_apex (apex confers no ownership)"
    fi
fi

[ -n "$SUSP_JS" ] && add_signal "Suspicious JS: $SUSP_JS"

# Surface notable page console output (errors / failed requests) -- diagnoses blank SPAs
# and can reveal skimmer debug lines. Full console (incl. logs) is in the cached page.json.
CONSOLE=$(echo "$PAGE_DATA" | jq -r '(.console // []) | map(select(.type=="error" or .type=="pageerror" or .type=="requestfailed")) | .[:8] | .[] | "[\(.type)] \(.text)"' 2>/dev/null)
if [ -n "$CONSOLE" ]; then
    echo ""
    echo "${BOLD}Console${RESET}"
    while IFS= read -r _c; do [ -n "$_c" ] && echo_grey "- $_c"; done <<< "$CONSOLE"
fi

# Off-domain exfil targets the page's code posts to -- with DNS/geo/age. A newly-registered
# target is a strong signal. Cached (exfil.txt) so re-scans skip the lookups.
EXFIL_DOMAINS=$(echo "$PAGE_DATA" | jq -r '(.exfilDomains // []) | .[]' 2>/dev/null)
if [ -n "$EXFIL_DOMAINS" ]; then
    echo ""
    echo "${BOLD}Exfil Targets${RESET}"
    if [ ! -f "$CACHE_DIR/exfil.txt" ]; then
        while IFS= read -r _d; do [ -n "$_d" ] && domain_dns "$_d"; done <<< "$EXFIL_DOMAINS" > "$CACHE_DIR/exfil.txt"
    fi
    while IFS= read -r _line; do
        [ -z "$_line" ] && continue
        echo_grey "- $_line"
        # flag a freshly-registered exfil target (age < 30d) as its own signal
        _age=$(printf '%s' "$_line" | grep -oE 'age [0-9]+d' | grep -oE '[0-9]+')
        [ -n "$_age" ] && [ "$_age" -lt 30 ] 2>/dev/null && add_signal "Exfil target ${_line%% *} is only ${_age}d old (freshly registered)"
    done < "$CACHE_DIR/exfil.txt"
fi

# Redirect chain: phishing bounces a legit host (Azure static, shorteners) through throwaway
# domains. DNS-profile each off-domain hop and flag risky-TLD ones -- the chain infra is the
# signal even when the final hop is dead (404) or CF-gated. Cached in redirect.txt.
ORIG_APEX=$(printf '%s' "$DOMAIN" | grep -oE '[^.]+\.[^.]+$')
CHAIN_HOSTS=$(echo "$PAGE_DATA" | jq -r '(.redirects // []) | .[].url' 2>/dev/null \
    | sed -E 's|https?://([^/]+).*|\1|' | awk 'NF && !seen[$0]++')
if [ "$(printf '%s\n' "$CHAIN_HOSTS" | grep -c .)" -gt 1 ]; then
    echo ""
    echo "${BOLD}Redirect Chain${RESET}"
    if [ ! -f "$CACHE_DIR/redirect.txt" ]; then
        while IFS= read -r _h; do
            [ -z "$_h" ] && continue
            if [ "$(printf '%s' "$_h" | grep -oE '[^.]+\.[^.]+$')" = "$ORIG_APEX" ]; then
                printf '%s (origin)\n' "$_h"
            else
                domain_dns "$_h"
            fi
        done <<< "$CHAIN_HOSTS" > "$CACHE_DIR/redirect.txt"
    fi
    while IFS= read -r _line; do [ -n "$_line" ] && echo_grey "- $_line"; done < "$CACHE_DIR/redirect.txt"
    # Flag off-domain hops on a risky TLD or freshly registered (here-string -> current shell).
    while IFS= read -r _h; do
        [ -z "$_h" ] && continue
        [ "$(printf '%s' "$_h" | grep -oE '[^.]+\.[^.]+$')" = "$ORIG_APEX" ] && continue
        _t=$(printf '%s' "$_h" | grep -oE '\.[a-z]+$' | tr -d '.')
        if is_risky_tld "$_t"; then
            add_signal "Redirect to risky TLD: $_h (.$_t)"
            # also feed the verdict (SMELLS is counted by count_red_flags; SIGNALS is display-only)
            SMELLS="${SMELLS:+$SMELLS, }redirect to risky TLD .$_t"
        fi
    done <<< "$CHAIN_HOSTS"
fi

# === JS deobfuscation escalation ===
# When the scraper flagged obfuscation markers, deobfuscate the cached inline scripts
# (webcrack, sandboxed) and scan the CLEARTEXT for signals the obfuscation was hiding
# (exfil URLs, redirects, cookie theft, crypto). Deterministic, so it runs in both LLM
# and heuristic mode; cached per URL. Gated on -D and on scripts actually being present.
DEOBFUS_SIGNALS=""
# Gate on the _0x marker specifically: obfuscator.io hex-named identifiers are what webcrack
# actually cracks. The weak markers (hex escapes, String.fromCharCode) are emitted by ordinary
# MINIFIERS -- gating on those ran malware heuristics over Closure/Vite bundles and scored a legit
# site's own JS as exfil (youtube.com floored to DANGEROUS on its own accounts.google.com refs).
if [ -z "$NO_DEOBFUS" ] && printf '%s' "$SUSP_JS" | grep -q '_0x' && ls "$CACHE_DIR/scripts"/*.js >/dev/null 2>&1; then
    if [ -f "$CACHE_DIR/deob-signals.txt" ]; then
        DEOBFUS_SIGNALS=$(cat "$CACHE_DIR/deob-signals.txt")
    else
        echo ""
        echo "${BOLD}Deobfuscation${RESET}"
        echo_grey "- obfuscated JS detected; deobfuscating with webcrack (sandboxed)..."
        LANDED_DOMAIN=$(echo "$PAGE_DATA" | jq -r '.domain // ""' 2>/dev/null)
        LANDED_DOMAIN="${LANDED_DOMAIN:-$DOMAIN}"
        for f in "$CACHE_DIR/scripts"/*.js; do
            _clean=$("$SCRIPT_DIR/js-deobfuscate.sh" "$f" 2>/dev/null)
            # ORIG_JS: the source webcrack was handed, so js_signals can tell a REVEALED exfil URL
            # from one that was in plain sight all along (legit minified bundle).
            _s=$(LANDED_DOMAIN="$LANDED_DOMAIN" ORIG_JS="$f" js_signals <<< "$_clean")
            [ -n "$_s" ] && DEOBFUS_SIGNALS+="${DEOBFUS_SIGNALS:+; }$_s"
        done
        printf '%s' "$DEOBFUS_SIGNALS" > "$CACHE_DIR/deob-signals.txt"
    fi
    # Each deobfuscated finding becomes its own signal (split on the ", " / "; " joiners).
    # Process substitution (not a pipe) so the appends survive in the current shell.
    if [ -n "$DEOBFUS_SIGNALS" ]; then
        while IFS= read -r _sig; do
            [ -n "$_sig" ] && add_signal "deobfuscated JS: $_sig"
        done < <(printf '%s\n' "$DEOBFUS_SIGNALS" | sed 's/; /\n/g; s/, /\n/g')
    fi
fi

# Suspicious-JS markers are only a TRIGGER for deobfuscation. If that ran and revealed nothing
# malicious (same-domain assets only), the marker is cleared -- mirror verdict.sh so the LLM prompt
# below doesn't re-count it as a red flag (minified Vite/webpack bundles use String.fromCharCode).
JS_CLEARED=""
if [ -n "$SUSP_JS" ] && [ -n "$DEOBFUS_SIGNALS" ] \
   && ! printf '%s' "$DEOBFUS_SIGNALS" | grep -qiE 'off-domain URL|JS redirect|crypto wallet'; then
    JS_CLEARED=1
fi

# === What we already know about this host ===
# The feedback ledger is a free, offline prior: kits rotate paths and query strings behind one
# hostname, so a credential harvester settled at /login is evidence about /verify tomorrow.
# feedback-report.sh --host keys on the FULL host, never the apex (see there for why).
# Only an INSPECTED DANGEROUS becomes a red flag. `agree` is one keypress -- Enter is the default
# answer -- and a prior SUSPICIOUS is often just this tool's own uncertainty, so feeding either
# back into the floor would let a host ratchet itself up on its own output. The rest is context.
# Cap: this is ONE red flag, so alone it floors to SUSPICIOUS. A compromised legitimate host still
# serves real pages on other paths; the page's own evidence is what takes it to DANGEROUS.
# Widen to the whole registrable domain when that domain means ONE owner: a kit rotates
# subdomains as freely as paths (lxu438.getnew.space and tyu620.getnew.space, one day apart).
# Not when the apex is shared hosting -- see is_tenant_suffix. psl.sh already stops most of those
# (github.io and friends ARE public suffixes, so apex_of returns the tenant host and this is a
# no-op), and TENANT_SUFFIXES covers what the PSL misses.
_prior_scope="$DOMAIN"; _prior_q=(--host "$DOMAIN")
if [ "$APEX_DOMAIN" != "$DOMAIN" ] && ! is_tenant_suffix "$APEX_DOMAIN"; then
    _prior_scope="$APEX_DOMAIN (all subdomains)"; _prior_q=(--apex "$APEX_DOMAIN")
fi
HOST_PRIORS=$("$SCRIPT_DIR/feedback-report.sh" "${_prior_q[@]}" "$URL" 2>/dev/null)
if [ -n "$HOST_PRIORS" ]; then
    echo ""
    echo "${BOLD}Prior judgements on $_prior_scope${RESET}"
    _host_bad="" _host_susp=""
    while IFS=$'\t' read -r _pv _ps _pu _pn _pc; do
        [ -z "$_pv" ] && continue
        echo_grey "- $_pv${_pc:+/$_pc} ($_ps): $_pu"
        [ -n "$_pn" ] && printf '%s\n' "$_pn" | fold -s -w 92 | sed "s/^/    ${GREY}/;s/\$/${RESET}/"
        [ "$_ps" = "inspected" ] && case "$_pv" in
            DANGEROUS)  [ -z "$_host_bad" ]  && _host_bad="$_pu" ;;
            SUSPICIOUS) [ -z "$_host_susp" ] && _host_susp="$_pu" ;;
        esac
    done <<< "$HOST_PRIORS"
    # commas separate smells for count_red_flags, and urls may contain them.
    # A settled DANGEROUS sibling is an ordinary red flag; a settled SUSPICIOUS one is capped at
    # SUSPICIOUS by verdict.sh and excluded from the count (see priorsusp there).
    _prior_smell() {   # <wording> <url>
        local where=host
        printf '%s' "$2" | grep -qE "^[a-z]+://$(printf '%s' "$DOMAIN" | sed 's/\./\\./g')([/:?#]|$)" || where=domain
        SMELLS="${SMELLS:+$SMELLS, }$1 on this $where ($(printf '%s' "$2" | tr ',' ' '))"
    }
    if [ -n "$_host_bad" ]; then
        _prior_smell "Confirmed phishing previously inspected" "$_host_bad"
    elif [ -n "$_host_susp" ]; then
        _prior_smell "A sibling url was previously inspected as suspicious" "$_host_susp"
    fi
    HOST_PRIORS_LLM=$(printf '%s' "$HOST_PRIORS" | awk -F'\t' '{ printf "%s%s (%s) %s", sep, $1, $2, $3; sep="; " }')
fi

# === Same campaign tag, any domain ===
# The last thing that survives a domain rotation is the affiliate / sub-id tag in the link. Ten
# throwaway domains carrying ?s1=upg12 are one operator, and neither the host nor the apex rollup
# can see that, because the domains share nothing. Only runs when this domain is otherwise unknown
# to us: with a settled sibling on the domain itself the smell is already recorded, and a second
# one would double-count as two red flags for what is one piece of evidence.
if [ -z "$_host_bad" ] && [ -z "$_host_susp" ]; then
    _ckey=$(campaign_key "${FINAL_URL:-$URL}")
    [ -z "$_ckey" ] && _ckey=$(campaign_key "$URL")
    _camp=""
    [ -n "$_ckey" ] && _camp=$("$SCRIPT_DIR/feedback-report.sh" --campaign "$_ckey" "$URL" 2>/dev/null)
    if [ -n "$_camp" ]; then
        echo ""
        echo "${BOLD}Same campaign tag ($_ckey) seen before${RESET}"
        _camp_bad="" _camp_susp=""
        while IFS=$'\t' read -r _pv _ps _pu _pn _pc; do
            [ -z "$_pv" ] && continue
            echo_grey "- $_pv${_pc:+/$_pc} ($_ps): $_pu"
            [ -n "$_pn" ] && printf '%s\n' "$_pn" | fold -s -w 92 | sed "s/^/    ${GREY}/;s/\$/${RESET}/"
            [ "$_ps" = "inspected" ] && case "$_pv" in
                DANGEROUS)  [ -z "$_camp_bad" ]  && _camp_bad="$_pu" ;;
                SUSPICIOUS) [ -z "$_camp_susp" ] && _camp_susp="$_pu" ;;
            esac
        done <<< "$_camp"
        # Same two shapes as the domain rollup: a settled DANGEROUS match is an ordinary red flag,
        # a settled SUSPICIOUS one is capped at SUSPICIOUS by verdict.sh (the wording carries it).
        if [ -n "$_camp_bad" ]; then
            SMELLS="${SMELLS:+$SMELLS, }Confirmed phishing previously inspected under the same campaign tag $_ckey ($(printf '%s' "$_camp_bad" | tr ',' ' '))"
        elif [ -n "$_camp_susp" ]; then
            SMELLS="${SMELLS:+$SMELLS, }A url under the same campaign tag $_ckey was previously inspected as suspicious ($(printf '%s' "$_camp_susp" | tr ',' ' '))"
        fi
        CAMPAIGN_LLM=$(printf '%s' "$_camp" | awk -F'\t' '{ printf "%s%s (%s) %s", sep, $1, $2, $3; sep="; " }')
    fi
fi

# === Third-party reputation (opt-in: -t) ===
# ponytail: OFF by default and absent from benchmarks (they never pass -t). Extra external
# verification for manual scans. Needs only the URL, so it runs even with -s. Cached per URL
# (respects -r) like every other network lookup. A confirmed-malicious hit feeds the
# deterministic floor via SMELLS, exactly like the redirect-to-risky-TLD signal above.
VT_SUMMARY=""; URLSCAN_SUMMARY=""
if [ -n "$VT" ]; then
    echo ""
    # "cached" when a prior -t run already populated either provider's cache (mirrors Domain Info)
    _rep_tag="third-party"
    { [ -s "$CACHE_DIR/virustotal.json" ] || [ -s "$CACHE_DIR/urlscan.json" ]; } && _rep_tag="third-party, cached"
    echo "${BOLD}Reputation ($_rep_tag)${RESET}"
    # Load API keys from .env (see .env.sample). set -a so sourced KEY=val lines export.
    [ -f "$SCRIPT_DIR/.env" ] && { set -a; . "$SCRIPT_DIR/.env"; set +a; }

    # display signal + feed the safety floor. Detail must stay comma-free (count_red_flags
    # splits SMELLS on commas and counts each non-empty piece as one red flag).
    rep_redflag() {  # <provider> <detail-no-commas>
        add_signal "$1 flagged this URL malicious: $2"
        SMELLS="${SMELLS:+$SMELLS, }$1 flagged malicious ($2)"
    }

    # --- VirusTotal (needs VT_API_KEY; https://docs.virustotal.com/reference/overview) ---
    if [ -z "${VT_API_KEY:-}" ]; then
        echo_grey "- VirusTotal: no VT_API_KEY (add it to $SCRIPT_DIR/.env) -- skipped"
    else
        if [ ! -s "$CACHE_DIR/virustotal.json" ]; then
            # v3 URL id = base64url(url) without '=' padding.
            _vtid=$(printf '%s' "$URL" | base64 -w0 | tr '+/' '-_' | tr -d '=')
            curl -s --max-time 20 -H "x-apikey: $VT_API_KEY" \
                "https://www.virustotal.com/api/v3/urls/$_vtid" > "$CACHE_DIR/virustotal.json" 2>/dev/null
        fi
        _vtstats=$(jq -r '.data.attributes.last_analysis_stats // empty' "$CACHE_DIR/virustotal.json" 2>/dev/null)
        if [ -z "$_vtstats" ]; then
            echo_grey "- VirusTotal: $(jq -r '.error.message // "URL not in VirusTotal (never submitted)"' "$CACHE_DIR/virustotal.json" 2>/dev/null)"
            rm -f "$CACHE_DIR/virustotal.json"   # a miss/error is not a result -> don't cache it
        else
            _vm=$(jq -r '.data.attributes.last_analysis_stats.malicious // 0' "$CACHE_DIR/virustotal.json")
            _vs=$(jq -r '.data.attributes.last_analysis_stats.suspicious // 0' "$CACHE_DIR/virustotal.json")
            _vt=$(jq -r '.data.attributes.last_analysis_stats | add // 0' "$CACHE_DIR/virustotal.json")
            VT_SUMMARY="$_vm/$_vt engines malicious, $_vs suspicious"
            echo_grey "- VirusTotal: $VT_SUMMARY  (https://www.virustotal.com/gui/url/$(printf '%s' "$URL" | sha256sum | cut -d' ' -f1))"
            [ "${_vm:-0}" -gt 0 ] 2>/dev/null && rep_redflag VirusTotal "$_vm vendors"
        fi
    fi

    # --- urlscan.io (public search only; URLSCAN_API_KEY optional, raises rate limits) ---
    _uhdr=(); [ -n "${URLSCAN_API_KEY:-}" ] && _uhdr=(-H "API-Key: ${URLSCAN_API_KEY}")
    if [ ! -s "$CACHE_DIR/urlscan.json" ]; then
        # Search existing public scans for this exact URL; take the most recent one's verdict.
        _uuid=$(curl -s --max-time 15 "${_uhdr[@]}" -G "https://urlscan.io/api/v1/search/" \
            --data-urlencode "q=page.url:\"$URL\"" 2>/dev/null | jq -r '.results[0]._id // empty' 2>/dev/null)
        [ -n "$_uuid" ] && curl -s --max-time 15 "${_uhdr[@]}" \
            "https://urlscan.io/api/v1/result/$_uuid/" > "$CACHE_DIR/urlscan.json" 2>/dev/null
    fi
    if [ -z "$(jq -r '.verdicts.overall // empty' "$CACHE_DIR/urlscan.json" 2>/dev/null)" ]; then
        echo_grey "- urlscan.io: no prior public scan for this URL"
        rm -f "$CACHE_DIR/urlscan.json"
    else
        _um=$(jq -r '.verdicts.overall.malicious // false' "$CACHE_DIR/urlscan.json")
        _usc=$(jq -r '.verdicts.overall.score // 0' "$CACHE_DIR/urlscan.json")
        # verdicts.engines is a SEPARATE judgement (urlscan's own ML classifier plus any engine
        # verdicts) and it routinely calls a page malicious while verdicts.overall stays at 0.
        # Reading only .overall silently discarded a malicious/score-96 call on healthlynotes.com.
        _uem=$(jq -r '.verdicts.engines.malicious // false' "$CACHE_DIR/urlscan.json")
        _uesc=$(jq -r '.verdicts.engines.score // 0' "$CACHE_DIR/urlscan.json")
        _utime=$(jq -r '.task.time // "?"' "$CACHE_DIR/urlscan.json" | cut -dT -f1)
        URLSCAN_SUMMARY="overall malicious=$_um score $_usc, engines malicious=$_uem score $_uesc (last scan $_utime)"
        echo_grey "- urlscan.io: $URLSCAN_SUMMARY  (https://urlscan.io/search/#page.url:%22$URL%22)"
        # Named separately in the flag text so the analyst can weigh an ML call differently from a
        # community/engine consensus. Either one alone is one red flag, never two.
        if [ "$_um" = "true" ]; then
            rep_redflag urlscan.io "overall score $_usc"
        elif [ "$_uem" = "true" ]; then
            rep_redflag "urlscan.io engines" "ML score $_uesc"
        fi
    fi
fi

# === PHASE 3: LLM Analysis (skipped in heuristic mode: -H, -m heuristic, or menu option 0) ===
VERDICT=""   # default; only a real LLM run overrides it. Heuristic modes leave it empty.
if [ -z "$HEURISTIC" ]; then
echo ""
echo "${BOLD}Model${RESET}"
if _is_claude "$MODEL"; then
    _load_env
    [ -z "${ANTHROPIC_API_KEY:-}" ] && { echo "  No ANTHROPIC_API_KEY (add it to $SCRIPT_DIR/.env) -- needed for $MODEL"; exit 1; }
    MODEL=$(_claude_id "$MODEL")   # normalise the bare 'claude' alias -> id (label + cache key)
    echo_grey "- $MODEL (Anthropic API)"
else
    ensure_ollama || exit 1
fi

# -m auto -> best benchmarked model (falls back to qwen2.5:1.5b if no benchmark data yet).
# Guard: if that model isn't actually installed, drop to the first installed one.
if [ "$MODEL" = auto ]; then
    MODEL=$(best_model)
    [ -z "$MODEL" ] && MODEL="qwen2.5:1.5b"
    INSTALLED=($(docker exec llm-spam-test ollama list 2>/dev/null | awk 'NR>1 {print $1}'))
    if ! printf '%s\n' "${INSTALLED[@]}" | grep -qxF "$MODEL"; then
        [ ${#INSTALLED[@]} -eq 0 ] && { echo "auto: no models installed (is llm-spam-test running?)"; exit 1; }
        echo "auto: best model '$MODEL' not installed -> using '${INSTALLED[0]}'"
        MODEL="${INSTALLED[0]}"
    fi
    echo_grey "- $MODEL (auto)"
fi

if [ -z "$MODEL" ]; then
    MODELS=($(docker exec llm-spam-test ollama list 2>/dev/null | awk 'NR>1 {print $1}'))
    if [ ${#MODELS[@]} -eq 0 ]; then
        echo "  No models available (is llm-spam-test container running?)"
        exit 1
    fi
    # Default = best benchmarked model if it's installed, else the first one. Enter picks it.
    DEFAULT=$(best_model); [ -z "$DEFAULT" ] && DEFAULT="qwen2.5:1.5b"
    printf '%s\n' "${MODELS[@]}" | grep -qxF "$DEFAULT" || DEFAULT="${MODELS[0]}"
    echo "Available models:"
    echo "  0: none (pure heuristic, no LLM)"
    for i in "${!MODELS[@]}"; do
        [ "${MODELS[$i]}" = "$DEFAULT" ] && tag=" (best)" || tag=""
        echo "  $((i+1)): ${MODELS[$i]}$tag"
    done
    echo ""
    read -p "${CYAN}Select model (0-${#MODELS[@]}) [Enter = $DEFAULT]: ${RESET}" SEL
    if [ "$SEL" = 0 ]; then
        HEURISTIC=1        # pure heuristic: no LLM, verdict from the decision table
    elif [ -z "$SEL" ]; then
        MODEL="$DEFAULT"
    else
        MODEL="${MODELS[$((SEL-1))]}"
    fi
    if [ -z "$MODEL" ] && [ -z "$HEURISTIC" ]; then
        echo "Invalid selection."
        exit 1
    fi
fi

# Everything below runs only for a real model pick -- the menu (option 0) may have just
# switched us to heuristic mode, so re-check before spending the vision/LLM calls.
if [ -z "$HEURISTIC" ]; then

# === Vision escalation ===
# The VLM "sees" the rendered page: it catches (a) visual brand-clones that DOM scraping
# can't, and (b) a credential input the DOM missed (kits use non-password inputs / shadow
# DOM to dodge detection). Trigger on a detected login form OR when a form is present with a
# login-ish / exfil context. Gated on -V, a screenshot, and the model being installed.
VISION_NOTE=""
VISION_TRIGGER=""
[ "$HAS_LOGIN" = "true" ] && VISION_TRIGGER=1
if [ -z "$VISION_TRIGGER" ] && [ "${FORMS:-0}" -gt 0 ] \
   && printf '%s %s %s' "$TITLE" "$URL" "$SMELLS" | grep -qiE 'log[ -]?in|sign[ -]?in|password|account|webmail|secure|verif|credential|exfil|obfuscated network|excel|office|outlook|microsoft|onedrive'; then
    VISION_TRIGGER=1
fi
if [ -z "$NO_VISION" ] && [ -n "$VISION_TRIGGER" ]; then
    if [ -f "$CACHE_DIR/vision.txt" ]; then
        # Reuse the cached VLM verdict (the ~1min call is the single most expensive step).
        VISION_NOTE=$(cat "$CACHE_DIR/vision.txt")
    elif [ -f "$SHOT" ]; then
        # Compare the brand against the domain we ACTUALLY landed on (post-redirect), not the
        # entry/cloaker domain -- phishing routinely enters via a shortener/tracker.
        LANDED_DOMAIN=$(echo "$PAGE_DATA" | jq -r '.domain // ""' 2>/dev/null)
        LANDED_DOMAIN="${LANDED_DOMAIN:-$DOMAIN}"
        VP="This screenshot is the web page served at domain '$LANDED_DOMAIN'. Answer concisely in two lines:
BRAND: what brand/company does its visual design (logo, colours, layout) imitate, and does it match the domain '$LANDED_DOMAIN'? If a well-known brand's page is served from an unrelated domain, say so.
PASSWORD: is a password or login/credential input field visible on the page? Reply exactly 'PASSWORD: yes' or 'PASSWORD: no'."
        VRESP=""
        if _is_claude "$VISION_MODEL"; then
            echo_grey "- visual check (brand + credential input) via $(_claude_id "$VISION_MODEL") (Anthropic API)..."
            VRESP=$(_claude_vision "$SHOT" "$VP")
        elif docker exec llm-spam-test ollama list 2>/dev/null | grep -q "$VISION_MODEL"; then
            echo_grey "- visual check (brand + credential input) via $VISION_MODEL (~1min on CPU)..."
            # think:false  we want a crisp verdict, not a reasoning essay. Without it the
            # model's <think> ramble gets truncated by num_predict and leaks in as the "answer".
            VRESP=$(base64 -w0 "$SHOT" | jq -Rs --arg m "$VISION_MODEL" --arg p "$VP" \
                '{model:$m,prompt:$p,images:[.],think:false,options:{temperature:0,num_predict:200},stream:false}' \
                | curl -s --max-time 180 http://localhost:11434/api/generate -d @- | jq -r '.response // ""')
        fi
        if [ -n "$VRESP" ]; then
            # belt-and-braces: strip a <think> block if the model emits one anyway
            VISION_NOTE=$(echo "$VRESP" | sed '/<think>/,/<\/think>/d' | tr -s '[:space:]' ' ' | sed 's/^ *//;s/ *$//')
            printf '%s' "$VISION_NOTE" > "$CACHE_DIR/vision.txt"
        fi
    fi
    if [ -n "$VISION_NOTE" ]; then
        echo_grey "- $VISION_NOTE"
        # Double-check: if the VLM sees a credential field the DOM missed, treat it as a login
        # page so the verdict floor (login + red flag) can fire. Match only 'PASSWORD: yes'.
        if [ "$HAS_LOGIN" != "true" ] && echo "$VISION_NOTE" | grep -qiE 'PASSWORD:?[[:space:]]*yes'; then
            add_signal "Vision: credential input visible (DOM detection missed it)"
            HAS_LOGIN=true
        fi
        # Visual brand impersonation: the VLM says the page imitates a known brand that does NOT
        # own the landed domain -- credential phishing's core tell, and the text-based brand smell
        # misses it when the brand appears only as a logo/image (not in title/form-action). Feed it
        # to the deterministic floor via SMELLS (comma-free), exactly like the redirect-to-risky-TLD
        # signal -- so with a login form it floors to DANGEROUS instead of relying on the LLM.
        # Primary: the structured 'BRAND_MATCH: no' token. Fallback: the VLM's free text (it doesn't
        # always emit the token) saying the design belongs to a brand unrelated to the landed domain.
        if echo "$VISION_NOTE" | grep -qiE 'BRAND_MATCH:?[[:space:]]*no\b' \
           || echo "$VISION_NOTE" | grep -qiE '(does not|doesn.?t|not) match|unrelated (to the )?domain|different (brand|company) (than|from) the domain'; then
            add_signal "Visual brand impersonation: page imitates a brand not owned by $LANDED_DOMAIN"
            SMELLS="${SMELLS:+$SMELLS, }visual brand impersonation - imitates a brand not owned by $LANDED_DOMAIN"
        fi
    fi
fi

# Did the page actually redirect? (only true if final URL differs from the requested one)
if [ -n "$FINAL_URL" ] && [ "$FINAL_URL" != "null" ] && [ "$FINAL_URL" != "$URL" ]; then
    IS_REDIRECT="yes -> $FINAL_URL"
else
    IS_REDIRECT="no"
fi

# Classify the URL path so the model doesn't confuse an unsubscribe link with a login page
if echo "$URL" | grep -qiE 'unsub|opt[-_]?out|list[-_]?manage|/remove|mailpref|newsletter'; then
    URL_KIND="mailing-list / unsubscribe endpoint. The query token typically base64-encodes a per-recipient id, so a click mainly CONFIRMS the address is live (list validation) rather than stealing credentials."
else
    URL_KIND="general web page"
fi

# The weak 1.5b LLM counts every item under "Phishing smells" as a red flag even when the prompt
# says not to, so hand it a filtered list that drops the smells verdict.sh:33 excludes --
# hidden-field COUNT, the third-party-hosts note and hotlinked brand artwork (all normal on legit
# sites). The deterministic core and the display signals still get the full SMELLS; this only
# removes the LLM's miscount fuel. Keep this list in sync with count_red_flags.
SMELLS_LLM=$(printf '%s' "$SMELLS" | tr ',' '\n' | sed 's/^ *//;s/ *$//' \
    | grep -viE 'hidden form field|third-party hosts referenced|hotlinked brand image' \
    | awk 'NF{a[n++]=$0} END{for(i=0;i<n;i++)printf "%s%s",(i?", ":""),a[i]}')

# The weak 1.5b LLM miscounts a CLEAN reputation line ("0/95 engines malicious") as a red flag,
# so only feed reputation to the LLM when it is actually adverse. An adverse hit already forces
# the floor via SMELLS/rep_redflag, so the LLM never needs the clean case (see llm-recounts note).
VT_LLM=""; { [ "${_vm:-0}" -gt 0 ] || [ "${_vs:-0}" -gt 0 ]; } 2>/dev/null && VT_LLM="$VT_SUMMARY"
URLSCAN_LLM=""; { [ "${_um:-false}" = "true" ] || [ "${_uem:-false}" = "true" ]; } && URLSCAN_LLM="$URLSCAN_SUMMARY"

# The 1.5b does not evaluate a rule's precondition -- it fires whichever rule is listed FIRST and
# parrots its text. It claimed "Login form present AND red flag count = 1" on a blank page with 0
# forms, and "Login form present" on wikipedia.org (which has none; that one landed SAFE by luck).
# So never ask it to count or to check a precondition: count_red_flags() already computes this
# deterministically for the safety floor, so reuse that number and hand it in as ground truth.
# Must stay ABOVE the CONTEXT build below, which interpolates it.
FLAGS_LLM=$(count_red_flags "$TLD" "${AGE_DAYS}" "$FINAL_URL" "$SMELLS" "$SUSP_JS" "$DEOBFUS_SIGNALS")

CONTEXT="URL: $URL
Domain: $DOMAIN
TLD: $TLD

EXTRACTED SIGNALS (these are the ground truth - do not assume anything not listed here):
- URL type: $URL_KIND
- Domain age (days): ${AGE_DAYS:-unknown}
- SSL cert age (days): ${CERT_AGE_DAYS:-unknown}
- A records / DNS TTL: ${A_RECORDS:-?} records, TTL ${TTL:-?}s
- Login or password form present: $HAS_LOGIN
- Total forms on page: $FORMS  (login forms: $LOGIN_FORMS)
- Redirected to a different URL: $IS_REDIRECT
- Suspicious JS: ${SUSP_JS:-none}${JS_CLEARED:+ (deobfuscated to same-domain assets only - NOT a red flag)}
- Deobfuscated JS signals (hidden by obfuscation, revealed by webcrack): ${DEOBFUS_SIGNALS:-none}
- Phishing smells flagged by scraper: ${SMELLS_LLM:-none}
- Red flag count: $FLAGS_LLM  (authoritative - already counted from these signals, use as-is)
- VirusTotal reputation: ${VT_LLM:-not checked}
- urlscan.io reputation: ${URLSCAN_LLM:-not checked}
- Prior analyst judgements on this domain: ${HOST_PRIORS_LLM:-none}
- Prior analyst judgements on the same campaign tag: ${CAMPAIGN_LLM:-none}
- Third-party domains loaded: ${THIRD_PARTY:-0}
- Visual brand check (vision model looking at the rendered page): ${VISION_NOTE:-not run}
- Page title: \"$TITLE\""

if [ "$HAS_LOGIN" = "true" ]; then
    LOGIN_FACT="This page HAS a login/password form. A login form is NORMAL and expected on legitimate sites (Google, banks, webmail). A login form BY ITSELF is not dangerous - it is only dangerous when combined with a red flag."
    RULES="RULE 1: the RED FLAG COUNT is 1 or more.
   -> VERDICT: DANGEROUS. A login form plus even ONE red flag is credential harvesting. You must NOT downgrade this to SUSPICIOUS or SAFE, no matter what else you think. It does NOT need a redirect to be DANGEROUS.

RULE 2: the RED FLAG COUNT is exactly 0.
   -> VERDICT: SAFE. This is a normal legitimate login page."
else
    LOGIN_FACT="This page has NO login form and NO password field on it. There is NO credential form here. Do NOT say a login form is present and do NOT reason about one."
    RULES="RULE 3: the RED FLAG COUNT is 1 or more, OR this is a mailing-list / unsubscribe endpoint.
   -> VERDICT: SUSPICIOUS (e.g. list-validation: a click confirms your address to spammers).

RULE 4: the RED FLAG COUNT is exactly 0.
   -> VERDICT: SAFE."
fi

SYSTEM_PROMPT="You are a strict cybersecurity analyst. Classify this URL using ONLY the EXTRACTED SIGNALS provided. Do NOT invent facts: if 'Redirected' is 'no' there is NO redirect. Never assume a redirect or a page feature that is not listed.

$LOGIN_FACT

The RED FLAG COUNT has ALREADY been computed for you and is given in the signals as 'Red flag count'. Use that number exactly as given. Do NOT recount it, do NOT adjust it, do NOT infer your own. For reference only, these are what it already counted:
- off-domain form submit
- brand impersonation (brand named but not the real domain)
- visual brand mismatch: the 'Visual brand check' says the page LOOKS like a known brand (its logo/design) but that brand does not match the domain
- risky TLD (.cfd .xyz .top .lol .sbs .icu .buzz .monster etc.)
- IP fingerprinting
- sensitive field names (ssn, cvv, routing, etc.)
- domain age under 90 days
- suspicious JS (eval, atob, hex-encoded, document.write) -- but do NOT count it if the Suspicious JS line says it was deobfuscated to same-domain assets
- deobfuscated JS that reveals an off-domain exfil URL, a JS redirect, or cookie/credential theft
- redirect to wp-content / wp-include / random path
- any phishing smell flagged by the scraper, EXCEPT the two below

NOT red flags (do NOT count these, no matter how many -- legitimate sites routinely have them):
- hidden form fields / 'N hidden form fields' (CSRF and tracking tokens; GitHub has 40+). The COUNT is never a red flag; only 'sensitive field names' above counts.
- third-party hosts / domains loaded (analytics, ads, CDNs -- e.g. Google Tag Manager, DoubleClick, Microsoft Clarity). A high count is normal instrumentation, not exfil.

Read the 'Red flag count' from the signals, then apply the ONE rule below that matches that number. These are the ONLY rules that apply to this page; do not consider any other rule:

$RULES

Reply with EXACTLY these two lines and nothing else:
REASON: one short sentence -- the Red flag count from the signals, and which RULE fired
VERDICT: SAFE or VERDICT: SUSPICIOUS or VERDICT: DANGEROUS"

# One Ollama inference for the current MODEL/SYSTEM_PROMPT/CONTEXT at temperature $1.
# Echoes the raw .response (or an error stub). Used by the main call and the empty-verdict retry.
_llm_infer() {
    _is_claude "$MODEL" && { _claude_infer "$@"; return; }
    curl -s --max-time 180 -X POST http://localhost:11434/api/generate \
        --data-raw "{\"model\":\"$MODEL\",\"system\":$(echo "$SYSTEM_PROMPT" | jq -Rs .),\"prompt\":$(echo "$CONTEXT" | jq -Rs .),\"think\":false,\"options\":{\"temperature\":${1:-0.0},\"num_predict\":512},\"stream\":false,\"keep_alive\":\"5m\"}" \
        | jq -r '.response // "Error: No response from model"' 2>/dev/null
}
# A parseable verdict, uppercased, or empty. Case-insensitive so a lowercase reply still counts.
_parse_verdict() { printf '%s' "$1" | grep -oiE 'VERDICT:[[:space:]]*(SAFE|SUSPICIOUS|DANGEROUS)' | grep -oiE 'SAFE|SUSPICIOUS|DANGEROUS' | head -1 | tr 'a-z' 'A-Z'; }

# Cache the LLM answer keyed by model + full request (system+context). Same URL + same
# model -> same signals -> same answer, so re-scans reuse it. -r wipes the cache dir.
LLM_CACHE="$CACHE_DIR/llm-$(printf '%s' "$MODEL|$SYSTEM_PROMPT|$CONTEXT" | sha256sum | cut -c1-16).txt"
# NO_LLM_CACHE=1 forces a real inference (still writes the cache) -- the benchmark sets it
# so its timings measure the model, not a cache hit.
if [ -z "${NO_LLM_CACHE:-}" ] && [ -f "$LLM_CACHE" ]; then
    RESPONSE=$(cat "$LLM_CACHE")
    LLM_LABEL="cached"
else
    echo_grey "- LLM analyzing..."
    LLM_START=$(date +%s.%N)
    RESPONSE=$(_llm_infer 0.0)
    LLM_SECS=$(echo "$(date +%s.%N) - $LLM_START" | bc)
    # cache only a verdict-bearing answer -- never the error stub or a verdict-less reply, so a
    # transient failure / no-verdict re-infers next scan instead of sticking as a cached blank.
    [ -n "$(_parse_verdict "$RESPONSE")" ] && printf '%s' "$RESPONSE" > "$LLM_CACHE"
    LLM_LABEL=$(printf '%.1fs' "$LLM_SECS")
fi

echo ""
# Reasoning models wrap their chain-of-thought in <think>...</think>. Surface it as
# an explicit audit trail (why it decided) instead of dumping it into the analysis.
# ponytail: assumes <think> tags sit on their own lines (true for minicpm/qwen); a
# same-line </think>text would over-trim -- revisit if a model emits that.
THINK=$(echo "$RESPONSE" | sed -n '/<think>/,/<\/think>/p' | sed '1d;$d')
BODY=$(echo "$RESPONSE" | sed '/<think>/,/<\/think>/d')
if [ -n "$THINK" ]; then
    echo "${CYAN}=== [reasoning] Model Reasoning ===${RESET}"
    echo "$THINK"
    echo ""
fi
printf "${BOLD}LLM Analysis (%s, %s)${RESET}\n" "$MODEL" "$LLM_LABEL"
_llm_body=$(echo "$BODY" | sed '/^VERDICT:/d; s/^REASON:[[:space:]]*//')
if [ -n "$(printf '%s' "$_llm_body" | tr -d '[:space:]')" ]; then
    while IFS= read -r _l; do
        [ -n "$_l" ] && echo_grey "- $_l"
    done <<< "$_llm_body"
else
    # Terse models (e.g. qwen2.5:1.5b) often emit only the VERDICT line, no prose.
    echo_grey "- (verdict only, no explanation from the model)"
fi

VERDICT=$(_parse_verdict "$BODY")

# Empty verdict = the model RAN but emitted no parseable VERDICT (qwen2.5:1.5b sometimes returns
# nothing). Retry once at a nudged temperature so the sampler escapes the degenerate no-verdict
# output; a working model should classify the page. If it STILL says nothing, a credential-
# harvesting surface must not present as a benign-looking UNCLEAR -> floor a login page to
# SUSPICIOUS. Only reachable on a real LLM run (heuristic mode never enters this block), so this
# never turns -H's intentional "no LLM" into SUSPICIOUS.
if [ -z "$VERDICT" ]; then
    echo_grey "- model returned no verdict; retrying once..."
    RESPONSE=$(_llm_infer 0.4)
    BODY=$(echo "$RESPONSE" | sed '/<think>/,/<\/think>/d')
    VERDICT=$(_parse_verdict "$BODY")
    if [ -n "$VERDICT" ]; then
        printf '%s' "$RESPONSE" > "$LLM_CACHE"
        echo_grey "- retry verdict: $VERDICT"
    else
        echo_grey "- still no verdict (UNCLEAR here means 'model did not assess', not 'safe')"
        [ "$HAS_LOGIN" = "true" ] && { VERDICT=SUSPICIOUS; echo_grey "- login form present -> flooring to SUSPICIOUS pending assessment"; }
    fi
fi
fi   # end real-LLM path (inner heuristic guard)
fi   # end PHASE 3 (outer heuristic guard)

# === Consolidated signal list ===
# Every signal gathered across the phases, printed together as one bullet list instead
# of sprinkled through the output. Gray detail; the colored verdict banner carries severity.
echo ""
echo "${BOLD}Signals (${#SIGNALS[@]}):${RESET}"
if [ ${#SIGNALS[@]} -gt 0 ]; then
    for _s in "${SIGNALS[@]}"; do echo_grey "- $_s"; done
else
    echo_grey "- none detected"
fi

# Offer to open the page screenshot for human validation (interactive terminal + GUI only).
# After the signals list; outside the LLM guard so heuristic mode offers it too. The
# screenshot persists in the cache dir.
if [ -f "$SHOT" ] && [ -t 0 ] && command -v xdg-open >/dev/null 2>&1; then
    echo ""
    read -r -p "${CYAN}Open page screenshot for manual review? [y/N] ${RESET}" _ans
    [[ "$_ans" =~ ^[Yy] ]] && { xdg-open "$SHOT" >/dev/null 2>&1 & }
fi

# The scanner cannot clear a page it never saw. An error status or an empty DOM makes any SAFE --
# from the LLM or from the no-signal default -- a phantom, so drop it to UNCLEAR here and let the
# floor below still escalate on whatever static signals exist. Same failure shape as the data: URL
# guard in page-fetch.sh: a dead target reads as a clean page.
if [ -n "$PAGE_FETCHED" ] && is_blank_page "$PAGE_STATUS" "$PAGE_ELEMS"; then
    echo_yellow "[!] No assessable page (HTTP ${PAGE_STATUS:-?}, ${PAGE_ELEMS:-0} DOM elements) -- cannot call this SAFE"
    VERDICT=""
fi
# Same rule one step earlier: the host did not resolve, so there was no page to fetch at all. The
# scan holds nothing but the url itself, and "no facts" is not evidence of innocence -- a phish
# whose host is already sinkholed or rotated away must not read SAFE the day after it worked.
if [ -n "$NO_DNS" ]; then
    echo_yellow "[!] Host does not resolve -- nothing was fetched, so this cannot be called SAFE"
    VERDICT=""
fi

# === Deterministic verdict (classify_verdict in verdict.sh) ===
# Signals are extracted deterministically upstream, so the final verdict is
# decided by the decision table in verdict.sh -- it escalates over the LLM's
# verdict but never downgrades. The "[floor] Safety floor" notice goes to stderr.
VERDICT=$(classify_verdict "$HAS_LOGIN" "$TLD" "${AGE_DAYS}" "$FINAL_URL" "$URL" "$SMELLS" "$SUSP_JS" "$DEOBFUS_SIGNALS" "$VERDICT")

# A prior deep inspection is the strongest context available on a re-scan: a human (or a claude
# triage) already read the artifacts and settled this URL. Its verdict therefore REPLACES the
# freshly computed one, in either direction -- that is what makes a known false positive stop
# shouting DANGEROUS, and a missed phish stop reading SAFE, from the second scan on.
# ponytail: interactive-only, so url-benchmark.sh still measures the raw heuristic+LLM core and
# an inspection can never paper over a detection regression. The machine verdict is printed too.
_insp=$(awk -F'\t' '$3=="inspected" { ts=$1; v=$2; note=(NF>=5 ? $5 : ""); c=(NF>=6 ? $6 : "") }
                    END { if (ts) print ts"\t"v"\t"note"\t"c }' "$CACHE_DIR/feedback.txt" 2>/dev/null)
_vmachine=""
if [ -n "$_insp" ]; then
    IFS=$'\t' read -r _its _iv _inote _icat <<< "$_insp"
    case "$_iv" in
        SAFE|SUSPICIOUS|DANGEROUS)
            [ "$_iv" != "$VERDICT" ] && [ -t 0 ] \
                && { _vmachine="${VERDICT:-UNCLEAR}"; VERDICT="$_iv"; } ;;
    esac
fi
# What the page IS, beside how bad it is (see category_of in verdict.sh). A recorded category
# beats the deterministic guess for the same reason a recorded verdict does: a human or a deep
# inspection looked at the page. Computed AFTER the override, never before -- guessing from the
# machine verdict and then printing the overridden one produced "SAFE (other)", where "other"
# is a category that only exists for verdicts we are calling bad.
CATEGORY=$(category_of "$VERDICT" "$HAS_LOGIN" "${FINAL_URL:-$URL}" "$SMELLS" "$DEOBFUS_SIGNALS" "$TITLE")
[ -n "$_icat" ] && [ -t 0 ] && CATEGORY="$_icat"

case "$VERDICT" in
    SAFE)       VC="$GREEN";  VLINE="[+] VERDICT: SAFE" ;;
    SUSPICIOUS) VC="$YELLOW"; VLINE="[!] VERDICT: SUSPICIOUS" ;;
    DANGEROUS)  VC="$RED";    VLINE="[!!] VERDICT: DANGEROUS" ;;
    *)          VC="$CYAN";   VLINE="[?] VERDICT: UNCLEAR" ;;
esac
VLINE="$VLINE${CATEGORY:+ ($CATEGORY)}"
echo ""
echo "${VC}${BOLD}=============================================="
echo "$VLINE"
echo "==============================================${RESET}"

# Show the inspection that settled it, so nobody re-litigates a closed case -- and name the
# machine verdict it overrode, so a detection gap stays visible instead of being papered over.
if [ -n "$_insp" ]; then
    echo ""
    if [ -n "$_vmachine" ]; then
        echo_cyan "Verdict from a prior deep inspection -- $_its (this scan's heuristics+LLM said $_vmachine)"
    else
        echo_cyan "Prior deep inspection -- $_its (verdict: ${_iv:-?})"
    fi
    printf '%s\n' "$_inote" | fold -s -w 96 | sed "s/^/  ${GREY}/;s/\$/${RESET}/"
fi

# Last-resort fallback: a bot gate (Turnstile/hCaptcha/reCAPTCHA) still blocks the real page
# (operator attach was declined, unavailable, or failed). Offer to just open it in the analyst's
# browser -- a residential IP + real browser usually passes the gate.
# ponytail: opening a live phishing URL is risky; explicit opt-in, default No, shown AFTER the
# verdict so the analyst decides with full context. Rings the bell before the prompt.
if [ -t 0 ] && command -v xdg-open >/dev/null 2>&1 \
   && printf '%s' "$SMELLS" | grep -qi 'gated from the scraper'; then
    echo ""
    _bell
    read -r -p "${CYAN}Bot gate still blocking. Open ${FINAL_URL:-$URL} in YOUR browser to inspect? (risky) [y/N] ${RESET}" _ans
    [[ "$_ans" =~ ^[Yy] ]] && { xdg-open "${FINAL_URL:-$URL}" >/dev/null 2>&1 & }
fi

# Analyst feedback: agree with the verdict? Recorded per-URL to refine the tool later.
# ponytail: interactive-only so benchmarks never prompt; one TSV line appended to the cache.
if [ -t 0 ]; then
    # _ask_category [default] -> one of VERDICT_CATEGORIES, chosen by number or by name.
    # Fixed vocabulary rather than free text, because these are mined later and free text
    # would not group (see verdict.sh).
    # The menu goes to stderr: only the chosen category may reach stdout, because the caller
    # reads this through command substitution.
    _ask_category() {
        local i=1 c choice picked
        for c in $VERDICT_CATEGORIES; do
            printf '  %s%2d)%s %-15s' "$GREY" "$i" "$RESET" "$c" >&2
            [ $((i % 3)) -eq 0 ] && echo "" >&2
            i=$((i+1))
        done
        echo "" >&2
        read -r -p "${CYAN}What is it? [number or name${1:+, Enter = $1}] ${RESET}" choice
        case "$choice" in
            '')       picked="" ;;
            *[!0-9]*) is_category "$choice" && picked="$choice" ;;
            *)        picked=$(printf '%s' "$VERDICT_CATEGORIES" | tr ' ' '\n' | sed -n "${choice}p") ;;
        esac
        printf '%s' "${picked:-${1:-other}}"   # unknown name / out-of-range number -> the default
    }

    echo ""
    read -r -p "${CYAN}Do you agree with this verdict? [Y/n/s(kip)/f(lag for later)/i(nspect now)] ${RESET}" _fb
    _inspect_now= _correct_v= _correct_c=
    case "$_fb" in
        # Disagreement without the correction is a complaint the toolkit cannot act on, so ask
        # what it really is. The disagree row still records that the scan was wrong (that is the
        # accuracy stat), and the correction rides an `inspected` row so re-scans report it.
        [Nn]*) _fb=disagree
            read -r -p "${CYAN}What should the verdict be? [1) SAFE  2) SUSPICIOUS  3) DANGEROUS] ${RESET}" _correct_v
            case "$_correct_v" in
                1|[Ss][Aa]*)          _correct_v=SAFE ;;
                2|[Ss][Uu]*)          _correct_v=SUSPICIOUS ;;
                3|[Dd]*)              _correct_v=DANGEROUS ;;
                *)                    _correct_v="" ;;
            esac
            [ -n "$_correct_v" ] && _correct_c=$(_ask_category "$CATEGORY")
            ;;
        [Ss]*) _fb=skip ;;
        # 'flag' is not a disagreement -- it means "the verdict may be right but this one needs a
        # human/deeper look". Kept as its own value so it never pollutes the agreement rate, and
        # `./feedback-report.sh -f` prints just these as a worklist.
        [Ff]*) _fb=flag ;;
        # 'inspect now' is the same flag lifecycle compressed into one sitting: the flag row is
        # still written (so an abandoned inspection leaves the URL on the worklist), then closed
        # by the `inspected` row below. Same append-only rows as the -f round-trip.
        [Ii]*) _fb=flag; _inspect_now=1 ;;
        *)     _fb=agree ;;
    esac
    # 6 columns: ts, verdict, state, url, note, category. Every row carries the category, so the
    # ledger can be mined by kind and not only by severity.
    printf '%s\t%s\t%s\t%s\t\t%s\n' "$(date -u +%FT%TZ)" "$VERDICT" "$_fb" "$URL" "$CATEGORY" >> "$CACHE_DIR/feedback.txt"

    # The correction is what makes a disagreement actionable: it becomes the settled label, so the
    # next scan of this URL reports it and the replay corpus scores against it.
    if [ -n "$_correct_v" ]; then
        read -r -p "${CYAN}Why? (optional, Enter to skip) ${RESET}" _why
        FB_VERDICT="$_correct_v" FB_CATEGORY="$_correct_c" "$SCRIPT_DIR/feedback-report.sh" \
            -i "$URL" "${_why:-analyst disagreed with $VERDICT: this is $_correct_c}"
    fi

    if [ -n "$_inspect_now" ]; then
        echo ""
        echo_grey "artifacts: $CACHE_DIR  (page.json, page.jpg, scripts/, vision.txt)"
        # ponytail: headless `claude -p` does the triage, read-only tools so it never prompts
        # for permission mid-run and never touches the live site. Falls back to a typed note.
        if command -v claude >/dev/null 2>&1; then
            echo_grey "deep inspection: claude is reading the cached scan (ctrl-c to skip)..."
            if _iout=$(claude -p "Deep-inspect one phishing scan from this repo ($SCRIPT_DIR).

URL:      $URL
Landed:   ${FINAL_URL:-$URL}
Verdict:  $VERDICT
Signals:  ${SMELLS:-none}
Cache:    $CACHE_DIR
Host facts: $HOST_DIR/meta.env

Read the cached artifacts (page.json, page-login.json, meta.env, scripts/,
deob-signals.txt, vision.txt, virustotal.json, urlscan.json -- whichever exist) and say
whether $VERDICT is right. Cite concrete evidence from the artifacts, never guess. If it
is wrong, name the heuristic gap in verdict.sh / page-fetch.sh that let it through.
Do not fetch the live URL and do not edit any file.
End your reply with exactly these three lines:
VERDICT: <SAFE|SUSPICIOUS|DANGEROUS -- the TRUE verdict, which future scans will report>
CATEGORY: <what the page IS, one of: $VERDICT_CATEGORIES>
NOTE: <one-line conclusion, max 200 chars>" \
                --allowedTools "Read,Grep,Glob" 2>&1); then
                printf '%s\n' "$_iout"
                _ifound=$(printf '%s\n' "$_iout" | grep -m1 '^NOTE:' | sed 's/^NOTE:[[:space:]]*//')
                [ -z "$_ifound" ] && _ifound=$(printf '%s\n' "$_iout" | grep -v '^[[:space:]]*$' | tail -1)
                # The corrected verdict is the point of the inspection: it is what a re-scan
                # reports. Unparseable -> keep this run's verdict, never guess one.
                _ivnew=$(printf '%s\n' "$_iout" | grep -m1 '^VERDICT:' \
                         | grep -oiE 'SAFE|SUSPICIOUS|DANGEROUS' | head -1 | tr 'a-z' 'A-Z')
                _icnew=$(printf '%s\n' "$_iout" | grep -m1 '^CATEGORY:' \
                         | sed 's/^CATEGORY:[[:space:]]*//' | tr -d ' ' | tr 'A-Z' 'a-z')
                is_category "$_icnew" || _icnew=""
            else
                echo_yellow "claude inspection failed: $(printf '%s' "$_iout" | tail -1)"
            fi
        fi
        case "${_ivnew:-$VERDICT}" in
            SAFE|SUSPICIOUS|DANGEROUS) _ivnew="${_ivnew:-$VERDICT}" ;;
            *) _ivnew="" ;;   # nothing to correct to -> the row keeps the last known verdict
        esac
        _icnew="${_icnew:-$CATEGORY}"
        echo ""
        if [ -n "$_ifound" ]; then
            echo_cyan "Real verdict for this URL: $_ivnew${_icnew:+ ($_icnew)}  (future scans will report it)"
            read -r -p "${CYAN}Record it? [Y/n/c(hange category), or type your own note] ${RESET}" _iedit
            case "$_iedit" in
                [Nn]|[Nn][Oo]) _ifound= ;;
                [Cc]) _icnew=$(_ask_category "$_icnew") ;;
                ?*) _ifound="$_iedit" ;;
            esac
        else
            read -r -p "${CYAN}What did the inspection find? (empty = leave flagged) ${RESET}" _ifound
            [ -n "$_ifound" ] && _icnew=$(_ask_category "$_icnew")
        fi
        [ -n "$_ifound" ] && FB_VERDICT="$_ivnew" FB_CATEGORY="$_icnew" \
            "$SCRIPT_DIR/feedback-report.sh" -i "$URL" "$_ifound"
    fi
fi

# A bare interactive run also asks before it KEEPS what it just fetched. A scan of a live phish
# leaves the page, the screenshot, its scripts and the victim's email in the query string sitting
# on disk, and that is not always what you want after a one-off look. Asked last, because the deep
# inspection above reads those very artifacts. The feedback ledger always survives -- the judgement
# is the part that cannot be re-fetched.
if [ -n "$BARE_RUN" ] && [ -t 0 ] && [ -z "$REUSED_CACHE" ]; then
    echo ""
    read -r -p "${CYAN}Keep this scan cached (page, screenshot, scripts, LLM answers)? [Y/n] ${RESET}" _ans
    case "$_ans" in
        [Nn]*) _purge_cache; echo_grey "cache cleared for this URL (feedback history kept)" ;;
    esac
fi

# Always the last line: which URL this whole run was about. A scan scrolls several screens of
# signals, console errors and prompts, so by the time you reach the bottom the URL is long gone --
# and the next thing you usually do is paste it into a ticket or re-run it with another flag.
echo ""
echo_grey "scanned: $URL"
