#!/bin/bash

# URL Analyzer - combines page-fetch signals with LLM analysis

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/ollama-up.sh"
source "$SCRIPT_DIR/verdict.sh"
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
shift $((OPTIND-1))

# -m none is an alias for -H (pure heuristic: no LLM, verdict from the decision table)
[ "$MODEL" = none ] && { HEURISTIC=1; MODEL=""; }

# Now that -c mono is known, load the shared color helpers.
source "$SCRIPT_DIR/colors.sh"

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
[ -n "$REFRESH" ] && rm -rf "$CACHE_DIR"
mkdir -p "$CACHE_DIR"

# === PHASE 1: Static URL Analysis (zero-day signals) ===
# Split host from an explicit :port -- a port glued to DOMAIN breaks dig/openssl (the non-standard
# high port is itself a tunneling/phishing signal, e.g. portmap.io:46801). PORT feeds the cert check.
AUTHORITY=$(echo "$URL" | sed -E 's|https?://([^/]+).*|\1|')
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
TECH_BRANDS="google|facebook|microsoft|apple|amazon|paypal|netflix|instagram|linkedin|twitter|github|dropbox|adobe|zoom|slack|salesforce|oracle|ibm|cisco|vmware"
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
if echo "$DOMAIN" | grep -qiE "($BRANDS)" && ! echo "$DOMAIN" | grep -qiE "^(www\.)?($BRANDS)\.(com|org|net|io)$"; then
    MATCHED=$(echo "$DOMAIN" | grep -oiE "($BRANDS)" | head -1)
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

# ponytail: Random-looking domain (high entropy)
DOMAIN_BASE=$(echo "$DOMAIN" | sed 's/\.[^.]*$//' | tr -d '.-')
if [ ${#DOMAIN_BASE} -gt 8 ] && echo "$DOMAIN_BASE" | grep -qE '^[a-z0-9]+$' && echo "$DOMAIN_BASE" | grep -qE '[0-9].*[0-9]'; then
    add_signal "Random-looking domain: $DOMAIN_BASE"
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

# === Domain Info Lookup ===
# ponytail: IP/geo, domain age, SSL and DNS are cached in meta.env so re-scans and the
# model benchmark skip these network round-trips. -r refreshes.
if [ -f "$CACHE_DIR/meta.env" ]; then
    source "$CACHE_DIR/meta.env"
    echo "${BOLD}Domain Info (cached)${RESET}"
    echo_grey "- IP: ${IP:-(unresolvable)}${COUNTRY:+ ($COUNTRY, $ORG)}"
    [ -n "$AGE_DAYS" ] && echo_grey "- Domain age: $AGE_DAYS days"
    [ -n "$CERT_AGE_DAYS" ] && echo_grey "- SSL cert age: $CERT_AGE_DAYS days${CERT_ISSUER:+ (issuer: $CERT_ISSUER)}"
    [ "${A_RECORDS:-0}" -gt 5 ] 2>/dev/null && add_signal "Fast-flux: $A_RECORDS A records"
else
echo "${BOLD}Domain Info${RESET}"

# Get apex domain (last 2 parts for most TLDs)
APEX_DOMAIN=$(echo "$DOMAIN" | grep -oE '[^.]+\.[^.]+$')

# DNS + IP info
IP=$(dig +short "$DOMAIN" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
if [ -n "$IP" ]; then
    IP_INFO=$(curl -s --max-time 5 "http://ip-api.com/json/$IP?fields=country,org,isp" 2>/dev/null)
    COUNTRY=$(echo "$IP_INFO" | jq -r '.country // "?"')
    ORG=$(echo "$IP_INFO" | jq -r '.org // .isp // "?"')
    echo_grey "- IP: $IP ($COUNTRY, $ORG)"
else
    echo_grey "- IP: (unresolvable)"
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
        if [ -n "$CREATED_TS" ]; then
            NOW_TS=$(date +%s)
            AGE_DAYS=$(( (NOW_TS - CREATED_TS) / 86400 ))
            if [ "$AGE_DAYS" -lt 30 ]; then
                add_signal "Domain age: $AGE_DAYS days (VERY NEW - high risk)"
            elif [ "$AGE_DAYS" -lt 90 ]; then
                add_signal "Domain age: $AGE_DAYS days (new)"
            else
                echo_grey "- Domain age: $AGE_DAYS days (created $CREATED_DATE)"
            fi
        else
            echo_grey "- Domain created: $CREATED_DATE"
        fi
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
            if [ -n "$CERT_TS" ]; then
                CERT_AGE_DAYS=$(( ($(date +%s) - CERT_TS) / 86400 ))
                if [ "$CERT_AGE_DAYS" -lt 7 ]; then
                    add_signal "SSL cert age: $CERT_AGE_DAYS days (VERY NEW - suspicious)"
                elif [ "$CERT_AGE_DAYS" -lt 30 ]; then
                    echo_grey "- SSL cert age: $CERT_AGE_DAYS days (recent)"
                else
                    echo_grey "- SSL cert: $CERT_AGE_DAYS days old, issuer: $CERT_ISSUER"
                fi
            fi
        fi
    fi
fi

# === DNS Records Check ===
A_RECORDS=$(dig +short "$DOMAIN" A 2>/dev/null | grep -E '^[0-9]+\.' | wc -l)
if [ "$A_RECORDS" -gt 5 ]; then
    add_signal "Fast-flux: $A_RECORDS A records (suspicious)"
fi

TTL=$(dig +noall +answer "$DOMAIN" A 2>/dev/null | awk '{print $2}' | head -1)
if [ -n "$TTL" ] && [ "$TTL" -lt 300 ]; then
    add_signal "Low TTL: ${TTL}s (fast-flux indicator)"
fi

# Persist the lookups for re-scans (only once we actually resolved something).
# printf %q keeps org names with spaces/quotes shell-safe when sourced back.
if [ -n "$IP" ]; then
    { printf 'IP=%q\n' "$IP";               printf 'COUNTRY=%q\n' "$COUNTRY"
      printf 'ORG=%q\n' "$ORG";             printf 'AGE_DAYS=%q\n' "$AGE_DAYS"
      printf 'CERT_AGE_DAYS=%q\n' "$CERT_AGE_DAYS"; printf 'CERT_ISSUER=%q\n' "$CERT_ISSUER"
      printf 'A_RECORDS=%q\n' "$A_RECORDS"; printf 'TTL=%q\n' "$TTL"; } > "$CACHE_DIR/meta.env"
fi
fi

# Don't spin up the fetch container if the domain has no DNS A record -- it would just
# time out. Static + DNS info above still stands. (data: URLs need no DNS, so exempt them.)
if [ -z "$SKIP_FETCH" ] && [ -z "$IP" ] && ! printf '%s' "$URL" | grep -q '^data:'; then
    add_signal "Domain does not resolve (no DNS A record)"
    SKIP_FETCH=1
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

    if echo "$PAGE_DATA" | jq -e '.error' >/dev/null 2>&1; then
        echo_yellow "[!] Page unreachable or timeout"
        PAGE_DATA="{}"
    else
        # Extract signals
        SMELLS=$(echo "$PAGE_DATA" | jq -r '.phishingSmells[]?' 2>/dev/null)
        HAS_LOGIN=$(echo "$PAGE_DATA" | jq -r '.hasLoginForm' 2>/dev/null)
        TITLE=$(echo "$PAGE_DATA" | jq -r '.title' 2>/dev/null)
        FINAL_URL=$(echo "$PAGE_DATA" | jq -r '.finalUrl' 2>/dev/null)
        THIRD_PARTY=$(echo "$PAGE_DATA" | jq -r '.thirdPartyDomains | length' 2>/dev/null)

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
if [ -z "$NO_DEOBFUS" ] && [ -n "$SUSP_JS" ] && ls "$CACHE_DIR/scripts"/*.js >/dev/null 2>&1; then
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
            _s=$(LANDED_DOMAIN="$LANDED_DOMAIN" js_signals <<< "$_clean")
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
        _utime=$(jq -r '.task.time // "?"' "$CACHE_DIR/urlscan.json" | cut -dT -f1)
        URLSCAN_SUMMARY="malicious=$_um, score $_usc (last scan $_utime)"
        echo_grey "- urlscan.io: $URLSCAN_SUMMARY  (https://urlscan.io/search/#page.url:%22$URL%22)"
        [ "$_um" = "true" ] && rep_redflag urlscan.io "score $_usc"
    fi
fi

# === PHASE 3: LLM Analysis (skipped in heuristic mode: -H, -m heuristic, or menu option 0) ===
VERDICT=""   # default; only a real LLM run overrides it. Heuristic modes leave it empty.
if [ -z "$HEURISTIC" ]; then
echo ""
echo "${BOLD}Model${RESET}"
ensure_ollama || exit 1

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
    elif [ -f "$SHOT" ] && docker exec llm-spam-test ollama list 2>/dev/null | grep -q "$VISION_MODEL"; then
        # Compare the brand against the domain we ACTUALLY landed on (post-redirect), not the
        # entry/cloaker domain -- phishing routinely enters via a shortener/tracker.
        LANDED_DOMAIN=$(echo "$PAGE_DATA" | jq -r '.domain // ""' 2>/dev/null)
        LANDED_DOMAIN="${LANDED_DOMAIN:-$DOMAIN}"
        echo_grey "- visual check (brand + credential input) via $VISION_MODEL (~1min on CPU)..."
        VP="This screenshot is the web page served at domain '$LANDED_DOMAIN'. Answer concisely in two lines:
BRAND: what brand/company does its visual design (logo, colours, layout) imitate, and does it match the domain '$LANDED_DOMAIN'? If a well-known brand's page is served from an unrelated domain, say so.
PASSWORD: is a password or login/credential input field visible on the page? Reply exactly 'PASSWORD: yes' or 'PASSWORD: no'."
        # think:false  we want a crisp verdict, not a reasoning essay. Without it the
        # model's <think> ramble gets truncated by num_predict and leaks in as the "answer".
        VRESP=$(base64 -w0 "$SHOT" | jq -Rs --arg m "$VISION_MODEL" --arg p "$VP" \
            '{model:$m,prompt:$p,images:[.],think:false,options:{temperature:0,num_predict:200},stream:false}' \
            | curl -s --max-time 180 http://localhost:11434/api/generate -d @- | jq -r '.response // ""')
        # belt-and-braces: strip a <think> block if the model emits one anyway
        VISION_NOTE=$(echo "$VRESP" | sed '/<think>/,/<\/think>/d' | tr -s '[:space:]' ' ' | sed 's/^ *//;s/ *$//')
        printf '%s' "$VISION_NOTE" > "$CACHE_DIR/vision.txt"
    fi
    if [ -n "$VISION_NOTE" ]; then
        echo_grey "- $VISION_NOTE"
        # Double-check: if the VLM sees a credential field the DOM missed, treat it as a login
        # page so the verdict floor (login + red flag) can fire. Match only 'PASSWORD: yes'.
        if [ "$HAS_LOGIN" != "true" ] && echo "$VISION_NOTE" | grep -qiE 'PASSWORD:?[[:space:]]*yes'; then
            add_signal "Vision: credential input visible (DOM detection missed it)"
            HAS_LOGIN=true
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
- Suspicious JS: ${SUSP_JS:-none}
- Deobfuscated JS signals (hidden by obfuscation, revealed by webcrack): ${DEOBFUS_SIGNALS:-none}
- Phishing smells flagged by scraper: ${SMELLS:-none}
- VirusTotal reputation: ${VT_SUMMARY:-not checked}
- urlscan.io reputation: ${URLSCAN_SUMMARY:-not checked}
- Third-party domains loaded: ${THIRD_PARTY:-0}
- Visual brand check (vision model looking at the rendered page): ${VISION_NOTE:-not run}
- Page title: \"$TITLE\""

SYSTEM_PROMPT="You are a strict cybersecurity analyst. Classify this URL using ONLY the EXTRACTED SIGNALS provided. Do NOT invent facts: if 'Login form present' is false there is NO credential form; if 'Redirected' is 'no' there is NO redirect. Never assume a redirect or login page that is not listed.

A login form is NORMAL and expected on legitimate sites (Google, banks, webmail). A login form BY ITSELF is not dangerous - it is only dangerous when combined with a red flag.

RED FLAGS (count how many are present in the signals):
- off-domain form submit
- brand impersonation (brand named but not the real domain)
- visual brand mismatch: the 'Visual brand check' says the page LOOKS like a known brand (its logo/design) but that brand does not match the domain
- risky TLD (.cfd .xyz .top .lol .sbs .icu .buzz .monster etc.)
- IP fingerprinting
- sensitive field names (ssn, cvv, routing, etc.)
- domain age under 90 days
- suspicious JS (eval, atob, hex-encoded, document.write)
- deobfuscated JS that reveals an off-domain exfil URL, a JS redirect, or cookie/credential theft
- redirect to wp-content / wp-include / random path
- any phishing smell flagged by the scraper

Follow this decision procedure EXACTLY, in order. Count the RED FLAGS first, then apply the FIRST rule that matches:

RULE 1 (MANDATORY - check this first): Login form present AND red flag count >= 1.
   -> VERDICT: DANGEROUS. This is required. A login form plus even ONE red flag is credential harvesting. You must NOT downgrade this to SUSPICIOUS or SAFE, no matter what else you think. It does NOT need a redirect to be DANGEROUS.

RULE 2: Login form present AND red flag count = 0 (established domain >90 days, same-domain submit, no smells, no suspicious JS).
   -> VERDICT: SAFE. This is a normal legitimate login page.

RULE 3: NO login form, but it is a mailing-list / unsubscribe endpoint on a young or throwaway domain, OR any single red flag is present.
   -> VERDICT: SUSPICIOUS (e.g. list-validation: a click confirms your address to spammers).

RULE 4: NO login form, established legitimate domain, zero red flags.
   -> VERDICT: SAFE.

Reply with EXACTLY these two lines and nothing else:
REASON: one short sentence -- was a login form present, how many red flags, and which RULE fired
VERDICT: SAFE or VERDICT: SUSPICIOUS or VERDICT: DANGEROUS"

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
    curl -s --max-time 180 -X POST http://localhost:11434/api/generate \
        --data-raw "{\"model\":\"$MODEL\",\"system\":$(echo "$SYSTEM_PROMPT" | jq -Rs .),\"prompt\":$(echo "$CONTEXT" | jq -Rs .),\"think\":false,\"options\":{\"temperature\":0.0,\"num_predict\":512},\"stream\":false,\"keep_alive\":\"5m\"}" > /tmp/url_analyze_response.json
    LLM_SECS=$(echo "$(date +%s.%N) - $LLM_START" | bc)
    RESPONSE=$(jq -r '.response // "Error: No response from model"' /tmp/url_analyze_response.json 2>/dev/null)
    rm -f /tmp/url_analyze_response.json
    # cache a real answer only, never the error stub (so a transient failure retries)
    [ "$RESPONSE" != "Error: No response from model" ] && printf '%s' "$RESPONSE" > "$LLM_CACHE"
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

VERDICT=$(echo "$BODY" | grep -oE 'VERDICT:\s*(SAFE|SUSPICIOUS|DANGEROUS)' | awk '{print $2}')
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

# === Deterministic verdict (classify_verdict in verdict.sh) ===
# Signals are extracted deterministically upstream, so the final verdict is
# decided by the decision table in verdict.sh -- it escalates over the LLM's
# verdict but never downgrades. The "[floor] Safety floor" notice goes to stderr.
VERDICT=$(classify_verdict "$HAS_LOGIN" "$TLD" "${AGE_DAYS}" "$FINAL_URL" "$URL" "$SMELLS" "$SUSP_JS" "$DEOBFUS_SIGNALS" "$VERDICT")

case "$VERDICT" in
    SAFE)       VC="$GREEN";  VLINE="[+] VERDICT: SAFE" ;;
    SUSPICIOUS) VC="$YELLOW"; VLINE="[!] VERDICT: SUSPICIOUS" ;;
    DANGEROUS)  VC="$RED";    VLINE="[!!] VERDICT: DANGEROUS" ;;
    *)          VC="$CYAN";   VLINE="[?] VERDICT: UNCLEAR" ;;
esac
echo ""
echo "${VC}${BOLD}=============================================="
echo "$VLINE"
echo "==============================================${RESET}"

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
