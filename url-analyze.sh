#!/bin/bash

# URL Analyzer - combines page-fetch signals with LLM analysis

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/ollama-up.sh"
source "$SCRIPT_DIR/verdict.sh"
source "$SCRIPT_DIR/js-signals.sh"
# colors.sh is sourced further down, after args are parsed (so -c mono can disable color)

# best_model -> the top-scoring model from the url-benchmark.sh CSV (highest accuracy,
# then fastest). Excludes the heuristic baseline. Empty if there is no benchmark data.
best_model() {
    local csv="$SCRIPT_DIR/results/url_benchmark.csv"
    [ -f "$csv" ] || return 0
    awk -F, 'NR>1 && $2!="none" && $2!="heuristic" {
        acc=$5; sub(/%/,"",acc); t=$7; sub(/s/,"",t)
        if (acc+0>ba || (acc+0==ba && t+0<bt)) { ba=acc+0; bt=t+0; bm=$2 }
    } END { print bm }' "$csv"
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
VISION_MODEL="${VISION_MODEL:-openbmb/minicpm-v4.6:q4_K_M}"

# Help as the first arg (getopts won't catch bare `help` or long `--help`).
case "${1:-}" in -h|--help|help) usage; exit 0 ;; esac

while getopts "m:sVHrc:Dh" opt; do
    case $opt in
        m) MODEL="$OPTARG" ;;
        s) SKIP_FETCH=1 ;;
        V) NO_VISION=1 ;;
        H) HEURISTIC=1 ;;     # heuristic-only: no LLM, verdict from verdict.sh decision table
        r) REFRESH=1 ;;       # ignore any cached page/screenshot/metadata and re-fetch
        c) case "$OPTARG" in mono|none|off|no) MONO=1 ;; esac ;;  # -c mono = no color
        D) NO_DEOBFUS=1 ;;    # skip JS deobfuscation escalation
        h) usage; exit 0 ;;
        *) usage >&2; exit 1 ;;
    esac
done
shift $((OPTIND-1))

# -m none is an alias for -H (pure heuristic: no LLM, verdict from the decision table)
[ "$MODEL" = none ] && { HEURISTIC=1; MODEL=""; }

# Now that -c mono is known, load the shared color helpers.
source "$SCRIPT_DIR/colors.sh"

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
DOMAIN=$(echo "$URL" | sed -E 's|https?://([^/]+).*|\1|')
TLD=$(echo "$DOMAIN" | grep -oE '\.[a-z]+$' | tr -d '.')

# All signals collect here and print as one bullet list before the verdict, instead of
# being sprinkled through the phases. add_signal appends.
SIGNALS=()
add_signal() { SIGNALS+=("$1"); }

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
    SSL_INFO=$(echo | timeout 5 openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -dates -issuer 2>/dev/null)
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
        echo_grey "- Fetching page content..."
        # Cache full inline scripts too (page-fetch only dumps them when obfuscation fires),
        # so the JS-deobfuscation escalation can reuse them.
        PAGE_DATA=$(PAGE_SHOT="$SHOT" PAGE_SCRIPTS_DIR="$CACHE_DIR/scripts" "$SCRIPT_DIR/page-fetch.sh" "$URL" 2>&1 | tail -1)
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

echo ""

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
[ -n "$SUSP_JS" ] && add_signal "Suspicious JS: $SUSP_JS"

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
        echo "Obfuscated JS detected -> deobfuscating (webcrack, sandboxed)..."
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

# === PHASE 3: LLM Analysis (skipped in heuristic mode: -H, -m heuristic, or menu option 0) ===
VERDICT=""   # default; only a real LLM run overrides it. Heuristic modes leave it empty.
if [ -z "$HEURISTIC" ]; then
ensure_ollama || exit 1

# -m auto -> best benchmarked model (falls back to gemma2:2b if no benchmark data yet).
# Guard: if that model isn't actually installed, drop to the first installed one.
if [ "$MODEL" = auto ]; then
    MODEL=$(best_model)
    [ -z "$MODEL" ] && MODEL="gemma2:2b"
    INSTALLED=($(docker exec llm-spam-test ollama list 2>/dev/null | awk 'NR>1 {print $1}'))
    if ! printf '%s\n' "${INSTALLED[@]}" | grep -qxF "$MODEL"; then
        [ ${#INSTALLED[@]} -eq 0 ] && { echo "auto: no models installed (is llm-spam-test running?)"; exit 1; }
        echo "auto: best model '$MODEL' not installed -> using '${INSTALLED[0]}'"
        MODEL="${INSTALLED[0]}"
    fi
    echo "${CYAN}[model] $MODEL (auto)${RESET}"
fi

if [ -z "$MODEL" ]; then
    MODELS=($(docker exec llm-spam-test ollama list 2>/dev/null | awk 'NR>1 {print $1}'))
    if [ ${#MODELS[@]} -eq 0 ]; then
        echo "  No models available (is llm-spam-test container running?)"
        exit 1
    fi
    # Default = best benchmarked model if it's installed, else the first one. Enter picks it.
    DEFAULT=$(best_model); [ -z "$DEFAULT" ] && DEFAULT="gemma2:2b"
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
# A login form is where a visual brand-clone is both most likely and most costly to
# miss. Only there do we spend the ~1min VLM call: it "sees" the rendered page (logo,
# colours, layout) and catches clones that text/DOM scraping can't. Its answer feeds
# the LLM below as another signal. Gated on -V, a captured screenshot, and the model
# being installed. ponytail: login-form trigger only; widen to conflicting-signal
# cases if it proves worth the minute.
VISION_NOTE=""
if [ -z "$NO_VISION" ] && [ "$HAS_LOGIN" = "true" ]; then
    if [ -f "$CACHE_DIR/vision.txt" ]; then
        # Reuse the cached VLM verdict (the ~1min call is the single most expensive step).
        VISION_NOTE=$(cat "$CACHE_DIR/vision.txt")
    elif [ -f "$SHOT" ] && docker exec llm-spam-test ollama list 2>/dev/null | grep -q "$VISION_MODEL"; then
        # Compare the brand against the domain we ACTUALLY landed on (post-redirect), not the
        # entry/cloaker domain -- phishing routinely enters via a shortener/tracker.
        LANDED_DOMAIN=$(echo "$PAGE_DATA" | jq -r '.domain // ""' 2>/dev/null)
        LANDED_DOMAIN="${LANDED_DOMAIN:-$DOMAIN}"
        echo "${CYAN}[vision] Login form present - visual brand check via $VISION_MODEL (~1min on CPU)...${RESET}"
        VP="This screenshot is the web page served at domain '$LANDED_DOMAIN'. What brand/company does its visual design (logo, colours, layout) imitate? Does that brand match the domain '$LANDED_DOMAIN'? If a well-known brand's page is served from an unrelated domain, say so. Be concise."
        # think:false  we want a crisp brand verdict, not a reasoning essay. Without it the
        # model's <think> ramble gets truncated by num_predict and leaks in as the "answer".
        VRESP=$(base64 -w0 "$SHOT" | jq -Rs --arg m "$VISION_MODEL" --arg p "$VP" \
            '{model:$m,prompt:$p,images:[.],think:false,options:{temperature:0,num_predict:200},stream:false}' \
            | curl -s --max-time 180 http://localhost:11434/api/generate -d @- | jq -r '.response // ""')
        # belt-and-braces: strip a <think> block if the model emits one anyway
        VISION_NOTE=$(echo "$VRESP" | sed '/<think>/,/<\/think>/d' | tr -s '[:space:]' ' ' | sed 's/^ *//;s/ *$//')
        printf '%s' "$VISION_NOTE" > "$CACHE_DIR/vision.txt"
    fi
    [ -n "$VISION_NOTE" ] && echo "   -> $VISION_NOTE"
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

Be concise (2-3 sentences), state whether a login form was present and how many red flags you counted, name which RULE fired, then end with exactly one line:
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
    echo "${CYAN}[.] LLM analyzing...${RESET}"
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
echo "$BODY" | sed '/^VERDICT:/d' | while IFS= read -r _l; do
    [ -n "$_l" ] && echo_grey "- $_l"
done
echo ""

VERDICT=$(echo "$BODY" | grep -oE 'VERDICT:\s*(SAFE|SUSPICIOUS|DANGEROUS)' | awk '{print $2}')
fi   # end real-LLM path (inner heuristic guard)
fi   # end PHASE 3 (outer heuristic guard)

# === Consolidated signal list ===
# Every signal gathered across the phases, printed together as one bullet list instead
# of sprinkled through the output. Gray detail; the colored verdict banner carries severity.
echo "${BOLD}Signals (${#SIGNALS[@]}):${RESET}"
if [ ${#SIGNALS[@]} -gt 0 ]; then
    for _s in "${SIGNALS[@]}"; do echo_grey "- $_s"; done
else
    echo_grey "- none detected"
fi
echo ""

# Offer to open the page screenshot for human validation (interactive terminal + GUI only).
# After the signals list; outside the LLM guard so heuristic mode offers it too. The
# screenshot persists in the cache dir.
if [ -f "$SHOT" ] && [ -t 0 ] && command -v xdg-open >/dev/null 2>&1; then
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
echo "${VC}${BOLD}=============================================="
echo "$VLINE"
echo "==============================================${RESET}"
