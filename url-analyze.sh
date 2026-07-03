#!/bin/bash

# URL Analyzer - combines page-fetch signals with LLM analysis

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/ollama-up.sh"

spinner() {
    local pid=$1
    local msg="${2:-Analyzing...}"
    local chars='|/-\'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r%c %s" "${chars:i++%${#chars}:1}" "$msg"
        sleep 0.1
    done
    printf "\r✓ %s\n" "$msg"
}

MODEL=""
URL=""
SKIP_FETCH=""

while getopts "m:s" opt; do
    case $opt in
        m) MODEL="$OPTARG" ;;
        s) SKIP_FETCH=1 ;;
        *) echo "Usage: $0 [-m model] [-s] <url>"; exit 1 ;;
    esac
done
shift $((OPTIND-1))

URL="${1:-$URL}"

if [ -z "$URL" ]; then
    echo "Usage: $0 [-m model] [-s skip-fetch] <url>"
    echo "       $0 -m gemma2:2b https://example.com"
    exit 1
fi

# === PHASE 1: Static URL Analysis (zero-day signals) ===
echo "=== URL Analysis: $URL ==="
echo ""

# Extract domain info
DOMAIN=$(echo "$URL" | sed -E 's|https?://([^/]+).*|\1|')
TLD=$(echo "$DOMAIN" | grep -oE '\.[a-z]+$' | tr -d '.')

# ponytail: High-risk TLDs commonly used for phishing
RISKY_TLDS="cfd|xyz|top|lol|sbs|icu|buzz|surf|monster|click|link|gq|ml|tk|cf|ga"
if echo "$TLD" | grep -qE "^($RISKY_TLDS)$"; then
    echo "⚠️  High-risk TLD: .$TLD"
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
    echo "⚠️  Possible typosquatting: contains '$MATCHED' but domain is $DOMAIN"
fi

# ponytail: Excessive subdomains (often used to hide real domain)
SUBDOMAIN_COUNT=$(echo "$DOMAIN" | tr '.' '\n' | wc -l)
if [ "$SUBDOMAIN_COUNT" -gt 4 ]; then
    echo "⚠️  Excessive subdomains ($SUBDOMAIN_COUNT levels)"
fi

# ponytail: Homograph detection (mixed scripts in domain)
if echo "$DOMAIN" | grep -qP '[^\x00-\x7F]'; then
    echo "⚠️  Homograph attack: non-ASCII characters in domain"
fi

# ponytail: Random-looking domain (high entropy)
DOMAIN_BASE=$(echo "$DOMAIN" | sed 's/\.[^.]*$//' | tr -d '.-')
if [ ${#DOMAIN_BASE} -gt 8 ] && echo "$DOMAIN_BASE" | grep -qE '^[a-z0-9]+$' && echo "$DOMAIN_BASE" | grep -qE '[0-9].*[0-9]'; then
    echo "⚠️  Random-looking domain: $DOMAIN_BASE"
fi

# === Domain Info Lookup ===
echo "--- Domain Info ---"

# Get apex domain (last 2 parts for most TLDs)
APEX_DOMAIN=$(echo "$DOMAIN" | grep -oE '[^.]+\.[^.]+$')

# DNS + IP info
IP=$(dig +short "$DOMAIN" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
if [ -n "$IP" ]; then
    IP_INFO=$(curl -s --max-time 5 "http://ip-api.com/json/$IP?fields=country,org,isp" 2>/dev/null)
    COUNTRY=$(echo "$IP_INFO" | jq -r '.country // "?"')
    ORG=$(echo "$IP_INFO" | jq -r '.org // .isp // "?"')
    echo "IP: $IP ($COUNTRY, $ORG)"
else
    echo "IP: (unresolvable)"
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
                echo "⚠️  Domain age: $AGE_DAYS days (VERY NEW - high risk)"
            elif [ "$AGE_DAYS" -lt 90 ]; then
                echo "⚠️  Domain age: $AGE_DAYS days (new)"
            else
                echo "Domain age: $AGE_DAYS days (created $CREATED_DATE)"
            fi
        else
            echo "Domain created: $CREATED_DATE"
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
                    echo "⚠️  SSL cert age: $CERT_AGE_DAYS days (VERY NEW - suspicious)"
                elif [ "$CERT_AGE_DAYS" -lt 30 ]; then
                    echo "SSL cert age: $CERT_AGE_DAYS days (recent)"
                else
                    echo "SSL cert: $CERT_AGE_DAYS days old, issuer: $CERT_ISSUER"
                fi
            fi
        fi
    fi
fi

# === DNS Records Check ===
A_RECORDS=$(dig +short "$DOMAIN" A 2>/dev/null | grep -E '^[0-9]+\.' | wc -l)
if [ "$A_RECORDS" -gt 5 ]; then
    echo "⚠️  Fast-flux: $A_RECORDS A records (suspicious)"
fi

TTL=$(dig +noall +answer "$DOMAIN" A 2>/dev/null | awk '{print $2}' | head -1)
if [ -n "$TTL" ] && [ "$TTL" -lt 300 ]; then
    echo "⚠️  Low TTL: ${TTL}s (fast-flux indicator)"
fi

echo ""

# === PHASE 2: Page Fetch (dynamic signals) ===
if [ -z "$SKIP_FETCH" ]; then
    echo "Fetching page content..."
    PAGE_DATA=$("$SCRIPT_DIR/page-fetch.sh" "$URL" 2>&1 | tail -1)

    if echo "$PAGE_DATA" | jq -e '.error' >/dev/null 2>&1; then
        echo "⚠️  Page unreachable or timeout"
        PAGE_DATA="{}"
    else
        # Extract signals
        SMELLS=$(echo "$PAGE_DATA" | jq -r '.phishingSmells[]?' 2>/dev/null)
        HAS_LOGIN=$(echo "$PAGE_DATA" | jq -r '.hasLoginForm' 2>/dev/null)
        TITLE=$(echo "$PAGE_DATA" | jq -r '.title' 2>/dev/null)
        FINAL_URL=$(echo "$PAGE_DATA" | jq -r '.finalUrl' 2>/dev/null)
        THIRD_PARTY=$(echo "$PAGE_DATA" | jq -r '.thirdPartyDomains | length' 2>/dev/null)

        if [ "$FINAL_URL" != "$URL" ] && [ -n "$FINAL_URL" ] && [ "$FINAL_URL" != "null" ]; then
            echo "↪️  Redirects to: $FINAL_URL"
        fi

        if [ "$HAS_LOGIN" = "true" ]; then
            echo "🔐 Login form detected"
        fi

        if [ -n "$SMELLS" ]; then
            echo ""
            echo "🚨 Phishing signals detected:"
            echo "$SMELLS" | while read -r smell; do
                echo "   • $smell"
            done
        fi

        echo ""
        echo "Third-party domains: $THIRD_PARTY"
    fi
else
    PAGE_DATA="{}"
    echo "(page fetch skipped)"
fi

echo ""

# === PHASE 3: LLM Analysis ===
ensure_ollama || exit 1

if [ -z "$MODEL" ]; then
    echo "Available models:"
    MODELS=($(docker exec llm-spam-test ollama list 2>/dev/null | awk 'NR>1 {print $1}'))
    if [ ${#MODELS[@]} -eq 0 ]; then
        echo "  No models available (is llm-spam-test container running?)"
        exit 1
    fi
    for i in "${!MODELS[@]}"; do
        echo "  $((i+1)): ${MODELS[$i]}"
    done
    echo ""
    read -p "Select model (1-${#MODELS[@]}), or Enter to skip LLM: " SEL
    if [ -z "$SEL" ]; then
        echo ""
        echo "=== Summary (static analysis only) ==="
        exit 0
    fi
    MODEL="${MODELS[$((SEL-1))]}"
    if [ -z "$MODEL" ]; then
        echo "Invalid selection."
        exit 1
    fi
fi

# Extract explicit, pre-computed signals so the LLM reasons from facts (not raw JSON)
HAS_LOGIN=$(echo "$PAGE_DATA" | jq -r '.hasLoginForm // false' 2>/dev/null)
FORMS=$(echo "$PAGE_DATA" | jq -r '.counts.forms // 0' 2>/dev/null)
LOGIN_FORMS=$(echo "$PAGE_DATA" | jq -r '.counts.loginForms // 0' 2>/dev/null)
FINAL_URL=$(echo "$PAGE_DATA" | jq -r '.finalUrl // ""' 2>/dev/null)
TITLE=$(echo "$PAGE_DATA" | jq -r '.title // ""' 2>/dev/null)
THIRD_PARTY=$(echo "$PAGE_DATA" | jq -r '.thirdPartyDomains | length' 2>/dev/null)
SUSP_JS=$(echo "$PAGE_DATA" | jq -r '(.suspiciousJs // []) | join(", ")' 2>/dev/null)
SMELLS=$(echo "$PAGE_DATA" | jq -r '(.phishingSmells // []) | join(", ")' 2>/dev/null)

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
- Phishing smells flagged by scraper: ${SMELLS:-none}
- Third-party domains loaded: ${THIRD_PARTY:-0}
- Page title: \"$TITLE\""

SYSTEM_PROMPT="You are a strict cybersecurity analyst. Classify this URL using ONLY the EXTRACTED SIGNALS provided. Do NOT invent facts: if 'Login form present' is false there is NO credential form; if 'Redirected' is 'no' there is NO redirect. Never assume a redirect or login page that is not listed.

A login form is NORMAL and expected on legitimate sites (Google, banks, webmail). A login form BY ITSELF is not dangerous - it is only dangerous when combined with a red flag.

RED FLAGS (count how many are present in the signals):
- off-domain form submit
- brand impersonation (brand named but not the real domain)
- risky TLD (.cfd .xyz .top .lol .sbs .icu .buzz .monster etc.)
- IP fingerprinting
- sensitive field names (ssn, cvv, routing, etc.)
- domain age under 90 days
- suspicious JS (eval, atob, hex-encoded, document.write)
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

curl -s --max-time 120 -X POST http://localhost:11434/api/generate \
    --data-raw "{\"model\":\"$MODEL\",\"system\":$(echo "$SYSTEM_PROMPT" | jq -Rs .),\"prompt\":$(echo "$CONTEXT" | jq -Rs .),\"options\":{\"temperature\":0.0,\"num_predict\":512},\"stream\":false,\"keep_alive\":\"5m\"}" > /tmp/url_analyze_response.json &
CURL_PID=$!

spinner $CURL_PID "LLM analyzing..."

wait $CURL_PID 2>/dev/null

RESPONSE=$(jq -r '.response // "Error: No response from model"' /tmp/url_analyze_response.json 2>/dev/null)
rm -f /tmp/url_analyze_response.json

echo ""
echo "=== LLM Analysis ==="
echo "$RESPONSE" | sed '/^VERDICT:/d'
echo ""

VERDICT=$(echo "$RESPONSE" | grep -oE 'VERDICT:\s*(SAFE|SUSPICIOUS|DANGEROUS)' | awk '{print $2}')

# === Deterministic safety floor ===
# The signals are already extracted deterministically, so don't trust a small
# model to do boolean AND-logic. Count red flags in bash; a login form plus any
# red flag is credential harvesting and MUST be DANGEROUS. Floor only escalates,
# never downgrades, so it can never mask a threat the LLM did catch.
RISKY_TLDS="cfd xyz top lol sbs icu buzz monster gq tk ml ga cf work zip mov"
RED_FLAGS=0
# one flag per phishing smell the scraper reported
[ -n "$SMELLS" ] && RED_FLAGS=$(( RED_FLAGS + $(echo "$SMELLS" | tr ',' '\n' | grep -c .) ))
# suspicious JS present
[ -n "$SUSP_JS" ] && RED_FLAGS=$(( RED_FLAGS + 1 ))
# risky TLD
echo " $RISKY_TLDS " | grep -q " $TLD " && RED_FLAGS=$(( RED_FLAGS + 1 ))
# young domain (<90 days); AGE_DAYS unset means unknown -> not counted
[ -n "$AGE_DAYS" ] && [ "$AGE_DAYS" -lt 90 ] 2>/dev/null && RED_FLAGS=$(( RED_FLAGS + 1 ))
# redirect into a compromised WordPress tree
echo "$FINAL_URL" | grep -qiE 'wp-content|wp-include' && RED_FLAGS=$(( RED_FLAGS + 1 ))

# is this a mailing-list / unsubscribe endpoint? (list-validation risk on its own)
if echo "$URL" | grep -qiE 'unsub|opt[-_]?out|list[-_]?manage|/remove|mailpref|newsletter'; then
    IS_UNSUB=1
fi

if [ "$HAS_LOGIN" = "true" ] && [ "$RED_FLAGS" -ge 1 ] && [ "$VERDICT" != "DANGEROUS" ]; then
    # login form + any red flag = credential harvesting
    echo "⚙️  Safety floor: login form + $RED_FLAGS red flag(s) -> forcing DANGEROUS (LLM said ${VERDICT:-UNCLEAR})"
    VERDICT="DANGEROUS"
elif { [ "$RED_FLAGS" -ge 1 ] || [ -n "$IS_UNSUB" ]; } && { [ "$VERDICT" = "SAFE" ] || [ -z "$VERDICT" ]; }; then
    # no login form, but red flags / list-validation present -> at least SUSPICIOUS
    echo "⚙️  Safety floor: $RED_FLAGS red flag(s)${IS_UNSUB:+ + unsubscribe endpoint} -> forcing SUSPICIOUS (LLM said ${VERDICT:-UNCLEAR})"
    VERDICT="SUSPICIOUS"
fi

case "$VERDICT" in
    SAFE)
        echo "=============================================="
        echo "  ✅ VERDICT: SAFE"
        echo "=============================================="
        ;;
    SUSPICIOUS)
        echo "=============================================="
        echo "  ⚠️  VERDICT: SUSPICIOUS"
        echo "=============================================="
        ;;
    DANGEROUS)
        echo "=============================================="
        echo "  🚨 VERDICT: DANGEROUS"
        echo "=============================================="
        ;;
    *)
        echo "=============================================="
        echo "  ⚡ VERDICT: UNCLEAR"
        echo "=============================================="
        ;;
esac
