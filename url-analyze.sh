#!/bin/bash

# URL Analyzer - combines page-fetch signals with LLM analysis

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
BRANDS="google|facebook|microsoft|apple|amazon|paypal|netflix|instagram|linkedin|twitter|github|dropbox|chase|wellsfargo|bankofamerica|coinbase|binance|metamask|tronlink|trustwallet"
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

# Build context for LLM
CONTEXT="URL: $URL
Domain: $DOMAIN
TLD: $TLD

Page fetch data:
$PAGE_DATA"

SYSTEM_PROMPT="You are a cybersecurity analyst. Analyze this URL and page data for phishing/malware indicators.

Consider:
1. Domain legitimacy (TLD, typosquatting, random strings)
2. Page signals (login forms, redirects, third-party domains)
3. Brand impersonation patterns
4. Technical indicators (IP fingerprinting, compromised hosts)

Be concise. End with exactly:
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
