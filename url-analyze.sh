#!/bin/bash

spinner() {
    local pid=$1
    local chars='|/-\'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r%c Analyzing URL..." "${chars:i++%${#chars}:1}"
        sleep 0.1
    done
    printf "\rDone!                \n"
}

MODEL=""
URL=""

while getopts "m:" opt; do
    case $opt in
        m) MODEL="$OPTARG" ;;
        *) echo "Usage: $0 -m <model> <url>"; exit 1 ;;
    esac
done
shift $((OPTIND-1))

URL="${1:-$URL}"

if [ -z "$URL" ]; then
    echo "Usage: $0 -m <model> <url>"
    echo "       $0 -m gemma2:2b https://example.com"
    exit 1
fi

if [ -z "$MODEL" ]; then
    echo "Available models:"
    MODELS=($(docker exec llm-spam-test ollama list 2>/dev/null | awk 'NR>1 {print $1}'))
    for i in "${!MODELS[@]}"; do
        echo "  $((i+1)): ${MODELS[$i]}"
    done
    echo ""
    read -p "Select model (1-${#MODELS[@]}): " SEL
    if [ -z "$SEL" ]; then
        echo "No model selected."
        exit 1
    fi
    MODEL="${MODELS[$((SEL-1))]}"
    if [ -z "$MODEL" ]; then
        echo "Invalid selection."
        exit 1
    fi
fi

BASE_PROMPT=$(cat prompts/url_analyst.txt)
FULL_PROMPT="${BASE_PROMPT}
After your analysis, conclude with exactly one line:
SAFETY_SCORE: +1   (if the URL appears legitimate and safe)
SAFETY_SCORE: -1   (if the URL appears deceptive, phishing, or unsafe)"

PROMPT=$(sed "s|\[PASTE URL HERE\]|$URL|" <<< "$FULL_PROMPT")

curl -s --max-time 120 -X POST http://localhost:11434/api/generate \
    --data-raw "{\"model\":\"$MODEL\",\"system\":$(echo "$PROMPT" | jq -Rs .),\"prompt\":\"Analyze this URL.\",\"options\":{\"temperature\":0.0,\"num_predict\":1024},\"stream\":false,\"keep_alive\":\"5m\"}" > /tmp/url_analyze_response.json &
CURL_PID=$!

spinner $CURL_PID

wait $CURL_PID 2>/dev/null

RESPONSE=$(jq -r '.response // "Error: No response from model"' /tmp/url_analyze_response.json 2>/dev/null)
rm -f /tmp/url_analyze_response.json

if [ "$RESPONSE" = "Error: No response from model" ]; then
    echo "$RESPONSE"
    exit 1
fi

SCORE=$(echo "$RESPONSE" | grep -oP 'SAFETY_SCORE:\s*[+-]1' | grep -oP '[+-]1')
ANALYSIS=$(echo "$RESPONSE" | sed '/SAFETY_SCORE:/d')

echo ""
echo "=============================================="
echo "$ANALYSIS"
echo ""

if [ "$SCORE" = "+1" ]; then
    echo "=============================================="
    echo "  ✅ SAFE  (+1)"
    echo "=============================================="
elif [ "$SCORE" = "-1" ]; then
    echo "=============================================="
    echo "  ⚠️  UNSAFE  (-1)"
    echo "=============================================="
else
    echo "=============================================="
    echo "  ⚡ UNCLEAR (no definitive score)"
    echo "=============================================="
fi
