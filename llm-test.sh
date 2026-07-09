#!/bin/bash

# ==============================================================================
# AGENT DIRECTIVE: This script is a local benchmarking & dev tool for Ollama.
# GOAL: Detect SPAM/HAM in .eml text via SLMs (Small Language Models).
# OPTIMIZATION: Uses 4-bit quantization and CPU-thread pinning for low-resource envs.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- DEFAULT CONFIG ---
CONTAINER_NAME="llm-spam-test"
MODEL_NAME="qwen2.5:0.5b" # DEFAULT: Change to "gemma2:2b" for better accuracy
KEEP_ALIVE="5m"           # Keep model in RAM for 5 minutes for instant response
THREADS=$(nproc)          # Use all available CPU cores

# --- USER OPTIONS ---
# Usage: ./llm-test.sh [-c mono] [model_name] [strict_mode: true/false]
[ "$1" = "-c" ] && { [ "$2" = mono ] && MONO=1; shift 2; }
SELECTED_MODEL=${1:-$MODEL_NAME}
STRICT_MODE=${2:-true}
source "$SCRIPT_DIR/colors.sh"

echo_bold "--- SYSTEM PRE-FLIGHT ---"

# Memory Check (Strict)
FREE_RAM=$(free -m | awk '/^Mem:/{print $4}')
if [ "$FREE_RAM" -lt 2000 ]; then
    echo_red "[-] CRITICAL: Less than 2GB RAM free. Model load will likely fail."
    exit 1
fi

echo ""
echo_bold "--- CONTAINER & CACHE ---"
source "$SCRIPT_DIR/ollama-up.sh"
ensure_ollama || exit 1

# Cache Check
echo "Checking model cache for $SELECTED_MODEL..."
if docker exec $CONTAINER_NAME ollama list | grep -q "^$SELECTED_MODEL "; then
    echo_green "[+] Model already cached."
else
    echo "Pulling model..."
    docker exec $CONTAINER_NAME ollama pull $SELECTED_MODEL
fi

echo ""
echo_bold "--- INFERENCE OPTIMIZATION ---"

SYSTEM_PROMPT="You are a spam filter. Respond only with 'SPAM' or 'HAM'."
USER_INPUT="Subject: Claim your \$5000 Amazon Gift Card! Verification required."

OPTIONS_JSON=$(cat <<EOF
{
  "num_thread": $THREADS,
  "num_predict": 5,
  "temperature": 0.0,
  "top_k": 1
}
EOF
)

API_CALL() {
    curl -s --max-time 30 -X POST http://localhost:11434/api/generate -d "{
      \"model\": \"$SELECTED_MODEL\",
      \"system\": \"$SYSTEM_PROMPT\",
      \"prompt\": \"$1\",
      \"options\": $OPTIONS_JSON,
      \"stream\": false,
      \"keep_alive\": \"$KEEP_ALIVE\"
    }"
}

if command -v jq &> /dev/null; then
    PARSE_RESP() { echo "$1" | jq -r '.response // empty'; }
else
    PARSE_RESP() { echo "$1" | grep -oP '(?<="response":")[^"]*' | xargs; }
fi

echo "Warming up model..."
WARMUP=$(API_CALL "Test." | PARSE_RESP)

echo "Running detection..."
START=$(date +%s.%N)

RESPONSE=$(API_CALL "$USER_INPUT")

END=$(date +%s.%N)
DURATION=$(echo "$END - $START" | bc)

LABEL=$(PARSE_RESP "$RESPONSE")
# Color the label: SPAM red, HAM green, anything else plain.
case "$LABEL" in
    *SPAM*) LABEL_C="$RED" ;;
    *HAM*)  LABEL_C="$GREEN" ;;
    *)      LABEL_C="" ;;
esac
echo "----------------------------------------------------"
echo "TARGET MODEL:  $SELECTED_MODEL"
echo "DETECTION:     ${LABEL_C}${LABEL}${RESET}"
echo "TIME TAKEN:    $DURATION seconds"
echo "----------------------------------------------------"

