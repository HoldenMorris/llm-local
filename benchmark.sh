#!/bin/bash

# ==============================================================================
# 🤖 LLM Spam Detection Benchmark
# Tests model against a corpus of labeled .eml files
# Usage: ./benchmark.sh [model] [prompt_file]
# ==============================================================================

CORPUS_DIR="./test-corpus"
MODEL="${1:-qwen2.5:0.5b}"
PROMPT_FILE="${2:-prompts/default.txt}"
CONTAINER_NAME="llm-spam-test"
KEEP_ALIVE="5m"
THREADS=$(nproc)
RESULTS_DIR="./results"

if [ ! -f "$PROMPT_FILE" ]; then
    echo "Error: Prompt file '$PROMPT_FILE' not found"
    exit 1
fi

SYSTEM_PROMPT=$(cat "$PROMPT_FILE" | jq -Rs .)
PROMPT_NAME=$(basename "$PROMPT_FILE" .txt)

declare -A EXPECTED
EXPECTED["spam_high"]="SPAM"
EXPECTED["spam_low"]="SPAM"
EXPECTED["phishing"]="SPAM"
EXPECTED["whale_phishing"]="SPAM"
EXPECTED["dangerous"]="SPAM"
EXPECTED["clean"]="HAM"

CATEGORIES=("spam_high" "spam_low" "phishing" "whale_phishing" "dangerous" "clean")

# quote-safe whitespace trim (xargs mangles unmatched ' and ")
trim() { tr -s '[:space:]' ' ' | sed 's/^ *//; s/ *$//'; }

extract_body() {
    sed -n '/^$/,/^--/p' "$1" | sed '1d;$d' | tr -d '\n' | sed 's/<[^>]*>//g' | trim
}

run_inference() {
    local prompt="$1" prompt_json
    prompt_json=$(printf '%s' "$prompt" | jq -Rs .)  # JSON-safe: a " in the body must not break the request
    # num_predict must clear the <think> block for reasoning models; plain models still stop at EOS after one word
    RESPONSE=$(curl -s --max-time 30 -X POST http://localhost:11434/api/generate \
        --data-raw "{\"model\":\"$MODEL\",\"system\":$SYSTEM_PROMPT,\"prompt\":$prompt_json,\"options\":{\"num_thread\":$THREADS,\"num_predict\":256,\"temperature\":0.0,\"top_k\":1},\"stream\":false,\"keep_alive\":\"$KEEP_ALIVE\"}")
    echo "$RESPONSE" | jq -r '(.response // empty) | gsub("(?s)<think>.*?</think>";"")' | tr -d '[:punct:]' | trim
}

echo "=============================================="
echo "🧪 LLM SPAM DETECTION BENCHMARK"
echo "=============================================="
echo "Model:      $MODEL"
echo "Prompt:     $PROMPT_FILE"
echo "Corpus:     $CORPUS_DIR"
echo "Date:       $(date '+%Y-%m-%d %H:%M:%S')"
echo "=============================================="
echo ""

declare -A RESULTS
declare -A CATEGORY_TIMES
CORRECT=0
TOTAL=0
TOTAL_TIME=0

for CATEGORY in "${CATEGORIES[@]}"; do
    CATEGORY_EXPECTED="${EXPECTED[$CATEGORY]}"
    CATEGORY_CORRECT=0
    CATEGORY_TOTAL=0
    CATEGORY_TIME=0
    
    echo "📂 Testing: $CATEGORY (expect: $CATEGORY_EXPECTED)"
    
    for eml in "$CORPUS_DIR/$CATEGORY"/*.eml; do
        [ -f "$eml" ] || continue
        
        BODY=$(extract_body "$eml")
        if [ -z "$BODY" ]; then
            BODY=$(grep -A100 "^From:" "$eml" | tail -n +2 | tr '\n' ' ' | xargs)
        fi
        
        START=$(date +%s.%N)
        DETECTED=$(run_inference "$BODY")
        END=$(date +%s.%N)
        DURATION=$(echo "$END - $START" | bc)
        
        if [ "$DETECTED" = "$CATEGORY_EXPECTED" ]; then
            RESULT="✅"
            ((CORRECT++))
            ((CATEGORY_CORRECT++))
        else
            RESULT="❌"
        fi
        
        ((TOTAL++))
        ((CATEGORY_TOTAL++))
        TOTAL_TIME=$(echo "$TOTAL_TIME + $DURATION" | bc)
        CATEGORY_TIME=$(echo "$CATEGORY_TIME + $DURATION" | bc)
        RESULTS["$eml"]="$DETECTED|$CATEGORY_EXPECTED|$DURATION"
        
        printf "   %s %-45s → %-6s (%.2fs)\n" "$RESULT" "$(basename "$eml")" "$DETECTED" "$DURATION"
    done
    
    if [ "$CATEGORY_TOTAL" -gt 0 ]; then
        CAT_AVG=$(echo "scale=2; $CATEGORY_TIME / $CATEGORY_TOTAL" | bc)
        CATEGORY_TIMES["$CATEGORY"]="$CAT_AVG"
    fi
    
    echo ""
done

AVG_TIME=$(echo "scale=2; $TOTAL_TIME / $TOTAL" | bc)
ACCURACY=$(echo "scale=1; $CORRECT * 100 / $TOTAL" | bc)

echo "=============================================="
echo "📊 SUMMARY"
echo "=============================================="
echo "Total tests:  $TOTAL"
echo "Correct:      $CORRECT"
echo "Accuracy:     ${ACCURACY}%"
echo "Avg time:     ${AVG_TIME}s"
echo ""

echo "Per-category breakdown:"
for CATEGORY in "${CATEGORIES[@]}"; do
    CAT_TOTAL=0
    CAT_CORRECT=0
    EXPECTED_VAL="${EXPECTED[$CATEGORY]}"
    for eml in "$CORPUS_DIR/$CATEGORY"/*.eml; do
        [ -f "$eml" ] || continue
        RESULT_DATA="${RESULTS[$eml]}"
        DETECTED=$(echo "$RESULT_DATA" | cut -d'|' -f1)
        if [ "$DETECTED" = "$EXPECTED_VAL" ]; then
            ((CAT_CORRECT++))
        fi
        ((CAT_TOTAL++))
    done
    if [ "$CAT_TOTAL" -gt 0 ]; then
        CAT_ACCURACY=$(echo "scale=0; $CAT_CORRECT * 100 / $CAT_TOTAL" | bc)
        CAT_AVG="${CATEGORY_TIMES[$CATEGORY]:-0}"
        printf "   %-18s %2d/%2d (%3s%%)  avg: %ss\n" "$CATEGORY:" "$CAT_CORRECT" "$CAT_TOTAL" "$CAT_ACCURACY" "$CAT_AVG"
    fi
done
echo "=============================================="

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
RESULTS_FILE="$RESULTS_DIR/benchmark_results.csv"

if [ ! -f "$RESULTS_FILE" ]; then
    echo "timestamp,model,prompt,total,correct,accuracy,avg_time" > "$RESULTS_FILE"
fi

echo "$TIMESTAMP,$MODEL,$PROMPT_NAME,$TOTAL,$CORRECT,${ACCURACY}%,${AVG_TIME}s" >> "$RESULTS_FILE"
echo ""
echo "📁 Results saved to: $RESULTS_FILE"
