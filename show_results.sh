#!/bin/bash

RESULTS_FILE="./results/benchmark_results.csv"

if [ ! -f "$RESULTS_FILE" ]; then
    echo "No results found. Run ./benchmark.sh first."
    exit 1
fi

echo ""
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║                    📊 LLM SPAM DETECTION RESULTS                         ║"
echo "╠════════════════════════════════════════════════════════════════════════╣"
printf "║ %-20s │ %-18s │ %-8s │ %-8s │ %-10s ║\n" "TIMESTAMP" "MODEL" "ACCURACY" "CORRECT" "AVG TIME"
echo "╠════════════════════════════════════════════════════════════════════════╣"

tail -n +2 "$RESULTS_FILE" | while IFS=',' read -r timestamp model prompt total correct accuracy avg_time; do
    printf "║ %-20s │ %-18s │ %-8s │ %-8s │ %-10s ║\n" "$timestamp" "$model" "$accuracy" "$correct/$total" "$avg_time"
done

echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""

echo "By Prompt:"
awk -F',' 'NR>1 {prompts[$3]++; correct[$3]+=$5; total[$3]+=$4} END {
    for (p in prompts) {
        acc = (correct[p]/total[p])*100
        printf "   %-12s: %2d/%2d correct (%.1f%%)\n", p, correct[p], total[p], acc
    }
}' "$RESULTS_FILE"

echo ""
echo "By Model:"
awk -F',' 'NR>1 {models[$2]++; correct[$2]+=$5; total[$2]+=$4} END {
    for (m in models) {
        acc = (correct[m]/total[m])*100
        printf "   %-18s: %2d/%2d correct (%.1f%%)\n", m, correct[m], total[m], acc
    }
}' "$RESULTS_FILE"
