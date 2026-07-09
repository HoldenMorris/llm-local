#!/bin/bash

# Find small local-model contenders for the URL benchmark on Hugging Face.
# Queries the HF API for GGUF text-generation models, keeps the small ones (<= MAX_B
# params, judged from the repo name), and prints a ready-to-run `ollama pull` for each.
# Then throw one into the ring:  ./url-benchmark.sh <model>
#
# Usage: ./model-scout.sh [search] [max_params_b]
#   ./model-scout.sh                 # top small instruct GGUF models by downloads
#   ./model-scout.sh qwen 4          # search "qwen", <= 4B params
#   ./model-scout.sh "phi" 4

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/colors.sh"

SEARCH="${1:-instruct}"
MAX_B="${2:-4}"

echo "${BOLD}Hugging Face GGUF models <= ${MAX_B}B  (search: \"$SEARCH\")${RESET}"
echo ""

JSON=$(curl -s --max-time 20 \
  "https://huggingface.co/api/models?filter=gguf&pipeline_tag=text-generation&search=${SEARCH}&sort=downloads&direction=-1&limit=80")
[ -z "$JSON" ] && { echo "No response from Hugging Face (network?)."; exit 1; }

shown=0
while IFS=$'\t' read -r id dl likes; do
    [ -z "$id" ] && continue
    # Param size from the repo name: the LARGEST "<num>b" token, so MoE names like
    # "35B-A3B" (35B total, 3B active) count as 35B and get filtered out, not 3B.
    size=$(grep -oiE '[0-9]+(\.[0-9]+)?b' <<< "$id" | tr -d 'bB' | sort -rn | head -1)
    [ -z "$size" ] && continue
    [ "$(echo "$size <= $MAX_B" | bc 2>/dev/null)" = 1 ] || continue
    echo "${BOLD}$id${RESET} ${GREY}(~${size}B, dl ${dl}, likes ${likes})${RESET}"
    echo_grey "  ollama pull hf.co/$id:Q4_K_M"
    shown=$((shown+1))
done < <(echo "$JSON" | jq -r '.[] | "\(.id)\t\(.downloads // 0)\t\(.likes // 0)"')

echo ""
if [ "$shown" -eq 0 ]; then
    echo "No <= ${MAX_B}B matches. Try a broader search or a larger cap: ./model-scout.sh \"$SEARCH\" 8"
else
    echo "${GREY}$shown candidate(s). Q4_K_M is a guess -- if the pull fails, check the repo's quant tags.${RESET}"
    echo "${GREY}Then benchmark:  ./url-benchmark.sh <model-name>${RESET}"
fi
echo "${GREY}Ollama's curated library (no API): https://ollama.com/library${RESET}"
