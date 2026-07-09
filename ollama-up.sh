#!/bin/bash

# Shared Ollama bootstrap. Source this file, then call `ensure_ollama`.
#
# ensure_ollama brings up the Ollama container (GPU-accelerated when an NVIDIA
# GPU is present) and blocks until the API on :11434 answers. It is idempotent:
# a no-op when the container is already serving. Returns non-zero on failure.
# Honors $CONTAINER_NAME (default: llm-spam-test) and $KEEP_ALIVE (default: 5m).

ensure_ollama() {
    local name="${CONTAINER_NAME:-llm-spam-test}"
    local keep_alive="${KEEP_ALIVE:-5m}"

    if docker ps -q -f name="$name" | grep -q .; then
        echo "${GREEN:-}[+] Ollama container already running.${RESET:-}"
    elif docker ps -aq -f name="$name" | grep -q .; then
        echo "${CYAN:-}[*] Restarting existing Ollama container...${RESET:-}"
        docker start "$name" >/dev/null || return 1
    else
        echo "${CYAN:-}[*] Creating new Ollama instance...${RESET:-}"
        local gpu_flag=""
        if nvidia-smi &>/dev/null; then
            echo "${GREEN:-}[+] GPU: NVIDIA detected. Enabling hardware acceleration.${RESET:-}"
            gpu_flag="--gpus all"
        else
            echo "${CYAN:-}[i]  GPU: none. Running on CPU.${RESET:-}"
        fi
        docker run -d $gpu_flag --name "$name" -p 11434:11434 \
            -e OLLAMA_KEEP_ALIVE="$keep_alive" \
            -v ollama_storage:/root/.ollama ollama/ollama:latest >/dev/null || return 1
    fi

    printf "${CYAN:-}[.] Waiting for Ollama API on :11434...${RESET:-}"
    for _ in $(seq 1 30); do
        if curl -s --max-time 5 localhost:11434/api/tags >/dev/null 2>&1; then
            echo " ready."
            return 0
        fi
        sleep 1
    done
    echo " timed out - Ollama not ready on :11434." >&2
    return 1
}
