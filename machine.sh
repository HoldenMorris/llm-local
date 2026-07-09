#!/bin/bash

# machine_id -> a compact hardware fingerprint (cores / RAM / GPU) for grouping benchmark
# results. A model's speed depends heavily on the box it ran on, so timings are only
# comparable within the same machine_id. Source this file, then call machine_id.
# Example: 14c-30g-cpu   or   16c-64g-NVIDIA-GeForce-RTX-4090
machine_id() {
    local cores ram gpu
    cores=$(nproc 2>/dev/null || echo '?')
    ram=$(free -g 2>/dev/null | awk '/^Mem:/{printf "%dg", $2}')
    gpu=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 | tr ' ' '-')
    printf '%sc-%s-%s' "$cores" "${ram:-?g}" "${gpu:-cpu}" | tr -d ','
}
