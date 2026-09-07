#!/usr/bin/env bash
#
# Start both halves of scope: the container that serves the UI, and the host worker that runs the
# toolkit. One command, because two terminals is one more thing to forget.
#
#   ./web/up.sh            # build if needed, start the container, run the worker in the foreground
#   ./web/up.sh --down     # stop the container
#   ./web/up.sh --rebuild  # rebuild the image first
#
# Ctrl-C stops the worker and the container together.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source "$SCRIPT_DIR/colors.sh"

IMAGE="local-llm-scope"
NAME="scope-web"
PORT="${SCOPE_PORT:-8787}"

stop() { docker rm -f "$NAME" >/dev/null 2>&1; }

case "${1:-}" in
    --down) stop; echo_grey "scope-web stopped"; exit 0 ;;
    --rebuild) stop; docker rmi -f "$IMAGE" >/dev/null 2>&1 ;;
esac

docker image inspect "$IMAGE" >/dev/null 2>&1 || {
    echo_grey "- building $IMAGE (first run only)..."
    docker build -q -t "$IMAGE" "$SCRIPT_DIR/web" >/dev/null || { echo_red "build failed"; exit 1; }
}

stop
# The spool has to exist before the mount: docker CREATES a missing bind source as a ROOT-owned
# directory, which is the same trap page-fetch.sh documents.
mkdir -p "$SCRIPT_DIR/.cache/web-jobs"

# 127.0.0.1 ONLY. These pages show live phishing screenshots and the recipient addresses embedded
# in the urls; a 0.0.0.0 bind would put all of that on the LAN.
#
# The repo goes in READ-ONLY and only .cache/ is writable, so the process that renders
# attacker-controlled strings cannot alter a single script -- including the worker's own whitelist.
#
# --user: the container and the worker share one spool directory, so they have to agree on who
# owns a file. Running as the invoking user is also what keeps every file the container writes
# owned by you rather than by a uid that only exists inside the image.
docker run -d --name "$NAME" \
    -p "127.0.0.1:$PORT:8787" \
    --user "$(id -u):$(id -g)" \
    -v "$SCRIPT_DIR:/app:ro" \
    -v "$SCRIPT_DIR/.cache:/app/.cache:rw" \
    --read-only --tmpfs /tmp \
    --security-opt no-new-privileges \
    "$IMAGE" >/dev/null || { echo_red "could not start $NAME"; exit 1; }

echo_bold "scope"
echo_green "  http://127.0.0.1:$PORT"
echo_grey  "  container $NAME (repo read-only), worker below. ctrl-c stops both."
echo ""

trap 'stop; exit 0' INT TERM
exec "$SCRIPT_DIR/web/worker.sh"
