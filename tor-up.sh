#!/bin/bash
# Tor sidecar for the headless scanner (page-fetch.sh -p tor). Free egress with a selectable
# exit country + circuit rotation. Idempotent -- a no-op when already bootstrapped. Mirrors
# ollama-up.sh's "ensure it's running" shape. See .planning/phases/ip-routing.
#
#   ./tor-up.sh [-g <cc>] [--rotate] [--down]
#     -g <cc>    exit-node country (ISO code: us, gb, de, ...). Applied live via the control port.
#     --rotate   request a fresh circuit / new exit IP (NEWNYM).
#     --down     stop + remove the sidecar.
#
# Exposes SOCKS5 on llm-tor:9050 (docker net, for the scanner container) and 127.0.0.1:9050
# (host, for the egress readout). Control port 9051 stays in-container only (never published).

set -e
NET="llm-net"
NAME="llm-tor"
IMAGE="local-llm-tor"

# Send a command to Tor's control port from inside the container (127.0.0.1:9051, null auth --
# reachable only in-container / on the isolated net, never from the host).
_ctrl() { docker exec "$NAME" sh -c "printf 'AUTHENTICATE \"\"\r\n$1\r\nQUIT\r\n' | nc -w 3 127.0.0.1 9051" 2>/dev/null; }

EXIT_CC="" ROTATE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --down) docker rm -f "$NAME" >/dev/null 2>&1 || true; exit 0 ;;
        -g) EXIT_CC="$2"; shift 2 ;;
        --rotate) ROTATE=1; shift ;;
        *) shift ;;
    esac
done

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

# Auto-build the tiny image on first use (same pattern as the webcrack image).
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "- building $IMAGE (first run)..." >&2
    docker build -t "$IMAGE" - >/dev/null <<'DOCKER'
FROM alpine:3.20
RUN apk add --no-cache tor curl
RUN printf 'SocksPort 0.0.0.0:9050\nControlPort 127.0.0.1:9051\nCookieAuthentication 0\nUser tor\nDataDirectory /var/lib/tor\n' > /etc/tor/torrc \
    && chown -R tor:tor /var/lib/tor
CMD ["tor", "-f", "/etc/tor/torrc"]
DOCKER
fi

if ! docker ps -q -f "name=^${NAME}$" | grep -q .; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    echo "- starting $NAME (Tor sidecar)..." >&2
    docker run -d --name "$NAME" --network "$NET" -p 127.0.0.1:9050:9050 "$IMAGE" >/dev/null
fi

# Block until Tor reports bootstrap 100% (fresh container needs ~5-20s).
printf '%s' "- Tor bootstrapping" >&2
_ready=""
for _ in $(seq 1 60); do
    if _ctrl 'GETINFO status/bootstrap-phase' | grep -q 'PROGRESS=100'; then _ready=1; echo " ready." >&2; break; fi
    printf '.' >&2; sleep 1
done
[ -z "$_ready" ] && { echo " timed out." >&2; exit 1; }

# Exit country (live SETCONF, no restart). Force a fresh circuit so it takes effect now.
if [ -n "$EXIT_CC" ]; then
    _ctrl "SETCONF ExitNodes=\"{$EXIT_CC}\" StrictNodes=1" >/dev/null && echo "- exit country: $EXIT_CC" >&2
    ROTATE=1
fi
[ -n "$ROTATE" ] && { _ctrl 'SIGNAL NEWNYM' >/dev/null && echo "- new Tor circuit requested" >&2; }
exit 0
