# Phase: egress IP routing (`-p none|tor|vpn`)

## Goal (what must be TRUE)
The operator can choose the **headless scanner's egress per scan** — `none` (direct),
`tor` (free, exit-country + fresh circuit), or `vpn` (free VPN via a sidecar) — to reach
**geo-gated** kits, **rotate** past IP blacklists, and keep scans **off the org's IP**. The tool
**shows the egress IP + geo** it actually used, and stays honest when the egress is blocked/flagged
(existing gate-detection + operator attach remain the fallback). Separately, the **attached Brave**
can be geo-switched by bringing up a host VPN it inherits — no per-scan plumbing.

## Decisions (see CONTEXT.md)
Free only · scope both (scanner per-scan, Brave host-inherited) · goals geo + rotation + attribution
hygiene, NOT residential reputation · mechanism `-p tor|vpn|none`.

## Approach — reuse the repo's patterns
Containerized (like `llm-spam-test`), a `*-up.sh` ensure-running helper (like `ollama-up.sh`), a
leading flag parsed then passed through. Route Chrome via a **shared docker network + `--proxy-server`**
(NOT `--network host` — that's reserved for attach mode). Egress verified by fetching ip-api through
the SAME proxy so the printed geo is what the kit saw.

## Wave 1 — Tor egress for the scanner (the free win)  ✅ SHIPPED 2026-07-10
Built: `tor-up.sh` (auto-built alpine+tor `llm-tor` on `llm-net`; live exit-country via control-port
SETCONF; `--rotate` NEWNYM; `--down`), `page-fetch.sh -p tor [-g cc]` (joins `llm-net`, Chrome
`--proxy-server=socks5://llm-tor:9050`, EGRESS readout), `url-analyze.sh -p/-g` passthrough + egress
bullet. Verified: browser egress confirmed via check.torproject.org ("configured to use Tor"), geo
shifted ZA->US/GB, exit-country targeting + rotation work, idempotent ensure ~0.4s.

- **`tor-up.sh`** (mirrors `ollama-up.sh`): ensure a small `llm-tor` container is running on a
  user-defined docker net `llm-net` (SocksPort 9050, ControlPort 9051). Tiny alpine+tor image
  (`apk add tor` + torrc), auto-built on first use. `tor-up.sh <cc>` sets exit country live via the
  control port (`SETCONF ExitNodes={cc} StrictNodes 1`) — no restart; `tor-up.sh --rotate` sends
  `NEWNYM` for a fresh circuit/IP.
- **`page-fetch.sh -p tor [-g <cc>]`**: join `--network llm-net`, add
  `--proxy-server=socks5://llm-tor:9050` to Chrome args (Chrome SOCKS5 resolves DNS remotely → no DNS
  leak). Fresh circuit per invocation. `-g us` picks exit country.
- **Egress readout**: before the fetch, `curl --socks5-hostname llm-tor:9050 ip-api.com/json` →
  print `egress: <ip> (<country>, <org>)` into the scan output + cache (`egress.txt`). If it resolves
  to a Tor/datacenter org, say so.
- **`url-analyze.sh -p tor -g <cc>`** passthrough to page-fetch; egress line shown in output.
- **Done when:** `./page-fetch.sh -p tor -g us <url>` egresses from a US IP different from direct, and
  a re-run with `--rotate` shows a different IP.

## Wave 2 — Free-VPN egress (`-p vpn`)
- **`vpn-up.sh`**: ensure a `gluetun` container `llm-vpn` on `llm-net` from a one-time free-VPN config
  (ProtonVPN free WireGuard; config path via `.env`: `VPN_WG_CONF=`). Doc the 5-min gluetun setup.
- **`page-fetch.sh -p vpn`**: `--network llm-net` + route through gluetun (`--proxy-server` to gluetun's
  http proxy, or share its netns). Same egress readout.
- **Done when:** `-p vpn` egresses from the VPN's country; missing/!running config fails loud with the
  setup hint (not a silent direct fetch).

## Wave 3 — Host geo-switch for attach + docs + guardrails
- **Attached Brave** already inherits the host route, so geo = "bring up your host VPN first." Add a
  thin optional **`vpn-geo.sh up <cc> | down`** wrapping `wg-quick` for a free ProtonVPN WG config, and
  print the attach browser's egress IP/geo (curl ip-api from the host) so the operator sees what the
  kit will see. **WebRTC leak note**: real Brave behind a VPN can leak the true IP via WebRTC — doc the
  mitigation (`brave://flags` / disable non-proxied UDP).
- **CLAUDE.md**: `-p`/`-g` flags, the free-tier ceiling, security note (only trusted egress — Tor
  project / your own VPN; never public proxy lists), Tor-blocked → attach fallback.
- **Smoke check** (`test-egress.sh`, opt-in / not in CI since it needs network+Tor): assert the `-p tor`
  egress IP differs from the direct IP and matches the requested country.
- **Done when:** docs land; egress IP/geo is visible in every routed scan; guardrails documented.

## Risks / guardrails (bake in, don't paper over)
- **Tor blocked/challenged** by many kits → not a bug; detection + attach fallback already handle it.
  Print "egress via Tor — kit may block/cloak" when `-p tor`.
- **Free VPN**: datacenter-flagged, few countries, shared IPs maybe pre-blacklisted. Set expectations.
- **Security**: only trusted egress (Tor Project image, operator's own VPN account). NO public proxy
  lists — MITM risk while fetching live malware. Enforced by only supporting tor/vpn, not arbitrary URLs.
- **Leaks**: Chrome SOCKS5 does remote DNS (good). WebRTC leak only affects the real Brave behind a
  host VPN (Wave 3 note). The headless container has no camera/mic/WebRTC exposure of the host.
- **Benchmarks unaffected**: default `-p none`; benchmarks never pass `-p`.

## Non-goals
Residential-reputation spoofing, paid residential proxies, public proxy lists, mid-scan per-request
rotation, JA3/TLS/JA4 spoofing.
