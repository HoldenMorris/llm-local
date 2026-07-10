# Context: egress IP routing (geo-target / cloak / rotate)

## Why
Some phishing kits only fire when the visitor's IP is in the **target geo** (US/UK/…); from an
out-of-zone IP they cloak to a benign page. Others **blacklist scanner IPs** after a few hits, or
hard-block known datacenter/cloud ranges. Our two browsers sit at opposite ends of this:

| | Headless scanner (`page-fetch.sh`, Docker) | Attached Brave (operator, host) |
|---|---|---|
| Current IP | Docker/host — **worst tier**, datacenter-flagged, easily blacklisted | operator's **real residential IP** — best tier, passes Turnstile |
| Gap | flagged as a scanner; wrong geo | right reputation, but **one country** (operator's) |
| Routing buys | geo + rotation + attribution hygiene | only geo (a proxy would *destroy* its residential edge) |

## The free tradeoff (the honest ceiling)
- **Geo-targeting** = easy + free (Tor exit-country, free-VPN location).
- **Residential reputation** = the *real* gate on sophisticated kits, and **no free tool delivers
  it** — every free option is datacenter or Tor (both flagged). The only free residential IP is the
  operator's own (attach mode). Legit free *residential* proxies don't exist (the "free" ones are
  botnet/malware — excluded).

## Options considered (free)
1. **Tor SOCKS** — free, exit-country selectable (`ExitNodes {us}`), rotate via `NEWNYM`. Best
   free geo+rotation. BUT Tor exits are widely blocked/challenged (Cloudflare) and many kits block
   Tor outright. Good for naive geo/blacklist gates + attribution hygiene; useless vs Tor-aware kits.
2. **Free VPN** (ProtonVPN free US/NL/JP, Windscribe ~10c/10GB) — different-country IP, still
   datacenter ASN, limited countries, shared IPs may be pre-blacklisted. Easiest host-wide.
3. **gluetun VPN container** — sidecar the scanner routes through; clean isolation, thin free-provider support.
4. **Public proxy lists** — VETOED: honeypots/MITM risk while fetching live malware.
5. **Cheap in-country VPS** (~$5, not free) — reliable + geo-correct but datacenter. Out of scope (free-only).

## Decisions (locked with operator, 2026-07-10)
- **Scope:** both browsers, independently. Scanner routes per-scan; attached Brave geo-switches by
  inheriting a host VPN (near-zero code — Brave uses the host route).
- **Goals (priority):** geo-targeting, dodge scanner blacklists, attribution hygiene. NOT residential
  reputation (accepted ceiling; attach mode covers the operator's own geo).
- **Budget:** free only — Tor + free VPN + residential attach.
- **Mechanism:** `page-fetch.sh -p tor|vpn|none` (+ `url-analyze.sh` passthrough), toggleable.

## Non-goals
Residential-reputation spoofing, paid residential proxies, public proxy lists, per-request rotation
mid-scan, JA3/TLS spoofing. When a kit needs residential + in-zone, the answer is attach mode on the
operator's IP (their geo) or a paid path — out of free scope, flagged honestly, not faked.
