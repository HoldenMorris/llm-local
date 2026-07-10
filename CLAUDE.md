# CLAUDE.md

## Ponytail Mode (Lazy Senior Dev)

Before writing code, stop at the first rung that holds:

1. Does this need to be built at all? (YAGNI)
2. Does it already exist in this codebase? Reuse it.
3. Does the standard library already do this? Use it.
4. Does a native platform feature cover it? Use it.
5. Does an already-installed dependency solve it? Use it.
6. Can this be one line? Make it one line.
7. Only then: write the minimum code that works.

Rules:
- No abstractions that weren't explicitly requested
- No new dependency if it can be avoided
- No boilerplate nobody asked for
- Deletion over addition. Boring over clever. Fewest files possible.
- Shortest working diff wins
- Mark intentional simplifications with `ponytail:` comment

Not lazy about: input validation, error handling, security, accessibility.

## Project Status

**Current focus:** URL/Page phishing detection toolkit

### Recommended models (CPU-only laptop: 14 cores, 30GB RAM, no GPU)

| Role | Model | Notes |
|------|-------|-------|
| Verdict LLM | `qwen2.5:1.5b` | URL benchmark (`14c-30g-cpu`): 100% (5/5), ~18s avg (~4-5s on clean pages), ~2× faster than gemma2:2b. Non-reasoning. `-m auto` selects it. |
| Runner-up | `gemma2:2b` | Also 100% on the URL corpus but ~2× slower. Best on the email-spam benchmark (`benchmark.sh` + `prompts/focused.txt`, 96%). |
| Vision | `openbmb/minicpm-v4.6:q4_K_M` | Only small VLM; ~50s/screenshot. Login-form escalation only. |
| Avoid for verdict | `llama3.2:3b`, `minicpm5` (1B), `minicpm4.1` (8B) | llama3.2:3b false-positived a real login page; reasoning models whiff (1B) or are ~2min (8B). |

Ollama runs in the `llm-spam-test` container (needs ≥0.31 for newer VLM archs).

### Tools

| Script | Purpose |
|--------|---------|
| `url-analyze.sh` | Full URL analysis (static + dynamic + LLM) |
| `url-benchmark.sh` | Compare models (+ `none` no-model baseline) on a labeled URL corpus |
| `model-scout.sh` | Find small GGUF model contenders on Hugging Face (prints `ollama pull` cmds) |
| `machine.sh` | Shared hardware fingerprint (cores/RAM/GPU) so benchmark timings group by machine |
| `page-fetch.sh` | Sandboxed page scraper with phishing signals |
| `js-deobfuscate.sh` | Sandboxed webcrack runner: obfuscated JS in -> cleartext out |
| `js-signals.sh` | Extract phishing signals from deobfuscated JS (`source` it, `js_signals`) |
| `benchmark.sh` | Email spam classification benchmark |
| `test-verdict.sh` | Golden tests pinning the deterministic verdict core (`verdict.sh`); pure, no LLM/network |
| `tor-up.sh` | Ensure the Tor sidecar (`llm-tor`) for scanner egress: exit-country + circuit rotation. `--down` to stop |
| `llm-test.sh` | Single email test |
| `colors.sh` | Shared ANSI colors — `source` it, use `${RED}..${RESET}` or `cecho` |

### colors.sh (shared)

Any tool can `source "$SCRIPT_DIR/colors.sh"` (after parsing args) to get:
- Vars: `RED GREEN YELLOW BLUE CYAN GREY BOLD DIM RESET`
- Readable helpers: `echo_red "..."`, `echo_green`, `echo_yellow`, `echo_blue`,
  `echo_cyan`, `echo_grey`, `echo_bold`, and `cecho <color> <text>`.

Color is emitted **only** when stdout is a terminal **and** not disabled. Disable via
`-c mono` (the tool sets `MONO=1` before sourcing), the `NO_COLOR` env var, or a
non-terminal stdout (piped / captured) — so machine-parsed output stays plain ASCII.
Used by `url-analyze.sh`, `url-benchmark.sh`, `benchmark.sh`, and `llm-test.sh`. All four
accept `-c mono` as a leading flag.

### URL scan cache

`url-analyze.sh` caches each URL's work in `.cache/<url-hash>/`: page content
(`page.json`), screenshot (`page.jpg`), domain metadata (`meta.env`), inline scripts
(`scripts/`), deobfuscation signals (`deob-signals.txt`), the vision VLM verdict
(`vision.txt`), and each LLM answer (`llm-<hash>.txt`, keyed by model + request). So
re-scans reuse the fetch, the ~1min vision call, and the LLM verdict instead of
re-computing. `-r` forces a full refresh.

Flags: `-m <model>` LLM (`-m auto` = best model per `results/url_benchmark.csv`, falls
back to qwen2.5:1.5b; `-m none` = same as `-H`), `-s` skip page fetch, `-V` no vision,
`-H` heuristic-only (no LLM — verdict straight from `verdict.sh`'s decision table), `-r`
ignore cache, `-c mono` no color, `-D` skip JS deobfuscation, `-t` third-party reputation
(VirusTotal + urlscan.io — off by default, opt-in, not in benchmarks; see below), `-p tor` route the
scanner's egress through Tor with `-g <cc>` exit country (see below). On a bot gate it
offers operator attach (see below). With no URL arg it prompts
for one; the interactive model menu lists `0: none (pure heuristic)` plus the installed models
and defaults to the best (press Enter). The LLM analysis line prints which model ran and
how long it took.

### Third-party reputation (`-t`, opt-in)

`-t` adds external verification from **VirusTotal** and **urlscan.io**. Off by default and
never triggered by the benchmarks (they don't pass `-t`). Results cache per URL in
`.cache/<hash>/{virustotal,urlscan}.json` (respect `-r`); a miss/error is not cached.
Keys live in a gitignored `.env` (copy `.env.sample`): `VT_API_KEY` (required — free key,
[docs](https://docs.virustotal.com/reference/overview)) and `URLSCAN_API_KEY` (optional;
urlscan search is a public API, the key only raises rate limits). VT = `last_analysis_stats`
lookup by base64url URL id; urlscan = **search existing public scans only** (no submission),
reading the latest scan's `verdicts.overall`. A confirmed-malicious hit from either feeds the
deterministic safety floor as a red flag (appended to `SMELLS`), and both summaries go into the
LLM context. **Rate limits:** VT free tier is 4 req/min · 500/day; the per-URL cache means a
re-scan costs zero API calls.

### Operator attach mode (bot gates: Turnstile / hCaptcha / reCAPTCHA)

Our headless container is the weakest tier against bot gates (see
`.planning/phases/anti-bot-rendering`). `page-fetch.sh` detects the major providers by the scripts
they load — **Cloudflare Turnstile**, **hCaptcha**, **reCAPTCHA** — and pushes a smell ending
`... - real page gated from the scraper` (fires whether the challenge is invisible or an
interactive click). On any such smell `url-analyze.sh` offers **operator attach**: after a terminal
**bell** it always asks first `[Y/n]`, then opens a visible **Brave** (`/snap/bin/brave`) with a
throwaway profile + `--remote-debugging-port=9222` at the gated URL. You (residential IP, real
browser) clear the gate and land on the real page, then press Enter; the tool re-scans by
CDP-**attaching** to your cleared tab — `page-fetch.sh` runs with `PAGE_ATTACH=<url>`, which
`puppeteer.connect`s over Docker `--network host` and reads the live uncloaked DOM (no
launch/navigation/stealth). The uncloaked `page.json` + screenshot overwrite the cache, so a
re-scan reuses them and the verdict/vision run on the real page. The tool **opens and closes**
Brave (kills it via `pkill -f <profile>` on exit/INT/TERM — snap Brave daemonizes out of the
launcher's process group). Interactive-only (`[ -t 0 ]`) so it never fires in benchmarks; you're
**always prompted before a window opens**. Falls back to the plain "open in your browser" offer if
Brave isn't found or attach is declined/fails. Signal:
`Operator attach: analyzed the uncloaked page past the <gate> gate`. Automated bypass (patched
drivers / xvfb / proxies / solvers) is deferred — research showed it unreliable + high-maintenance.

### Scanner egress routing (`-p tor`, Wave 1)

Some kits only fire for in-zone (target-country) IPs and cloak to a benign page otherwise; others
blacklist datacenter/scanner IPs. `-p tor` routes the **headless scanner's** egress through a free
**Tor sidecar** for geo-targeting, blacklist-dodging, and attribution hygiene:

```bash
./url-analyze.sh -p tor -g us <url>   # scan as if from a US IP
./tor-up.sh -g gb                     # (called automatically) set exit country live
./tor-up.sh --rotate                  # fresh circuit / new exit IP
./tor-up.sh --down                    # stop the sidecar
```

`tor-up.sh` auto-builds a tiny `alpine+tor` image (`local-llm-tor`) and runs `llm-tor` on the
`llm-net` docker network (SOCKS 9050, control 9051 in-container only). `page-fetch.sh -p tor [-g cc]`
joins `llm-net` and launches Chrome with `--proxy-server=socks5://llm-tor:9050` (SOCKS5 → remote DNS,
no leak). Exit country is set live via the control port (`SETCONF ExitNodes`); rotation via `NEWNYM`.
The tool prints the **actual exit IP + geo the page saw** (`- egress: <ip> (<cc>, <org>)`).

**Honest ceiling (by design, see `.planning/phases/ip-routing`):** Tor exits are datacenter-repped and
widely blocked/challenged (Cloudflare) and many kits block Tor outright — good for naive geo/blacklist
gates + opsec, useless vs Tor-aware/residential-only kits. No free tool gives residential reputation;
for that, **operator attach** (your real residential IP, your geo) is the reliable path. **Security:**
only Tor/your-own-VPN egress is supported — never public proxy lists (MITM risk on live malware).
Default is direct (no `-p`), so benchmarks are unaffected.

### url-benchmark.sh

Runs `url-corpus.txt` (labeled `VERDICT URL` lines) through each engine and prints an
accuracy-vs-time matrix + `results/url_benchmark.csv`. `none` = the no-model
if-then decision table baseline (empty/UNCLEAR normalized to a SAFE guess). Each row is
tagged with a `machine` fingerprint (`machine.sh`, e.g. `14c-30g-cpu`) — timings only
compare within one machine, and `-m auto` / `best_model` only picks from **this**
machine's rows.

```bash
./url-benchmark.sh                      # none + qwen2.5:1.5b (default)
./url-benchmark.sh gemma2:2b minicpm4.1:8b
CORPUS=my-urls.txt ./url-benchmark.sh
```

### model-scout.sh — find new contenders

Queries the Hugging Face API for small GGUF text-generation models and prints an
`ollama pull hf.co/<repo>:Q4_K_M` for each, so you can throw new models into the ring.
Filters by param size from the repo name (MoE `35B-A3B` counts as 35B, not 3B).

```bash
./model-scout.sh                # top small instruct GGUF models by downloads
./model-scout.sh qwen 4         # search "qwen", <= 4B params
# then: ollama pull hf.co/...   &&   ./url-benchmark.sh <model>
```

## url-analyze.sh - 3-Phase Analysis

### Phase 1: Static URL Analysis (no network)

| Detection | Description |
|-----------|-------------|
| High-risk TLD | `.cfd`, `.xyz`, `.top`, `.lol`, `.sbs`, `.icu`, `.buzz`, `.monster`, etc. |
| Typosquatting | Brand name in subdomain but not apex domain |
| Excessive subdomains | >4 levels (hiding real domain) |
| Homograph attack | Non-ASCII characters in domain |
| Random domain | High-entropy alphanumeric strings |
| Tunneling service | Host on a free tunnel/port-forwarder (`ngrok`, `trycloudflare`, `portmap.io`, `serveo`, `loca.lt`, …) — operator hidden behind a tunnel. Deterministic red flag, so it reads SUSPICIOUS even when the tunnel is down and the page can't be fetched. |

### Phase 2: Domain Info Lookup

| Detection | Source |
|-----------|--------|
| IP geolocation | ip-api.com (country, org, ISP) |
| Domain age | RDAP/Verisign (flags <30 days as high risk) |
| SSL cert age | openssl (flags <7 days as suspicious) |
| SSL issuer | openssl |
| Fast-flux DNS | >5 A records or TTL <300s |

### Phase 3: Page Fetch (via page-fetch.sh)

| Detection | Description |
|-----------|-------------|
| Login form | Password field present |
| Off-domain form | Login submits to different domain |
| IP fingerprinting | api.ipify.org, ipinfo.io, etc. |
| Compromised WordPress | Redirect to `/wp-include/` or `/wp-content/` with random paths |
| Silent refresh redirect | HTTP `Refresh:` response header or in-body `<meta refresh>` (not just 3xx `Location`) |
| Random URL path | High-entropy paths like `/kz51odwn/` |
| Urgency language | "suspended", "verify now", "24 hours", etc. |
| Hidden form fields | >3 hidden inputs |
| Sensitive field names | ssn, credit_card, cvv, routing, etc. |
| Clipboard hijacking | `oncopy`, clipboard API usage |
| Right-click disabled | `oncontextmenu` blocked |
| Crypto wallet addresses | BTC, ETH, TRX patterns |
| Brand impersonation | Brand in page **title or form action** but not the domain (OAuth whitelist). `BRAND_MATCH=body` also matches body text (noisier) |
| Suspicious JS | eval(), atob(), document.write(), hex-encoded strings, obfuscator.io `_0x` identifiers, String.fromCharCode |
| External link ratio | Skewed external vs internal links |

### Phase 3.5: JS Deobfuscation (escalation)

When Phase 3 flags obfuscation, `url-analyze.sh` escalates: it deobfuscates the page's
inline scripts with **webcrack** (static AST, sandboxed — never executes attacker JS) and
re-scans the cleartext for signals the obfuscation hid.

| Detection | Description |
|-----------|-------------|
| Off-domain exfil URL | `fetch`/XHR/form target on a different host than the landed domain |
| Cookie / storage theft | `document.cookie`, localStorage/sessionStorage reads feeding a send |
| JS redirect | `location.href/replace/assign`, `window.location=` |
| Revealed crypto address | BTC/ETH/TRX wallet decoded from the string array |

Off-domain exfil / redirect / crypto count as a deterministic red flag (see `verdict.sh`) —
so an obfuscated **login** page that deobfuscates to off-domain exfil floors to DANGEROUS.
Gated (only runs on obfuscation markers), cached per URL, `-D` to skip. Scripts: run
`./js-deobfuscate.sh <file.js>` standalone.

### Phase 4: LLM Analysis

- Contextual analysis of all signals
- Verdict: **SAFE** / **SUSPICIOUS** / **DANGEROUS**
- Strict mode: "when in doubt, choose DANGEROUS"

## Brand Detection (80+ brands)

| Category | Brands |
|----------|--------|
| Tech | google, microsoft, apple, amazon, paypal, netflix, zoom, slack |
| Crypto | coinbase, binance, metamask, ledger, trustwallet, kraken |
| US Banks | chase, wellsfargo, bankofamerica, citi, schwab, fidelity, amex |
| UK Banks | barclays, hsbc, lloyds, natwest, monzo, revolut |
| EU Banks | ing, bnp, deutsche, ubs, creditsuisse |
| African Banks | nedbank, standardbank, fnb, absa, capitec, investec |
| APAC Banks | dbs, ocbc, maybank, icici, hdfc, anz, westpac |

## Commands

```bash
# Full analysis with LLM
./url-analyze.sh -m qwen2.5:1.5b <url>

# Static analysis only (skip page fetch)
./url-analyze.sh -s <url>

# Page scraper only (JSON output)
./page-fetch.sh <url>

# Email spam benchmark
./benchmark.sh [model] [prompt]
```

## Config (env vars)

| Var | Default | Effect |
|-----|---------|--------|
| `BRAND_MATCH` | `strict` | Brand impersonation match scope: `strict` = title/form-action; `body` = also body text |
| `VISION_MODEL` | `openbmb/minicpm-v4.6:q4_K_M` | VLM for the login-form visual brand check |
| `NO_COLOR` | (unset) | Disable ANSI color (also `-c mono`) |
| `VT_API_KEY` | (unset) | VirusTotal key for `-t` (in `.env`; required for the VT lookup) |
| `URLSCAN_API_KEY` | (unset) | urlscan.io key for `-t` (in `.env`; optional — raises rate limits) |

## Dependencies

- Docker with Ollama image (`llm-spam-test` container)
- Docker with `ghcr.io/puppeteer/puppeteer` for page-fetch
- Docker `local-llm-webcrack` image (auto-built on first deobfuscation: `node:22-alpine` + `webcrack`)
- `jq`, `bc`, `dig`, `openssl`, `curl`

## Skills Installed

- **GSD (Get Shit Done)** - Project management for solo devs
- **Ponytail** - Lazy senior dev mode (marketplace added)
