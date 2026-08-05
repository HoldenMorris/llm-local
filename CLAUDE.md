# CLAUDE.md

## Ponytail Mode (Lazy Senior Dev)

Before you write code, stop at the first rung that holds:

1. Does this need to exist at all? (YAGNI)
2. Does it already exist in this codebase? Reuse it.
3. Does the standard library already do this? Use it.
4. Does a native platform feature cover it? Use it.
5. Does an already-installed dependency solve it? Use it.
6. Can this be one line? Make it one line.
7. Only then: write the minimum code that works.

Rules:
- No abstraction that nobody requested
- No new dependency if you can avoid it
- No boilerplate that nobody asked for
- Deletion over addition. Boring over clever. Fewest files possible.
- Shortest working diff wins
- Mark intentional simplifications with a `ponytail:` comment

Not lazy about: input validation, error handling, security, accessibility.

## Project Status

**Current focus:** URL/Page phishing detection toolkit

### Detection changes drive forward. Improve BOTH paths, never flip-flop

When a double-check of a URL exposes a miss, the fix must ratchet **both** paths forward.
The two paths are the deterministic heuristic core (`verdict.sh` / `page-fetch.sh`) and the
LLM. Never trade one against the other. A miss usually has two co-causes. First, the flaky
small LLM returns empty output, or contradicts a known fact like `HAS_LOGIN`. Second, a
heuristic floor scored 0 and let the LLM downgrade the verdict.

A patch to only the LLM (prompt tweaks), or to only the heuristic, moves the false result
around. The next scan then flips the other way. So every detection fix does three things:

1. **Make the deterministic floor catch it**, so the verdict holds whatever the LLM says.
   `classify_verdict` escalates over the LLM but never downgrades. Lean on that.
2. **Harden the LLM path too**: retry on empty, starve miscount fuel, feed it deterministic facts.
3. **Pin it** with a `test-verdict.sh` golden case. Confirm no regression on a known-good page.

Guard against false positives while you drive forward. Cap each new floor at the severity the
signal earns. A login page plus an off-CDN third-party host is SUSPICIOUS, not DANGEROUS.
Reuse the upstream filtering, such as the `cdnRe` regex in `page-fetch.sh`, so legit CDNs and
captchas do not trip the floor.

### Recommended models (CPU-only laptop: 14 cores, 30GB RAM, no GPU)

| Role | Model | Notes |
|------|-------|-------|
| Verdict LLM | `qwen2.5:1.5b` | URL benchmark (`14c-30g-cpu`): 100% (5/5), ~18s avg (~4-5s on clean pages), ~2× faster than gemma2:2b. Non-reasoning. `-m auto` picks it. |
| Runner-up | `gemma2:2b` | Also 100% on the URL corpus, but ~2× slower. Best on the email-spam benchmark (`benchmark.sh` plus `prompts/focused.txt`, 96%). |
| Vision | `openbmb/minicpm-v4.6:q4_K_M` | The only small VLM. ~50s per screenshot. Login-form escalation only. |
| Avoid for verdict | `llama3.2:3b`, `minicpm5` (1B), `minicpm4.1` (8B) | `llama3.2:3b` false-positived a real login page. Reasoning models whiff (1B) or take ~2min (8B). |

Ollama runs in the `llm-spam-test` container, which needs version 0.31 or later for the newer
VLM architectures.

### Tools

| Script | Purpose |
|--------|---------|
| `url-analyze.sh` | Full URL analysis (static plus dynamic plus LLM) |
| `url-benchmark.sh` | Compare models (plus the `none` no-model baseline) on a labeled URL corpus |
| `model-scout.sh` | Find small GGUF model contenders on Hugging Face (prints `ollama pull` commands) |
| `machine.sh` | Shared hardware fingerprint (cores/RAM/GPU) so benchmark timings group by machine |
| `page-fetch.sh` | Sandboxed page scraper with phishing signals |
| `js-deobfuscate.sh` | Sandboxed webcrack runner: obfuscated JS in, cleartext out |
| `js-signals.sh` | Extract phishing signals from deobfuscated JS (`source` it, `js_signals`) |
| `benchmark.sh` | Email spam classification benchmark |
| `test-verdict.sh` | Golden tests that pin the deterministic verdict core (`verdict.sh`). Pure: no LLM, no network |
| `feedback-report.sh` | Mine analyst feedback (the "Do you agree?" prompt in `url-analyze.sh`) from `.cache/*/feedback.txt` into an agreement-rate and disagreement report. `-f` prints only the **open** flags, one per line. `-i <url> <note>` records a deep inspection: it appends an `inspected` row with what you found, which closes the flag. Rows are append-only and the **latest row wins**, so an inspection supersedes the flag but never erases it, and a later re-flag re-opens the URL. The prompt also takes `i` (inspect now): it writes the flag, then runs headless `claude -p` (read-only tools) over the cached scan artifacts to triage the verdict, and records the `NOTE:` line it returns as the inspection that closes the flag. No `claude` on PATH, or a failed run, falls back to a note you type. Run `--self-test` for the self-check |
| `psl.sh` | Public Suffix List helper. `source` it, then `apex_of <host>`. Gives the true registrable domain. Caches the list in `.cache/` and refreshes it every 30 days. Run `./psl.sh` for the self-check |
| `brand-verify.sh` | Ask if the **brand's own site** links to a host. `PROVEN` suppresses a brand smell. `UNPROVEN` escalates nothing. Run `--self-test` for the self-check |
| `tor-up.sh` | Bring up the Tor sidecar (`llm-tor`) for scanner egress: exit country and circuit rotation. `--down` stops it |
| `llm-test.sh` | Single email test |
| `colors.sh` | Shared ANSI colors. `source` it, then use `${RED}..${RESET}` or `cecho` |

### colors.sh (shared)

Any tool can `source "$SCRIPT_DIR/colors.sh"` after it parses args. That gives:
- Vars: `RED GREEN YELLOW BLUE CYAN GREY BOLD DIM RESET`
- Readable helpers: `echo_red "..."`, `echo_green`, `echo_yellow`, `echo_blue`,
  `echo_cyan`, `echo_grey`, `echo_bold`, and `cecho <color> <text>`.

The helpers print color **only** when stdout is a terminal and color stays on. Three things
turn color off: the `-c mono` flag (the tool sets `MONO=1` before it sources the file), the
`NO_COLOR` env var, and a non-terminal stdout (a pipe or a capture). Machine-parsed output
therefore stays plain ASCII. Four tools use `colors.sh`: `url-analyze.sh`, `url-benchmark.sh`,
`benchmark.sh`, and `llm-test.sh`. All four accept `-c mono` as a leading flag.

### URL scan cache

`url-analyze.sh` caches the work for each URL in `.cache/<url-hash>/`: page content
(`page.json`), screenshot (`page.jpg`), the followed credential page and its screenshot
(`page-login.json`, `login.jpg`), domain metadata (`meta.env`), inline scripts
(`scripts/`), deobfuscation signals (`deob-signals.txt`), the vision VLM verdict
(`vision.txt`), and each LLM answer (`llm-<hash>.txt`, keyed by model and request). A re-scan
therefore reuses the fetch, the ~1min vision call, and the LLM verdict instead of a re-compute.
`-r` forces a full refresh.

Flags:
- `-m <model>` picks the verdict LLM. `-m auto` picks the best model per
  `results/url_benchmark.csv` and falls back to `qwen2.5:1.5b`. `-m none` matches `-H`.
  **`-m claude-<id>`** (or bare `-m claude`, which aliases `claude-opus-4-8`) runs the verdict
  LLM through the **Anthropic API** instead of local Ollama. That path is opt-in and needs
  `ANTHROPIC_API_KEY` in `.env`. `VISION_MODEL=claude-<id>` does the same for the screenshot reader.
- `-s` skips the page fetch.
- `-V` turns off vision.
- `-H` is heuristic-only: no LLM, verdict straight from the decision table in `verdict.sh`.
- `-r` ignores the cache.
- `-c mono` turns off color.
- `-D` skips JS deobfuscation.
- `-t` adds third-party reputation (VirusTotal plus urlscan.io). Off by default, opt-in, not in
  the benchmarks. See below.
- `-p tor` routes scanner egress through Tor. `-g <cc>` sets the exit country. See below.

On a bot gate the tool offers operator attach (see below). With no URL argument it prompts for
one. The interactive model menu lists `0: none (pure heuristic)` plus the installed models, and
defaults to the best one (press Enter). The LLM analysis line prints which model ran and how
long it took.

### Third-party reputation (`-t`, opt-in)

`-t` adds external verification from **VirusTotal** and **urlscan.io**. It stays off by default,
and the benchmarks never trigger it because they do not pass `-t`. Results cache per URL in
`.cache/<hash>/{virustotal,urlscan}.json` and respect `-r`. The tool does not cache a miss or an
error. Keys live in a gitignored `.env` (copy `.env.sample`). `VT_API_KEY` is mandatory and free
([docs](https://docs.virustotal.com/reference/overview)). `URLSCAN_API_KEY` is optional, because
urlscan search is a public API and the key only raises rate limits.

VirusTotal reads `last_analysis_stats` by base64url URL id. urlscan **searches existing public
scans only** (no submission) and reads **both** `verdicts.overall` and `verdicts.engines` from the
latest scan. The two are separate judgements: `engines` carries urlscan's own ML classifier and it
often calls a page malicious while `overall` stays at 0, so reading only `overall` threw away a
score-96 hit on `healthlynotes.com`. Either verdict alone is **one** red flag, never two, and the
flag text names which one fired. A
confirmed-malicious hit from either source feeds the deterministic safety floor as a red flag
(appended to `SMELLS`), and both summaries go into the LLM context. A VirusTotal consensus of
**5 or more vendors** floors the verdict to DANGEROUS on its own, with no login form needed:
scam storefronts and droppers take money rather than passwords. **Rate limits:** the
VirusTotal free tier allows 4 requests per minute and 500 per day. The per-URL cache means a
re-scan costs zero API calls.

### Operator attach mode (bot gates: Turnstile / hCaptcha / reCAPTCHA)

Our headless container is the weakest tier against bot gates. See
`.planning/phases/anti-bot-rendering`. `page-fetch.sh` detects the major providers by the
scripts they load: **Cloudflare Turnstile**, **hCaptcha**, and **reCAPTCHA**. It then pushes a
smell that ends `... - real page gated from the scraper`. This fires whether the challenge is
invisible or an interactive click.

On any such smell, `url-analyze.sh` offers **operator attach**. It rings a terminal **bell** and
always asks first `[Y/n]`. It then opens a visible **Brave** (`/snap/bin/brave`) at the gated
URL, with a throwaway profile and `--remote-debugging-port=9222`. You have a residential IP and
a real browser, so you clear the gate and land on the real page. Press Enter, and the tool
re-scans by a CDP **attach** to your cleared tab. `page-fetch.sh` runs with `PAGE_ATTACH=<url>`,
calls `puppeteer.connect` over Docker `--network host`, and reads the live uncloaked DOM. That
path does no launch, no navigation, and no stealth.

The uncloaked `page.json` and screenshot overwrite the cache, so a re-scan reuses them and the
verdict and vision run on the real page. The tool **opens and closes** Brave, and kills it with
`pkill -f <profile>` on exit, INT, and TERM, because snap Brave daemonizes out of the process
group of the launcher. Attach is interactive-only (`[ -t 0 ]`), so it never fires in the
benchmarks. The tool **always prompts you before a window opens**. If Brave is missing, or you
decline attach, or attach fails, the tool falls back to the plain "open in your browser" offer.

Signal: `Operator attach: analyzed the uncloaked page past the <gate> gate`. Automated bypass
(patched drivers, xvfb, proxies, solvers) stays on hold, because research showed it unreliable
and high-maintenance.

### Scanner egress routing (`-p tor`, Wave 1)

Some kits only fire for in-zone (target-country) IPs and cloak to a benign page otherwise.
Others blacklist datacenter and scanner IPs. `-p tor` routes the egress of the **headless
scanner** through a free **Tor sidecar**, for geo-targeting, blacklist-dodging, and attribution
hygiene:

```bash
./url-analyze.sh -p tor -g us <url>   # scan as if from a US IP
./tor-up.sh -g gb                     # (called automatically) set exit country live
./tor-up.sh --rotate                  # fresh circuit / new exit IP
./tor-up.sh --down                    # stop the sidecar
```

`tor-up.sh` auto-builds a tiny `alpine+tor` image (`local-llm-tor`) and runs `llm-tor` on the
`llm-net` docker network. SOCKS listens on 9050, and the control port 9051 stays in-container.
`page-fetch.sh -p tor [-g cc]` joins `llm-net` and launches Chrome with
`--proxy-server=socks5://llm-tor:9050`. SOCKS5 gives remote DNS, so there is no leak. The
control port sets the exit country live (`SETCONF ExitNodes`) and rotates the circuit
(`NEWNYM`). The tool prints the **actual exit IP and geo the page saw**
(`- egress: <ip> (<cc>, <org>)`).

**Honest ceiling (by design, see `.planning/phases/ip-routing`):** Tor exits carry datacenter
reputation, and Cloudflare and others widely block or challenge them. Many kits block Tor
outright. So `-p tor` helps against naive geo and blacklist gates and helps opsec, but it is
useless against Tor-aware or residential-only kits. No free tool gives residential reputation.
For that, **operator attach** is the reliable path, because it uses your real residential IP and
your geo.

**Security:** the tool supports only Tor egress or your own VPN, never public proxy lists, which
carry a MITM risk on live malware. The default is direct egress (no `-p`), so the benchmarks
stay the same.

### url-benchmark.sh

`url-benchmark.sh` runs `url-corpus.txt` through each engine. The corpus holds labeled
`VERDICT URL` lines. The run prints an accuracy-vs-time matrix and writes
`results/url_benchmark.csv`. The `none` engine is the no-model if-then decision table baseline,
where empty and UNCLEAR normalize to a SAFE guess. Each row carries a `machine` fingerprint from
`machine.sh`, such as `14c-30g-cpu`. Timings only compare within one machine, and `-m auto` and
`best_model` only pick from the rows of **this** machine.

```bash
./url-benchmark.sh                      # none + qwen2.5:1.5b (default)
./url-benchmark.sh gemma2:2b minicpm4.1:8b
CORPUS=my-urls.txt ./url-benchmark.sh
```

### model-scout.sh: find new contenders

`model-scout.sh` queries the Hugging Face API for small GGUF text-generation models. It prints
an `ollama pull hf.co/<repo>:Q4_K_M` line for each one, so you can throw new models into the
ring. It filters by parameter size from the repo name. A MoE name like `35B-A3B` counts as 35B,
not 3B.

```bash
./model-scout.sh                # top small instruct GGUF models by downloads
./model-scout.sh qwen 4         # search "qwen", <= 4B params
# then: ollama pull hf.co/...   &&   ./url-benchmark.sh <model>
```

## url-analyze.sh: 3-Phase Analysis

### Phase 1: Static URL Analysis (no network)

| Detection | Description |
|-----------|-------------|
| High-risk TLD | `.cfd`, `.xyz`, `.top`, `.lol`, `.sbs`, `.icu`, `.buzz`, `.monster`, and more |
| Typosquatting | Brand name in the subdomain but not the apex domain |
| Excessive subdomains | More than 4 levels (this hides the real domain) |
| Homograph attack | Non-ASCII characters in the domain |
| Random domain | High-entropy alphanumeric strings |
| Tunneling service | Host on a free tunnel or port-forwarder (`ngrok`, `trycloudflare`, `portmap.io`, `serveo`, `loca.lt`, and more). The operator hides behind a tunnel. This is a deterministic red flag, so the URL reads SUSPICIOUS even when the tunnel is down and the fetch fails. |

### Phase 2: Domain Info Lookup

| Detection | Source |
|-----------|--------|
| IP geolocation | ip-api.com (country, org, ISP) |
| Domain age | RDAP/Verisign (flags less than 30 days as high risk). The lookup uses the **registrable domain** from `psl.sh`, not the last two labels. `smithpower.autoit.za.com` gave `za.com` before, so the age read 28 years (the CentralNic registry) and every `*.za.com` phish inherited an "aged domain" pass. A host that sits directly on a shared namespace has no RDAP record, so the age reads unknown, which is the honest answer |
| SSL cert age | openssl (flags less than 7 days as suspicious) |
| SSL issuer | openssl |
| Fast-flux DNS | More than 5 A records, or TTL under 300s |

### Phase 3: Page Fetch (via page-fetch.sh)

| Detection | Description |
|-----------|-------------|
| Login form | Password field present |
| Off-domain form | Login submits to a different domain |
| IP fingerprinting | api.ipify.org, ipinfo.io, and similar |
| Compromised WordPress | Redirect to `/wp-include/` or `/wp-content/` with random paths |
| Silent refresh redirect | HTTP `Refresh:` response header, or in-body `<meta refresh>`. Not just a 3xx `Location` |
| Random URL path | High-entropy paths like `/kz51odwn/` |
| Urgency language | "suspended", "verify now", "24 hours", and similar |
| Hidden form fields | More than 3 hidden inputs |
| Sensitive field names | ssn, credit_card, cvv, routing, and similar |
| Clipboard hijacking | `oncopy`, clipboard API usage |
| Right-click disabled | `oncontextmenu` blocked |
| Crypto wallet addresses | BTC, ETH, TRX patterns |
| Brand impersonation | Brand in the page **title or form action** but not the domain (OAuth whitelist). `BRAND_MATCH=body` also matches body text (noisier) |
| Hotlinked brand image | An `<img>` served from a **brand's own domain** while the page is not that brand. A kit cloned from the real login page still points the logo at the victim brand's CDN, so the asset host gives the attribution. No logo database and no image matching. Legit pages also embed brand artwork (payment buttons, dealer logos), so this is context only: `count_red_flags` excludes it, and it floors to SUSPICIOUS **only with a login form**. Skips brands under 5 characters and the ubiquitous embed set (google, facebook, amazon, microsoft, apple, github, and the social networks) |
| Brand-lookalike subdomain | On a **multi-tenant host** (`github.io`, `pages.dev`, `netlify.app`, `vercel.app`, `web.app`, `workers.dev`, and more) the apex confers no identity. So a subdomain that spells out the page `<title>` (8 chars or more) or a known brand, wrapped in extra lure text, is impersonation. Example: `supportimmigrationadviceserviceorg.github.io` = "Immigration Advice Service". This feeds the deterministic floor: SUSPICIOUS, or DANGEROUS with a login form. It catches what the static typosquat check misses, because `github.io` reads as brand-owned (`github` is a brand) and the brand list is fixed. |
| Suspicious JS | eval(), atob(), document.write(), hex-encoded strings, obfuscator.io `_0x` identifiers, String.fromCharCode |
| External link ratio | Skewed external vs internal links |

### Phase 3.2: Follow the login link (escalation)

A marketing landing page or SPA shell often carries **no form at all**. The credential form sits
one click away behind a "Login" or "Member Portal" link. Every login-gated floor (off-CDN
third-party host, hotlinked brand artwork, brand-lookalike subdomain) stays a no-op until a
password field is seen, so a kit with a clean front page and the harvester at `/login` reads SAFE.
This is what `icamis.icam.mw` did: a SAFE verdict on a page with zero forms, and the vision model
never even ran.

`page-fetch.sh` puts the candidate links in `loginLinks` (strongest first, matched on link **text**
and path). `url-analyze.sh` spends **one** more fetch on the best one and caches it as
`page-login.json` plus `login.jpg`. If that page really asks for credentials, its smells merge as
if seen on the landed page, `HAS_LOGIN` becomes true, and the VLM reads the **credential page**
instead of the marketing shell.

Two caps hold the false positives down. The **link is never a signal**: a site that has a login
page is not suspicious, so only what the followed page contains can score. And only a
**same-registrable-domain** link is followed, because legit sites sign in off-domain
(`login.microsoftonline.com`) and following that would import the identity provider's signals as
this site's.

### Phase 3.5: JS Deobfuscation (escalation)

When Phase 3 flags obfuscation, `url-analyze.sh` escalates. It deobfuscates the inline scripts
of the page with **webcrack**, a static AST tool that runs sandboxed and never executes attacker
JS. It then re-scans the cleartext for the signals the obfuscation hid.

| Detection | Description |
|-----------|-------------|
| Off-domain exfil URL | `fetch`/XHR/form target on a different host than the landed domain |
| Cookie / storage theft | `document.cookie`, localStorage/sessionStorage reads that feed a send |
| JS redirect | `location.href/replace/assign`, `window.location=` |
| Revealed crypto address | BTC/ETH/TRX wallet decoded from the string array |

An off-domain exfil, a JS redirect, or a crypto address counts as a deterministic red flag (see
`verdict.sh`). An obfuscated **login** page that deobfuscates to off-domain exfil therefore
floors to DANGEROUS. The escalation is gated: it only runs on obfuscation markers, and it caches
per URL. `-D` skips it. To run the deobfuscator standalone: `./js-deobfuscate.sh <file.js>`.

### Phase 4: LLM Analysis

- Reads all the signals in context
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
| `BRAND_MATCH` | `strict` | Brand impersonation match scope. `strict` = title and form action. `body` = also body text |
| `VISION_MODEL` | `openbmb/minicpm-v4.6:q4_K_M` | VLM for the login-form visual brand check. Set it to `claude-<id>` (for example `claude-haiku-4-5`) to read the screenshot through the Anthropic API instead of local Ollama (needs `ANTHROPIC_API_KEY`) |
| `NO_COLOR` | (unset) | Turn off ANSI color (`-c mono` does the same) |
| `VT_API_KEY` | (unset) | VirusTotal key for `-t`, in `.env`. The VT lookup needs it |
| `URLSCAN_API_KEY` | (unset) | urlscan.io key for `-t`, in `.env`. Optional, it only raises rate limits |
| `ANTHROPIC_API_KEY` | (unset) | Claude API key for `-m claude-<id>` and `VISION_MODEL=claude-<id>`, in `.env`. Opt-in: it sends page text and screenshots to the API |

## Dependencies

- Docker with the Ollama image (`llm-spam-test` container)
- Docker with `ghcr.io/puppeteer/puppeteer` for page-fetch
- Docker `local-llm-webcrack` image (auto-builds on the first deobfuscation: `node:22-alpine`
  plus `webcrack`)
- `jq`, `bc`, `dig`, `openssl`, `curl`

## Skills Installed

- **GSD (Get Shit Done)**: project management for solo devs
- **Ponytail**: lazy senior dev mode (added from the marketplace)
