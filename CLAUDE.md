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
| Verdict LLM | `gemma2:2b` + `prompts/focused.txt` | Best benchmark: 96% acc, 15/15 threat recall, ~4s. Non-reasoning = no `<think>` tax. |
| Vision | `openbmb/minicpm-v4.6:q4_K_M` | Only small VLM; ~50s/screenshot. Login-form escalation only. |
| Avoid for verdict | `minicpm5` (1B), `minicpm4.1` (8B) | Reasoning models: 1B whiffs on signals, 8B ~2min (too slow). |

Ollama runs in the `llm-spam-test` container (needs ≥0.31 for newer VLM archs).

### Tools

| Script | Purpose |
|--------|---------|
| `url-analyze.sh` | Full URL analysis (static + dynamic + LLM) |
| `url-benchmark.sh` | Compare models (+ heuristic baseline) on a labeled URL corpus |
| `page-fetch.sh` | Sandboxed page scraper with phishing signals |
| `js-deobfuscate.sh` | Sandboxed webcrack runner: obfuscated JS in -> cleartext out |
| `js-signals.sh` | Extract phishing signals from deobfuscated JS (`source` it, `js_signals`) |
| `benchmark.sh` | Email spam classification benchmark |
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

`url-analyze.sh` caches each URL's page content, screenshot and domain metadata in
`.cache/<url-hash>/` (`page.json`, `page.jpg`, `meta.env`), so re-scans and the model
benchmark reuse one fetch instead of re-hitting Docker/the network. `-r` forces a refresh.

Flags: `-m <model>` LLM (`-m auto` = best model per `results/url_benchmark.csv`, falls
back to gemma2:2b; `-m heuristic` = same as `-H`), `-s` skip page fetch, `-V` no vision,
`-H` heuristic-only (no LLM — verdict straight from `verdict.sh`'s decision table), `-r`
ignore cache, `-c mono` no color, `-D` skip JS deobfuscation. With no URL arg it prompts
for one; the interactive model menu lists `0: [Pure Heuristic]` plus the installed models
and defaults to the best (press Enter). The LLM analysis line prints which model ran and
how long it took.

### url-benchmark.sh

Runs `url-corpus.txt` (labeled `VERDICT URL` lines) through each engine and prints an
accuracy-vs-time matrix + `results/url_benchmark.csv`. `heuristic` = the no-model
if-then decision table baseline (empty/UNCLEAR normalized to a SAFE guess).

```bash
./url-benchmark.sh                      # heuristic + gemma2:2b (default)
./url-benchmark.sh gemma2:2b minicpm4.1:8b
CORPUS=my-urls.txt ./url-benchmark.sh
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
./url-analyze.sh -m gemma2:2b <url>

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

## Dependencies

- Docker with Ollama image (`llm-spam-test` container)
- Docker with `ghcr.io/puppeteer/puppeteer` for page-fetch
- Docker `local-llm-webcrack` image (auto-built on first deobfuscation: `node:22-alpine` + `webcrack`)
- `jq`, `bc`, `dig`, `openssl`, `curl`

## Skills Installed

- **GSD (Get Shit Done)** - Project management for solo devs
- **Ponytail** - Lazy senior dev mode (marketplace added)
