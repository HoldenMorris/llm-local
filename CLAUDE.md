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

### Tools

| Script | Purpose |
|--------|---------|
| `url-analyze.sh` | Full URL analysis (static + dynamic + LLM) |
| `page-fetch.sh` | Sandboxed page scraper with phishing signals |
| `benchmark.sh` | Email spam classification benchmark |
| `llm-test.sh` | Single email test |

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
| Random URL path | High-entropy paths like `/kz51odwn/` |
| Urgency language | "suspended", "verify now", "24 hours", etc. |
| Hidden form fields | >3 hidden inputs |
| Sensitive field names | ssn, credit_card, cvv, routing, etc. |
| Clipboard hijacking | `oncopy`, clipboard API usage |
| Right-click disabled | `oncontextmenu` blocked |
| Crypto wallet addresses | BTC, ETH, TRX patterns |
| Brand impersonation | Brand mentioned but not in domain (with OAuth whitelist) |
| Suspicious JS | eval(), atob(), document.write(), hex-encoded strings |
| External link ratio | Skewed external vs internal links |

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

## Dependencies

- Docker with Ollama image (`llm-spam-test` container)
- Docker with `ghcr.io/puppeteer/puppeteer` for page-fetch
- `jq`, `bc`, `dig`, `openssl`, `curl`

## Skills Installed

- **GSD (Get Shit Done)** - Project management for solo devs
- **Ponytail** - Lazy senior dev mode (marketplace added)
