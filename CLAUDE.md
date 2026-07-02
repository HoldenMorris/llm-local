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
- Question complex requests: "Do you actually need X, or does Y cover it?"
- Mark intentional simplifications with `ponytail:` comment

Not lazy about: input validation, error handling, security, accessibility.

## Project Status

**Current focus:** Page scraper for phishing detection

### Working
- `benchmark.sh` - Email spam classification benchmark (Ollama/Docker)
- `llm-test.sh` - Single email test
- `page-fetch.sh` - Sandboxed page scraper with phishing signals (FIXED)
- `url-analyze.sh` - LLM-based URL analysis

### page-fetch.sh
Puppeteer-based scraper in hardened Docker container. Extracts:
- Redirect chains, forms, links, scripts, iframes
- Login form detection
- Third-party domains
- Phishing signals: brand impersonation, external link ratio, off-domain form submission, suspicious JS

OAuth/payment whitelist: accounts.google.com, stripe.com, supabase.co, etc. are recognized as legitimate integrations (won't trigger brand impersonation false positives).

### Test Corpus
Categories: spam_high, spam_low, phishing, whale_phishing, dangerous, clean

## Commands

```bash
./benchmark.sh [model] [prompt]     # Run full benchmark
./llm-test.sh [model]               # Test single email
./page-fetch.sh <url>               # Scrape page for phishing signals
./url-analyze.sh -m <model> <url>   # LLM URL analysis
```

## Dependencies
- Docker with Ollama image (llm-spam-test container)
- Docker with ghcr.io/puppeteer/puppeteer for page-fetch
- jq, bc

## Skills Installed
- **GSD (Get Shit Done)** - Project management for solo devs
- **Ponytail** - Lazy senior dev mode (marketplace added)
