# local-llm — URL / page phishing detection toolkit

Give it a URL. It renders the page in a sandbox, extracts the signals, and prints a
`SAFE | SUSPICIOUS | DANGEROUS` verdict, a category (`phishing`, `scam`, `login`, `content`, …)
and the evidence behind both. A small local LLM writes the rationale; a **deterministic core**
(`verdict.sh`) sets a safety floor that escalates over the LLM and never downgrades, so a flaky
model cannot talk a threat down.

Everything runs locally: Docker (Ollama, Puppeteer, webcrack) plus shell. No account needed for the
default path.

| Doc | What it is |
|-----|------------|
| [`CLAUDE.md`](CLAUDE.md) | The full reference — every detection, every flag, every cache, and why each one is capped where it is |
| [`PHISHING_ALERTS_ROADMAP.md`](PHISHING_ALERTS_ROADMAP.md) | How this plugs into the Luca **Phishing Alerts** pipeline, and the phased wiring plan |
| [`.planning/ROADMAP.md`](.planning/ROADMAP.md) | What shipped, what is next |

## Quick start

```bash
./url-analyze.sh https://example.com        # interactive analyst run (asks about cache + artifacts)
./url-analyze.sh -H https://example.com     # deterministic only: no LLM, no model, sub-second
./url-analyze.sh -m auto https://example.com    # + best benchmarked local LLM verdict
./url-analyze.sh -t -m claude https://example.com   # + VirusTotal/urlscan + Claude API verdict
./page-fetch.sh https://example.com         # page signals as JSON on stdout, no verdict
./url-analyze.sh -h                         # all flags
```

The first run pulls the Docker images and the model, so it is slow once. After that a scan is
~4–18 s with the local LLM (~50 s if the vision step fires) and sub-second with `-H`.

## What a scan does

| Phase | Work | Network |
|-------|------|---------|
| 1 — static | risky TLD, typosquat, homograph, random domain, excessive subdomains, open-redirect abuse, tunnel/redirector hosts | none |
| 2 — domain | IP geo, RDAP domain age + registry status, cert age/issuer, fast-flux DNS, prior judgements on this host / domain / campaign tag | DNS + RDAP + ip-api |
| 3 — page | sandboxed render: login form, off-domain form action, exfil hosts, brand impersonation, kit signatures, invisible-character padding, BitM WebSocket relay, obfuscated JS (escalates to deobfuscation), screenshot (escalates to a vision model) | fetches the page |
| 4 — verdict | deterministic floor from the signals, then the LLM rationale on top | local Ollama, or the Anthropic API with `-m claude-<id>` |

Scans cache per URL in `.cache/<url-hash>/` and per host in `.cache/host/<host>:<port>/`; `-r`
forces a refresh.

## Tools

| Script | Purpose |
|--------|---------|
| `url-analyze.sh` | Full URL analysis (static + dynamic + LLM). The main entry point |
| `page-fetch.sh` | Sandboxed page scraper. JSON signals on stdout |
| `verdict.sh` | The deterministic verdict core. Pure, sourced by the rest |
| `test-verdict.sh` | 188 golden cases pinning that core. No LLM, no network |
| `feedback-report.sh` | The analyst ledger: agreement rate, open flags, deep inspections, `--settled` for an alerting pipeline, `--corpus` for the weekly replay |
| `next-alert.sh` | Take the newest unruled LUCA Slack alert and say which button to click |
| `slack-harvest.sh` | Pull the verdicts analysts already recorded in Slack back into the ledger |
| `inspect.sh` | Deep inspection: headless `claude -p` reads one scan's cached artifacts and judges the verdict |
| `intel-feed.sh` | Read a threat-intel feed and print what is new, tagged with the detections we already have |
| `url-benchmark.sh` | Accuracy-vs-time matrix over a labeled URL corpus, per machine |
| `js-deobfuscate.sh` / `js-signals.sh` | Sandboxed webcrack runner and the signal extractor over its output |
| `psl.sh` / `brand-verify.sh` / `machine.sh` / `colors.sh` | Shared helpers (`source` them; each has a self-check) |
| `sync-to-luca.sh` | Publish this repo's HEAD into `luca-ecosystem/tools/local-llm` on a fresh branch. Lives in the source repo only — it is `export-ignore`d, so it is absent from the luca snapshot |
| `benchmark.sh` / `llm-test.sh` / `show_results.sh` | The original email-spam classification benchmark over `test-corpus/` |

## The feedback ledger

Every interactive scan asks whether you agree. The answers live in `.cache/*/feedback.txt` and are
the toolkit's only ground truth:

```bash
./feedback-report.sh                 # agreement rate + disagreements
./feedback-report.sh -f              # the open flags, one per line
./feedback-report.sh --corpus > url-corpus-live.txt   # settled + live URLs as a labeled corpus
CORPUS=url-corpus-live.txt ./url-benchmark.sh         # the weekly replay
```

`url-corpus-live.txt` is gitignored: live phishing URLs embed recipient email addresses and reset
tokens, so the export is never committed or synced.

## Tests

```bash
./test-verdict.sh              # 188 golden cases over the deterministic core
./feedback-report.sh --self-test
./next-alert.sh --self-test
./brand-verify.sh --self-test
./psl.sh                       # self-check
./inspect.sh                   # self-check (parsers only)
```

All of them are pure: no LLM, no network, no live infrastructure fetched.

## Requirements

- Docker — Ollama (`llm-spam-test`, 0.31+), `ghcr.io/puppeteer/puppeteer`, and a webcrack image
  that auto-builds on first use
- `jq`, `bc`, `dig`, `openssl`, `curl`; `python3` (stdlib) for `intel-feed.sh`
- Optional keys in `.env` (copy `.env.sample`): `VT_API_KEY` and `URLSCAN_API_KEY` for `-t`,
  `ANTHROPIC_API_KEY` for `-m claude-<id>`

Reference box is CPU-only (14 cores, 30 GB, no GPU). The verdict model is `qwen2.5:1.5b`.

## Troubleshooting

```bash
docker rm -f llm-spam-test      # container wedged: recreate it on the next run
docker exec llm-spam-test ollama pull qwen2.5:1.5b   # pull the verdict model by hand
./url-analyze.sh -r <url>       # ignore the cache and re-fetch everything
```
