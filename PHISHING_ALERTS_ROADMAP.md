# local-llm → Phishing Alerts: roadmap & capability brief

**Audience: Claude (or any agent) working in `luca-ecosystem`.** This is a Claude-facing
brief, not marketing copy. It says what the `tool/local-llm` scanner already does ("what's
in the can"), where it plugs into the existing **Phishing Alerts** pipeline, and the phased
work to wire it in. Names below are real files in this repo — grep them before acting.

---

## TL;DR (the roadmap ask)

Phishing Alerts today surfaces a URL **and a bare ML probability** to a human verifier in
Slack. `tool/local-llm` is the **explainable evidence + deterministic verdict layer** that
should ride alongside that score: given an alert URL, it renders the page in a sandbox and
returns a `SAFE | SUSPICIOUS | DANGEROUS` verdict backed by concrete, human-readable signals
(login form, off-domain credential exfil, brand impersonation, deobfuscated payloads). Fold
it in as an **async enrichment worker** so the verifier sees *why*, not just *how likely*, and
low-value alerts (the beehiiv-style 46.8% false alert pinned in
`services/luca-api/tests/test_phishing_alerts_filter.py`) get auto-triaged.

It is **not wired in yet** — it's a standalone, Docker-backed CLI. This doc is the plan to change that.

---

## How Phishing Alerts works today (the seam)

| Stage | Where | What it produces |
|-------|-------|------------------|
| URL classification | `services/luca-api/app/ml/url_classification.py` | an ML score → `ClassificationAttempt(url, url_hash_id, classification, clean_probs, phishing_probs)` — `phishing_probs` on a **0–100** scale |
| Alert query | `services/luca-api/app/services/stats_service.py` → `StatsService.get_phishing_alerts(start_date, end_date, min_confidence)` (endpoint `/stats/phishing-alerts`) | high-confidence rows, filtered by `min_confidence` |
| Human verification | `services/luca-slack-gateway/app/{poller,blocks,commands}.py` | a Slack alert with **OSINT link buttons** (VirusTotal, urlscan — `blocks._osint_buttons`) that the verifier clicks, then records a verdict (`app.verdict.KNOWN_ACTIONS`) |

The gap: the verifier gets a probability and *links to go look things up by hand*. There is no
automated page-level evidence attached. **That is exactly what local-llm produces.**

---

## What's in the can (already built, `tool/local-llm/`)

Entrypoint: `./url-analyze.sh <url>` → prints a `SAFE|SUSPICIOUS|DANGEROUS` verdict. All work
caches per URL in `.cache/<url-hash>/`.

| Capability | Script | Output an agent can consume |
|------------|--------|------------------------------|
| **Deterministic verdict core** | `verdict.sh` (`classify_verdict`) | A safety **floor** from the signals that *escalates over* the LLM and **never downgrades** — so a flaky small model can't talk a threat down. Pure, no network. Pinned by `test-verdict.sh` (45 golden cases). |
| **Sandboxed page fetch** | `page-fetch.sh <url>` | JSON on stdout: `{finalUrl, redirects[], title, hasLoginForm, counts{}, thirdPartyDomains[], exfilDomains[], suspiciousJs[], phishingSmells[], console[]}`. Never executes attacker JS. |
| **Static URL analysis** | `url-analyze.sh` (phase 1) | risky TLD, typosquat, homograph, high-entropy/random domain, free-tunnel host (ngrok/trycloudflare/…). |
| **Domain intel** | `url-analyze.sh` (phase 2) | IP geo (ip-api), domain age (RDAP), SSL cert age/issuer (openssl), fast-flux DNS. |
| **Page signals** | `page-fetch.sh` | login form, off-domain form action, IP-fingerprinting calls, compromised-WordPress redirect, `Refresh:`/meta-refresh cloak, urgency language, hidden fields, **brand impersonation** (title/form-action) + **brand-lookalike subdomain** on shared hosts, crypto-wallet addresses, suspicious JS. |
| **JS deobfuscation escalation** | `js-deobfuscate.sh` (webcrack) + `js-signals.sh` | when JS is obfuscated, statically deobfuscates and re-scans → **off-domain exfil URL**, cookie/storage theft, JS redirect, revealed crypto address. Off-domain exfil floors a login page to DANGEROUS. |
| **Vision escalation** | VLM (`openbmb/minicpm-v4.6` or `VISION_MODEL=claude-<id>`) | reads the screenshot for a login-form visual brand mismatch. |
| **Bot-gate handling** | `page-fetch.sh` + `url-analyze.sh` | detects Turnstile/hCaptcha/reCAPTCHA **and unrecognized/custom cloaks**; offers **operator attach** — a human clears the gate in a real browser and the tool re-scans the uncloaked DOM by CDP-attach. |
| **Third-party reputation** | `url-analyze.sh -t` | VirusTotal + urlscan lookups (the same sources `luca-slack-gateway` links as OSINT buttons — here consumed **programmatically** and folded into the verdict). |
| **Egress routing** | `url-analyze.sh -p tor -g <cc>` | route the scanner through Tor with an exit country, for geo-gated / scanner-blacklisting kits. |
| **LLM verdict backends** | `-m qwen2.5:1.5b` (local Ollama, CPU) · `-m claude-<id>` (Anthropic API) · `-H` (no LLM, pure heuristic) | verdict + short rationale. |

CPU-only reference box (14c/30G, no GPU): ~4–18 s/URL with the local LLM, ~50 s if vision runs,
sub-second for `-H`. **Batch/async, not the inline request path.**

---

## Integration roadmap (phased, cheapest first)

**Phase A — deterministic evidence on the alert (no LLM).**
A worker consumes new high-confidence `ClassificationAttempt` rows, runs
`./url-analyze.sh -H -V -D <url>` (heuristic-only, no vision, no deobfuscation → fast, no model),
and attaches the verdict + `phishingSmells[]` to the Slack alert (extend
`services/luca-slack-gateway/app/blocks.py` next to `_osint_buttons`). Immediate win: the
46.8%-style FP shows "no login form, no exfil, benign floor" instead of an unexplained score.

**Phase B — verdict LLM on borderline scores.** For rows near `min_confidence`, enable
`-m qwen2.5:1.5b` (local) or `-m claude-<id>` (API) for a second opinion + rationale.

**Phase C — operator attach for gated alert URLs.** When Phase A/B reports `... gated from the
scraper`, route the verifier into operator-attach so the alert carries the **uncloaked** page +
screenshot rather than a blank cloak.

**Phase D — signals back into the model.** Feed local-llm's structured signals to
`luca-forge` as labeled features to retrain `url_classification.py` — closing the loop from
"explain the alert" to "make the score better".

---

## Not done yet (honest ceiling)

- **No service wrapper.** It's a CLI; Phase A needs a queue consumer + a thin JSON contract
  (`page-fetch.sh` already emits JSON; `url-analyze.sh` would need a `--json` verdict flag — small).
- **Docker-backed.** The runner needs the Ollama, puppeteer, and webcrack containers (see
  `tool/local-llm/CLAUDE.md` → Dependencies). Not free to colocate with the API pods.
- **Secrets.** `-t` and the Claude path need `.env` keys (`VT_API_KEY`, `URLSCAN_API_KEY`,
  `ANTHROPIC_API_KEY`) — `.env` is gitignored; `.env.sample` is the template.
- **Timing.** Never inline in a request; enrichment is async/batch.

---

## Agent invocation contract (quick reference)

```bash
./page-fetch.sh <url>                 # → JSON signals on stdout (last line). No verdict, no LLM.
./url-analyze.sh -H <url>             # → deterministic verdict only (SAFE|SUSPICIOUS|DANGEROUS), fast.
./url-analyze.sh -m qwen2.5:1.5b <url>   # → + small-LLM rationale
./url-analyze.sh -t -m claude <url>   # → + VirusTotal/urlscan + Claude verdict
```

Verdict values: `SAFE | SUSPICIOUS | DANGEROUS`. Cache: `.cache/<sha256(url)[:16]>/` (`-r` to
refresh). Full toolkit reference: **`tool/local-llm/CLAUDE.md`**.
