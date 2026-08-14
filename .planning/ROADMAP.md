# Roadmap — URL/Page phishing detection toolkit

*Status as of 2026-08-14.*

## Shipped
- **Deterministic verdict core** (`verdict.sh`) — the safety floor, the category vocabulary, the
  campaign key and the interstitial destination parser, all pure and pinned by **188 golden cases**
  in `test-verdict.sh`. The LLM writes the rationale on top; it can escalate, never downgrade.
- **Feedback ledger** (`feedback-report.sh`) — analyst agreement rows, deep inspections, gone/alive
  liveness, per-verdict **categories**, `--settled` for an alerting pipeline, and `--corpus` for the
  weekly replay. 365 responses, 134 inspected, 5 flags still open.
- **Prior-judgement rollups** — a settled verdict on the host, on the registrable domain, or on the
  **campaign tag** (`?s1=…`, a SendGrid tracking blob) is evidence about the next URL, with the
  tenant-suffix guard that stops one operator's judgement tainting another's.
- **Slack alert path** — `next-alert.sh` turns the newest unruled LUCA alert into the button to
  click (ledger first, scan only what it cannot answer, never clicks itself);
  `slack-harvest.sh` pulls the rulings analysts already made in Slack back into the ledger
  (first run: 98 rulings, and an alert sample went from 0/22 settled to 19/22).
- **Kit fingerprinting** — invisible-character stripping, anti-analysis probe detection, the
  `kitSignatures` table (1Phish / Tycoon2FA / Kratos / BitM relay), and the **Browser-in-the-Middle**
  same-origin WebSocket read off CDP, for the kit that never submits.
- **Bot gates** — Turnstile / hCaptcha / reCAPTCHA and unrecognised cloaks detected; **operator
  attach** re-scans the uncloaked DOM over CDP from the analyst's own browser; a gate plus a
  confirmed sibling now floors to DANGEROUS, so a cloak cannot protect the kit it hides.
- **Escalations that find the credential surface** — follow one same-apex login link, follow an
  interstitial's decoded destination (age-gated so a real tracker stays context), and the Wayback
  CDX history for a dead or gated URL.
- **Third-party reputation** (`-t`) — VirusTotal + urlscan (both `overall` and `engines`), with a
  5-vendor consensus flooring to DANGEROUS on its own.
- **Egress routing** (`-p tor -g <cc>`) — Tor sidecar for geo-gated and scanner-blacklisting kits.
- **Threat-intel intake** (`intel-feed.sh`) — new posts tagged with the detections we already have,
  or `NO MATCHING DETECTION`.
- **Public-suffix correctness** (`psl.sh`) — registrable domain, not "last two labels", across the
  age, typosquat, subdomain-depth, entropy and fast-flux checks.
- **URL scan cache** — page/screenshot/meta/scripts/vision/LLM cached per URL hash, plus a per-host
  fact cache (~2.6 s → ~0.2 s on a known host).
- **Model benchmark** (`url-benchmark.sh`) — accuracy-vs-time matrix, machine-grouped;
  `model-scout.sh` finds new GGUF contenders. Current verdict pick: `qwen2.5:1.5b`.
- **JS deobfuscation** — webcrack (sandboxed) on obfuscated inline JS; aliased-atob detection;
  base64 exfil-URL extraction (incl. `+`-strip evasion) → exfil-target domains + DANGEROUS floor.
- **Shadow-DOM / SPA rendering** — shadow-piercing queries, mount-wait poll, iframe scan,
  stealth masking (navigator.webdriver etc.).
- **Console capture** — page console/errors/failed-requests as signals + diagnosis.
- **Redirect chain** — DNS-profiled hops, risky-TLD redirect counting, Cloudflare-challenge
  detection.
- **Vision escalation** — VLM brand check + credential-input double-check (catches non-password
  inputs the DOM misses).

## Planned

### Phase: Kit fingerprinting  — steps 1-3 shipped, 4-5 open
**Why:** attackers do not write URLs, they buy kits, and a kit leaks its build. Half the field by
volume (device-code and reverse-proxy AiTM) shows us a genuine page and cannot be caught by
appearance at all, while the other half leaks fixed asset names, endpoint paths and an
anti-analysis routine written specifically against our headless Linux scraper. Research, the top
ten kits of mid-2026 and what each one gives a URL scanner:
[phases/kit-fingerprinting/RESEARCH.md](phases/kit-fingerprinting/RESEARCH.md).

**Build order (cheapest first):**
1. ~~Strip invisible Unicode before every text match~~ — SHIPPED (c0f2d01).
2. ~~Detect the anti-analysis code itself~~ — SHIPPED (c0f2d01), capped at SUSPICIOUS.
3. ~~Kit signature table over the page markup~~ — SHIPPED. 1Phish / Tycoon2FA / Kratos / BitM
   relay. Adding a kit means adding a row; the bar for a token is "distinctive on its own".
3b. ~~Browser-in-the-Middle: the kit that never submits~~ — SHIPPED (622e68a). Same-origin
   WebSocket read straight off CDP, capped at SUSPICIOUS; the `socket.io` + `domdiffer` pair is
   the kit signature that reaches DANGEROUS.
4. A JS **capability vector hash** as a rotation-proof kit fingerprint, wired in as a fourth
   rollup key beside host / apex / campaign. Validate against the ledger corpus first.
5. Registrar out of the RDAP response we already fetch, as a grouping key.

### Phase: Slack scan loop  — shipped as `next-alert.sh` + `slack-harvest.sh`
**Shipped (2026-08-13/14):** Slack is connected here and the channel is
`#luca-phishing-alerts` (`C099U43SRS5`). `next-alert.sh` takes the newest alert **nobody has
ruled on** — an alert still showing buttons, i.e. no `Recorded:` line — asks `--settled` **before**
any network, scans only what the ledger cannot answer, resolves a Skip with the deep inspection
(`inspect.sh`), wipes the scan artifacts afterwards (`KEEP=1` keeps them), and says which button to
click. It never clicks: a recorded verdict must mean a human looked. `slack-harvest.sh` closes the
other direction, importing the rulings that only ever lived in Slack.

**Still open:** a periodic pass. Today it is one alert per invocation, run by hand. `/loop` plus
this script is the cheap version when the volume asks for it.

**Original why:** the automated-triage plan in [phases/slack-auto-triage/INTAKE.md](phases/slack-auto-triage/INTAKE.md)
has not moved, and its blockers are all **access**, not design: the Slack app has no authorisation
("contact samg"), the gateway host may not have Docker, and the ledger is machine-local. Holden's
own Slack session through Claude sidesteps all three — no app authorisation, no gateway deploy, no
`luca-ecosystem` change, and the scan runs on the machine that already has Docker, Ollama and the
ledger.

**Goal:** a URL posted in @Luca Phishing Alerts, or sent to Holden, is checked against the ledger
and — only if unknown — scanned, with a reply **drafted** for him to send. It drafts and never
posts, which also settles the attribution problem the earlier intake raised: if a human sends every
reply, `inspected` still means somebody looked.

**Honest limit:** the gateway's biggest win was *suppression* — `poll_once` checks the ledger
**before posting**, so a settled alert never reaches the channel. Claude sees a message only after
it is posted, so this route answers the noise rather than preventing it. Suppression still needs the
gateway; the ledger check, dedupe key and inspection wrapper built here are what it will inherit.
See [phases/slack-scan-loop/](phases/slack-scan-loop/).

### Phase: Scan review 2026-08-12 (signal precision + ledger integrity)  ← NEXT
**Why:** two scans on one day exposed the same thing from opposite directions. An adult gateway
read `SUSPICIOUS (other)` because nothing we run could name a page made entirely of pictures; a
genuine bank e-statement on S3 produced five false signals while the verdict stayed SAFE the whole
time — and that one still cost a human triage, which then wrote a self-contradicting row into the
ledger and exported a false label into the replay corpus.

**Goal:** every signal we print has a known precision, the vision model's new ADULT claim is
measured rather than assumed, and a settled row cannot quietly contradict itself. Everything is
answerable from artifacts already on disk (293 cache entries, ~290 screenshots, 147 labelled URLs)
— no new scans of live infrastructure.
See [phases/scan-review-2026-08-12/](phases/scan-review-2026-08-12/).

### Phase: Anti-bot rendering — operator attach shipped; automated bypass on hold
**Why:** Cloudflare Turnstile and similar anti-bot challenges gate the real credential page
from our headless scraper (e.g. `zbeem.top/…/login.php` behind Turnstile). Headless Chrome from
a datacenter IP gets the hardest, non-auto-passing challenges, so we land on a dead 404 and never
see the login form. See [phases/anti-bot-rendering/](phases/anti-bot-rendering/).

**Goal:** reach and screenshot/analyze content that is currently gated behind bot challenges,
as far as is feasible and appropriate for a *defensive* scanner — without pretending headless
CF-Turnstile bypass is reliably solvable.

**Front-runner (operator-in-the-loop):** the analyst passes the gate in a real visible browser;
page-fetch **attaches over CDP** (`puppeteer.connect`) to the cleared tab and analyses the
uncloaked DOM — or harvests the `cf_clearance` cookie to reuse. Sidesteps the whole JA4 / proxy /
solver arms race. Headful+xvfb is the auto best-effort fallback. See CONTEXT.md + PLAN.md.

**Scope to decide (pending research):**
- Headful Chromium under `xvfb` in the container (passes more challenges than `headless:'new'`).
- Patched/stealth automation drivers (puppeteer-extra-stealth, rebrowser-patches, patchright,
  nodriver) vs their current detectability.
- The IP problem (datacenter vs residential) and whether a proxy option is worth exposing.

**Done:**
- Detect Turnstile/hCaptcha/reCAPTCHA **and unrecognised custom cloaks**, flagged as "real page
  gated from the scraper".
- Best-effort auto-pass: `--disable-blink-features=AutomationControlled` + wait-and-follow.
- **Operator attach — SHIPPED (525cc29).** The analyst clears the gate in a real Brave window and
  `page-fetch.sh` re-reads the cleared tab over CDP (`PAGE_ATTACH=`, `puppeteer.connect`). The
  uncloaked page and screenshot overwrite the cache, so the verdict and the VLM run on the real
  page. Interactive-only, always prompts, falls back to "open it yourself" if Brave is missing.
- **Harvest what a gate leaks unsolved** — the widget **sitekey** (operator attribution,
  context-only) and the Wayback history, because a gated scan is factless the way a dead URL is.
- **A gate must not protect the kit it hides** — gate smell + a confirmed sibling (host,
  registrable domain or campaign tag) floors to DANGEROUS, on both the heuristic and the LLM path.

**On hold, deliberately:** automated bypass (patched drivers, xvfb, proxies, solvers). The 2026
benchmarks say it is not reliably winnable headless from a datacenter IP
([phases/anti-bot-rendering/RESEARCH-2026-08.md](phases/anti-bot-rendering/RESEARCH-2026-08.md)).

**Non-goals:** paid CAPTCHA-solver integration; anything that only serves offensive use.

### Backlog
- `-F` follow mode: re-scan off-domain redirect targets as their own pass.
- External `<script src>` fetch + deobfuscation (currently inline-only).
- REstringer escalation for JS webcrack can't crack.
- Aggregate exfil/redirect domains into a cross-scan watchlist.
