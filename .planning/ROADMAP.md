# Roadmap — URL/Page phishing detection toolkit

## Shipped
- **URL scan cache** — page/screenshot/meta/scripts/vision/LLM cached per URL hash.
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

### Phase: Anti-bot rendering (headful + xvfb)  ← NEXT
**Why:** Cloudflare Turnstile and similar anti-bot challenges gate the real credential page
from our headless scraper (e.g. `zbeem.top/…/login.php` behind Turnstile). Headless Chrome from
a datacenter IP gets the hardest, non-auto-passing challenges, so we land on a dead 404 and never
see the login form. See [phases/anti-bot-rendering/](phases/anti-bot-rendering/).

**Goal:** reach and screenshot/analyze content that is currently gated behind bot challenges,
as far as is feasible and appropriate for a *defensive* scanner — without pretending headless
CF-Turnstile bypass is reliably solvable.

**Scope to decide (pending research):**
- Headful Chromium under `xvfb` in the container (passes more challenges than `headless:'new'`).
- Patched/stealth automation drivers (puppeteer-extra-stealth, rebrowser-patches, patchright,
  nodriver) vs their current detectability.
- The IP problem (datacenter vs residential) and whether a proxy option is worth exposing.

**Done so far:**
- Detect Turnstile/CF challenges and flag them ("real page gated from the scraper").
- Best-effort auto-pass: `--disable-blink-features=AutomationControlled` + wait-and-follow.
- When gated, **offer to open the URL in the analyst's local browser** (residential IP + real
  browser usually passes the challenge) -- opt-in, default No, shown after the verdict.

**Non-goals:** paid CAPTCHA-solver integration; anything that only serves offensive use.

### Backlog
- `-F` follow mode: re-scan off-domain redirect targets as their own pass.
- External `<script src>` fetch + deobfuscation (currently inline-only).
- REstringer escalation for JS webcrack can't crack.
- Aggregate exfil/redirect domains into a cross-scan watchlist.
