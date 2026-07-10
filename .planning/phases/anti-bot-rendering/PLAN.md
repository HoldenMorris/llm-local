# Phase: Anti-bot rendering (headful + xvfb)

## Goal (what must be TRUE)
When a page's real content (e.g. a credential form) is gated behind a bot challenge
(Cloudflare Turnstile, "checking your browser", hCaptcha), the scanner either **reaches and
analyzes it** or **honestly flags that it could not**, without pretending a reliable headless
bypass exists. Improves recall on CF-fronted phishing (Azure static -> throwaway -> Turnstile
-> login.php) while staying defensive-use only.

## STATUS: operator attach mode SHIPPED (2026-07-10)
`url-analyze.sh -A` / auto-offer: on a `Cloudflare bot challenge` smell the tool opens a visible
Brave (throwaway profile + `--remote-debugging-port=9222`), the operator clears the gate + presses
Enter, then `page-fetch.sh` re-scans with `PAGE_ATTACH` (puppeteer.connect over Docker
`--network host`) and reads the uncloaked DOM. Tool opens AND closes Brave (`pkill -f <profile>`,
since snap Brave daemonizes out of the launcher's PGID). Uncloaked page.json+screenshot overwrite
the cache. Verified end-to-end: container→host CDP attach returns the real DOM; cleanup clears the
port. Patched drivers / xvfb / proxies / solvers remain deferred.

## DECISION (post-research — see RESEARCH.md)
Build **operator attach mode** next: CDP-connect to the analyst's already-cleared Brave tab and
analyse the uncloaked DOM. The research confirms automated Turnstile bypass is unreliable + high-
maintenance (even nodriver, the best tool, only hit 28/31 with a residential IP + headed; our
JS-stealth Puppeteer is the weakest tier). The operator's real Brave on a residential IP is the
reliable "clean browser". Defer patched drivers (patchright/nodriver) and headful+xvfb unless
attach mode proves insufficient. Skip proxies-alone / puppeteer-extra-stealth / API solvers.

Environment verified: `/snap/bin/brave` present; Docker `--network host` available (Linux), so a
container Puppeteer can `puppeteer.connect({browserURL:'http://localhost:9222'})`.

## Open questions (answered by RESEARCH.md)
1. Does **headful Chromium under xvfb** meaningfully pass more Turnstile/managed challenges
   than `headless:'new'` in 2026? At what cost (deps, RAM, speed) in the container?
2. Which **stealth/patched drivers** are still effective and worth adopting vs detected:
   puppeteer-extra-stealth, rebrowser-patches, patchright, nodriver, camoufox?
3. How much is the **IP** (datacenter vs residential) the real gate? Is a proxy option worth it?
4. What are the **fingerprint vectors** CF/Turnstile actually checks (webdriver, CDP,
   navigator, canvas/WebGL, timing, TLS/JA3/JA4, HTTP/2) — which can we neutralize cheaply?
5. Legal/ethical: what's acceptable for a defensive/authorized phishing-analysis tool?

## Approaches, ranked for THIS tool (local, CPU-only, human-run)

**A. Operator-in-the-loop (PREFERRED)** — the analyst passes the gate; the tool analyzes the
uncloaked page. Two shapes:
  - *Attach mode:* launch a real, visible Chromium with remote debugging (`--remote-debugging-
    port`), the operator solves Turnstile manually, then page-fetch **connects over CDP**
    (`puppeteer.connect`) to the already-cleared tab and runs the full extraction/screenshot/
    vision on the live DOM. No fingerprint/JA4/proxy fight at all.
  - *Clearance harvest:* operator solves once; capture the `cf_clearance` cookie (+ UA), then
    reuse it for subsequent automated `page-fetch` runs of that host until it expires.
  This is low-risk, maintainable, and matches how the tool is actually run.

**B. Headful + xvfb (auto, best-effort)** — Chromium `headless:false` under `xvfb-run` in the
container passes more *managed/invisible* challenges than `headless:'new'`. Gated behind a flag;
default stays headless for speed. Cost/efficacy TBD by research.

**C. Detect-and-flag (already shipped, always-on floor)** — when a challenge can't be passed,
flag "Cloudflare bot challenge" + offer to open in the operator's browser. Honest fallback.

**Deferred / out of scope:** patched-binary drivers (Camoufox/rebrowser) unless research shows
a cheap, maintainable win; JA4/TLS spoofing; API CAPTCHA solvers; residential proxies (the IP is
the real gate, but a proxy option is heavy and only marginally defensive — revisit if needed).

## Non-goals
- Paid CAPTCHA/Turnstile solver services baked in.
- Any technique whose only realistic use is offensive.
- A perfect headless bypass — Turnstile is an arms race; "operator passes it, tool analyses it,
  honestly flag the rest" is the bar.
