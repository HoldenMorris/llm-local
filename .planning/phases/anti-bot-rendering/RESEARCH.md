# Research: anti-bot / Turnstile arms race (2025-2026)

Deep-research pass (101 agents, 5 angles, 3-vote adversarial verification). Synthesis step
was cut off by a session limit, so this is the verified-claims set + our own recommendation.

## Verified findings (claim — [vote] — source)

**Automation leaks / driver detectability**
- Puppeteer/Playwright/Selenium leak automation via the CDP `Runtime.Enable` command, which
  emits `Runtime.consoleAPICalled` and is detectable in a few lines of page JS. [3-0]
  rebrowser.net / github.com/rebrowser/rebrowser-patches
- Fixing the CDP `Runtime.Enable` leak alone is NOT enough — proxies, UA and fingerprints must
  also match. [3-0] rebrowser-patches
- `puppeteer-extra-stealth` (JS-patch, ~20 evasions) has been unmaintained since March 2023 and
  is consistently detected by Cloudflare Bot Fight Mode and DataDome 2024+. [3-0] scrapewise.ai
- Cloudflare detects standard Selenium/Playwright via `navigator.webdriver` + CDP signatures. [—] scrapfly.io

**What actually passes (benchmark, headed, single residential IP, 31 CF targets: OK/gated/blocked)**
- **nodriver 28/3/0** (best; skips the CDP bridge so no `Runtime.enable`, but does NO behavioral
  simulation — no fake mouse/scroll/keystroke). [3-0]
- CloakBrowser & curl_cffi 26/3/2 · **Patchright** & **Camoufox** 25/3/3 · vanilla &
  rebrowser-playwright 24/2/5. [3-0] ianlpaterson.com
- Patchright patches the browser BEFORE the process starts (not page context), survives
  `Object.defineProperty` guards, and passes the nowsecure headless test most CF setups use. [2-1] scrapewise.ai
- Camoufox: 0% headless-detection but expensive — ~42.5s/bypass + 200MB+ RAM/instance. [2-1] scrapewise.ai

**The IP question**
- Residential proxies defeat IP-reputation / rate-limiting, so Cloudflare shifted to ML
  behavioral+fingerprint detection rather than IP alone. [3-0] blog.cloudflare.com
- Even with clean residential IPs, CF still catches proxy bots via request fingerprints +
  behavioral signals + global stats. [3-0] blog.cloudflare.com
- "A proxy rewrites only the IP layer. TLS handshake, HTTP/2 frames, navigator properties and
  canvas fingerprints all originate from the actual host." -> residential IP alone insufficient. [3-0]

**Turnstile modes**
- Managed mode auto-adapts to risk and only requires interaction when a further human check is
  needed — so a clean browser can pass with NO interaction. [2-1] developers.cloudflare.com
- CF does not disclose which client-side signals trigger a challenge. [3-0]

## Recommendation for THIS tool (CPU-only Docker Puppeteer, human-run)

1. **Operator-in-the-loop attach mode is the right primary path — the research validates it.**
   Our current stack (Puppeteer + JS `navigator.webdriver` masking) is the *weakest* tier: JS-patch
   stealth is reliably detected and the CDP `Runtime.Enable` leak remains. From a datacenter IP +
   headless we're near the bottom. Even the BEST automated tool (nodriver) only hit 28/31 *with a
   residential IP + headed*. So automated bypass is never reliable and is high-maintenance. The
   operator's REAL Brave (no CDP automation during the solve) on a residential IP is exactly the
   "clean browser" that passes managed Turnstile — attach AFTER they clear it and we skip the whole
   fingerprint/CDP fight. **Build this next.**
2. **Headful + xvfb**: marginal on its own (vanilla headed still 24/31) — worth it only bundled
   with a patched driver. Keep as a secondary auto best-effort, low priority.
3. **If automated bypass is ever required**: `patchright` (patches before start, survives guards,
   Node/Python — most maintainable) or `nodriver` (best score, but Python rewrite + no behavioral
   sim). Both are real adoption cost — DEFER unless attach mode proves insufficient.
4. **Skip**: `puppeteer-extra-stealth` (detected, dead); residential proxies *alone* (host
   fingerprints remain); API CAPTCHA solvers (ethics/out-of-scope).
5. **Keep (shipped)**: detect-and-flag the challenge + offer to open in the operator's browser.

**Decision:** implement operator attach mode (CDP-connect to the analyst's cleared Brave tab);
defer patched drivers and xvfb until/unless attach is insufficient.
