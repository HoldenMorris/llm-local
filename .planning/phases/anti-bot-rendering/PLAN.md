# Phase: Anti-bot rendering (headful + xvfb)

## Goal (what must be TRUE)
When a page's real content (e.g. a credential form) is gated behind a bot challenge
(Cloudflare Turnstile, "checking your browser", hCaptcha), the scanner either **reaches and
analyzes it** or **honestly flags that it could not**, without pretending a reliable headless
bypass exists. Improves recall on CF-fronted phishing (Azure static -> throwaway -> Turnstile
-> login.php) while staying defensive-use only.

## Open questions (answered by RESEARCH.md — deep research in progress)
1. Does **headful Chromium under xvfb** meaningfully pass more Turnstile/managed challenges
   than `headless:'new'` in 2026? At what cost (deps, RAM, speed) in the container?
2. Which **stealth/patched drivers** are still effective and worth adopting vs detected:
   puppeteer-extra-stealth, rebrowser-patches, patchright, nodriver, camoufox?
3. How much is the **IP** (datacenter vs residential) the real gate? Is a proxy option worth it?
4. What are the **fingerprint vectors** CF/Turnstile actually checks (webdriver, CDP,
   navigator, canvas/WebGL, timing, TLS/JA3/JA4, HTTP/2) — which can we neutralize cheaply?
5. Legal/ethical: what's acceptable for a defensive/authorized phishing-analysis tool?

## Candidate implementation (to refine post-research)
- `page-fetch` gains a headful mode: launch xvfb-run + Chromium `headless:false` inside the
  container (add xvfb to the image), gated behind a flag (default stays headless for speed).
- Optionally swap the launcher/stealth layer if research favors a patched driver.
- Keep the detect-and-flag + "open in local browser" fallbacks already shipped.

## Non-goals
- Paid CAPTCHA/Turnstile solver services.
- Any technique whose only realistic use is offensive.
- A perfect bypass — Turnstile is an arms race; "reach more, honestly flag the rest" is the bar.
