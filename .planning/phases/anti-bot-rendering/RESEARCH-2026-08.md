# Research addendum: the bot-gate ceiling, revisited 2026-08-12

Re-checked the 2025-2026 research (`RESEARCH.md`) now that operator attach has shipped. Two
questions: has the bypass landscape moved, and is passing the gate the only way through it?

## 1. The bypass landscape has NOT moved. Keep deferring.

The 2026 benchmarks say the same thing the earlier pass did, tool for tool:

- **nodriver** still wins outright — the only tool with zero blocked targets across 31 Cloudflare
  sites, and it still consistently passes what blocks Patchright.
- **Camoufox** still posts 0% headless detection, because it patches at the Firefox C++ level
  rather than in JS. Still expensive: ~42.5s per bypass and 200MB+ RAM per instance.
- **Patchright** is still positioned as the practical Node upgrade, and still loses to nodriver
  on Cloudflare Enterprise.
- On a **medium-security** target, nodriver alone passes; Patchright, CloakBrowser, Camoufox and
  curl_cffi all hit the interstitial.

Nothing here changes the original decision. And the cost lands badly on **this** machine: 14 cores,
30GB, no GPU, already spending ~50s per scan on the vision model. Camoufox at 200MB+ and ~42.5s per
bypass, or a Python rewrite for nodriver with no behavioural simulation, buys a partial improvement
on a path where **operator attach already gives 100%** — a real browser on a residential IP is the
clean client managed Turnstile is designed to let through.

**Decision: unchanged. Do not adopt a patched driver.** Revisit only if attach itself starts failing.

## 2. The better question: what does a gated page leak *without* being solved?

`RESEARCH.md` framed this entirely as "how do we get past the gate". But a gated page is the same
**factless scan** as a dead one — the class this toolkit already has a doctrine for — and we
currently extract *nothing* from it beyond "there is a gate". Three cheap sources, ranked:

### (a) The gate's own sitekey — operator attribution, not evasion  [cheap, shipped]

A kit-embedded Turnstile/hCaptcha/reCAPTCHA widget carries a **sitekey**: `data-sitekey` in the
markup, or `?k=` / `render=` in the provider request. A sitekey is registered to an *account*, and
a kit reuses it across campaigns — so it is the same kind of evidence as the SendGrid tracking blob
and the affiliate tag already in `campaign_key`: the last thing to change when domains rotate.

We were already fetching the page and throwing this away. Extracting it costs nothing extra and it
is the one identifier a gate **must** expose to function.

Note the ceiling: Cloudflare's own managed challenge (`cdn-cgi/challenge-platform`) is CF-hosted and
exposes no customer sitekey. This only reads *kit-deployed* widgets — which is the case the Joe
Security BitM kit actually used.

**Grouping by sitekey in the ledger is NOT cheap** and is deliberately not done here: `--campaign`
recomputes `campaign_key` from the stored URL, so a *page*-derived key needs a new ledger column and
a migration. Display + LLM context first; earn the column later if sitekeys actually repeat.

### (b) Web archive on a gated page  [cheap, shipped]

The Wayback lookup already exists and already handles exactly this problem — it is just gated on
`NO_DNS || PAGE_DEAD`. A gated page is factless for the same reason, and the archive may hold a
capture from before the gate went up, or from a crawler that passed it. Relaxing the trigger reuses
shipped, cached, informational-only code.

It also does not carry the privacy cost of (c): the CDX query sends `url=<host>/*` — the **hostname
only**, no path and no query — so a victim's email address or reset token never leaves the box. That
difference is the whole reason (b) ships as a default and (c) does not.

### (c) urlscan.io on a gated page  [cheap, NOT shipped — needs a human decision]

The highest-value source and the one we should not enable unilaterally. urlscan **search** is a
public keyless API over scans other people already ran, from infrastructure unlike ours — so someone
else may have rendered the page we were denied.

But `-t` is opt-in *by design*: it sends the URL to a third party. Auto-enabling it on gated pages
would leak the URL — often carrying a victim's email address or a reset token — to urlscan without
the operator asking. That is a privacy call for the analyst, not a default worth assuming.

**Recommended as an explicit flag or an interactive prompt, not a silent default.**

## Verdict

Stop trying to pass the gate. Harvest what the gate leaks and what other people already saw.
(a) and (b) are shipped. (c) awaits a decision on the privacy tradeoff.

Sources: [ianlpaterson.com benchmark](https://ianlpaterson.com/blog/anti-detect-browser-benchmark-patchright-nodriver-curl-cffi/),
[scrapewise.ai Playwright stealth 2026](https://scrapewise.ai/blogs/playwright-stealth-2026),
[scrapewise.ai bypass Cloudflare/Akamai/PerimeterX 2026](https://scrapewise.ai/blogs/bypass-cloudflare-akamai-perimeterx-web-scraping-2026)
