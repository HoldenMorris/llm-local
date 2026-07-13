# Gotcha: the vision (minicpm-v q4) BRAND prompt is load-bearing

The `openbmb/minicpm-v4.6:q4_K_M` vision prompt in `url-analyze.sh` (the `VP=`
"BRAND:/PASSWORD:" block) is **load-bearing** — do not casually reword it.

Even at `temperature:0` (deterministic per prompt), small wording changes flip the
brand verdict on the *same* screenshot. On a tradekorea-cloned phish
(`universoemprendimientossa.com/ppp/index.html`), the committed wording
("...If a well-known brand's page is served from an unrelated domain, say so.")
reliably yields *"imitates tradekorea, which does not match the domain"*. Three
reworded variants each degraded it:

- a 3-line structured `BRAND_MATCH:` token → generic *"typical web form, BRAND_MATCH: yes"*
- "say the design does NOT match the domain" → flat-wrong *"imitates tradekorea and matches its domain"*

**Why:** q4-quantized small VLM, brittle instruction-following.

**How to apply:** the visual-impersonation red flag keys off a free-text
`does not match | unrelated domain` fallback (plus an optional `BRAND_MATCH: no`
token) precisely because the token isn't reliably emitted — keep the fallback. If
you change the BRAND prompt, re-scan a known impersonation page AND a known-good
login (FlatShare staging) before committing.

Shipped in commit 0ec869e (visual-impersonation floor). Related:
`.planning/phases/anti-bot-rendering`.
