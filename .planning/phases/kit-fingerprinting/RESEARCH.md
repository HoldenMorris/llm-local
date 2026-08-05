# Research: what the ten most-used phishing kits teach a URL scanner

**Question:** we keep chasing individual URLs. Attackers do not write individual URLs, they buy
kits. What can we take from the kits themselves, and what can a URL/page scanner never see?

Sources are listed at the bottom. Ranking is by observed sample volume (ANY.RUN uploads, week of
2026-07-20), not by damage, so read it as "what you will actually meet".

## The field, mid-2026

| Kit | Volume | Type | What it targets |
|-----|--------|------|-----------------|
| Sneaky2FA | 886 | AiTM reverse proxy, browser-in-the-browser | M365 enterprise |
| EvilTokens | 684 | OAuth **device-code** phishing | M365, 340+ orgs in one March 2026 campaign |
| Evilginx2 / EvilProxy | 660 | AiTM reverse proxy (open source, resold $150-400/mo) | Fortune 500, SaaS |
| Kali365 | 503 | Device-code token theft ($250/mo) | M365 SMB + enterprise |
| MassBass | 90 | Templated cloning | cross-sector |
| Greatness | 88 | AiTM proxy, API-driven | manufacturing, healthcare, tech (incl. ZA) |
| Kratos | 76 | Credential harvester (200+ servers seized July 2026) | BEC / financial fraud |
| Tycoon2FA | 46 | AiTM reverse proxy (Storm-1747) | defence, manufacturing, insurance |
| Cephas | 27 | Obfuscated anti-bot AiTM | M365 |
| 1Phish | — | Credential + MFA + recovery-code harvester, 4 versions | 1Password vaults |

Tycoon2FA's low sample count is a takedown artefact, not a decline: Microsoft and Europol seized
300+ domains in March 2026, and it was back at #1 on the trend tracker by late April.

## Five things worth stealing

### 1. Build artefacts beat brand imagery

We look for the brand. The kits leak their **build**, and build strings do not rotate with the
domain:

- **Kratos** — every login page loads `barr.svg` and `lg.svg`, and posts to `next.php` or
  `save.php`. Those two facts alone give ~90% recall on the family.
- **1Phish** — carries `knox-reset`, `knox-provider_ltr__kddqqu0`, `reset_base__1e6d9s10`
  (scraped straight from 1Password's design system) plus
  `<input type="hidden" id="form-step" name="step" value="1">` in V1-V3, and accepts recovery
  codes prefixed `1PRK`.
- **Tycoon2FA** — POSTs the fields `pagelink`, `bltdip`, `bltdref`, `bltdua`, `bltddata`, and
  opens `/web6socket/socket.io/?type=User&appnum=1`.

`page-fetch.sh` already walks the DOM and does not report **form action paths, asset basenames or
hidden input names**. Those three lists, plus a small signature table, name the kit.

### 2. The anti-analysis code is a signature, and it is aimed at us

Our scraper is headless Chrome, on Linux, from a datacentre IP. Every check below is written
against exactly that:

- automation-artefact enumeration: `webdriver`, `__nightmare`, `_selenium`, `callPhantom`,
  `_Selenium_IDE_Recorder`, `__firefoxDriver`, `phantom`, `__stopAllTimers`. Datadog found the
  **same list in the same order** across every V2+ sample of 1Phish — a high-fidelity signature.
- DevTools traps: F12 / Ctrl-Shift-I/J/C blocked, `debugger` re-inserted on a 100ms `setInterval`.
- the script deleting itself from the DOM after it runs.
- `api.ipapi.is` lookups to reject Leaseweb / DigitalOcean / Linode / AWS / OVH / Hetzner ranges.
- blanking the page outright on Linux desktops.

Two consequences. The checks are **greppable in the deobfuscated JS** and legitimate sites do not
enumerate eight automation globals in a fixed order. And they explain our own results: a blank
page or a bot gate is usually the kit refusing us, not a broken site.

### 3. A kit fingerprint is the campaign key that cannot be rotated

Academic work clusters phishing pages by **JavaScript capability vectors** and reports 97% kit
detection across 548 families on 4,562 URLs. UI interactivity appears in 90% of clusters and basic
fingerprinting in 80%, so those are background; the discriminating power is in the credential-theft
and obfuscation patterns.

We already extract capabilities in `js-signals.sh` for the verdict. Emitting them as a **sorted
vector plus a hash** turns them into a grouping key that survives domain rotation — the thing
`campaign_key` cannot do once the operator changes the query parameter. This is the same problem we
solved for `?s1=upg12` and `state=<alnum>-<digits>`, one layer deeper and far harder to evade,
because changing it means changing the kit.

### 4. Invisible characters defeat naive matching

**Cephas** pads its source with random invisible Unicode; **Sneaky2FA** breaks UI text with
invisible tags and ships interface elements as base64 images rather than text. Both exist
specifically to break the string matching that we and every YARA rule do.

Stripping the zero-width set (U+200B-200D, U+FEFF, U+2060) and normalising before *any* text match
costs one `tr` and removes the entire evasion class. We do no normalisation today.

### 5. Infrastructure clusters even when domains do not

1Phish: 10 of 11 domains behind Cloudflare, registered in tight registrar batches — NICENIC first,
then Name SRS AB, PDR, RealTime Register. Tycoon2FA pulls jQuery, Turnstile, reCAPTCHA and
socket.io from legitimate CDNs so its own origin serves almost nothing.

We already do RDAP for domain age and throw the rest away. **Registrar is in that same response**
and is a cheap grouping key for bulk-registered kit domains.

## What a URL scanner cannot see, and we should stop pretending otherwise

- **Reverse-proxy AiTM** (Evilginx2, EvilProxy, Tycoon2FA, Greatness) serves the *real* identity
  provider's page, proxied. There is no brand anomaly, no cloned asset, no DOM tell — the page is
  genuine. What remains is transport (a login page opening a Socket.IO relay to its own origin,
  which no real IdP does) and infrastructure.
- **Device-code phishing** (EvilTokens, Kali365 — together 1,187 samples, the largest bloc here)
  has **no phishing page at all**. The victim authenticates on a genuine `microsoft.com` URL and
  approves a code the attacker generated. Our open-redirect work is the nearest we get; the rest
  needs email or identity telemetry we do not have.
- **Browser-in-the-browser** (Sneaky2FA) draws a fake browser chrome inside the page. The address
  bar the victim checks is a `<div>`. A screenshot-reading VLM can catch this; the DOM cannot.

That is roughly half the field by volume. Worth saying out loud in the README rather than
discovering per-URL.

## Ranked build list

1. **Strip invisible Unicode before every text match** (`page-fetch.sh`, `js-signals.sh`). One
   `tr`, kills the Cephas/Sneaky2FA evasion class outright.
2. **Automation-probe detection** in deobfuscated JS: the eight-name list, `debugger` loops,
   `api.ipapi.is`. One grep, near-zero false positives, and it fires on the kits that are
   *currently refusing us*.
3. **Kit artefact extraction**: form action paths, asset basenames, hidden input names, WebSocket
   endpoints out of `page-fetch.sh`, plus a signature table (`next.php`/`save.php`/`barr.svg`,
   `knox-*`/`#form-step`, `bltdip`/`web6socket`).
4. **JS capability vector + hash** as a rotation-proof kit fingerprint, wired into the existing
   rollup as a fourth key beside host / apex / campaign.
5. **Registrar from the RDAP response** we already fetch, as a grouping key.

1 and 2 are hours and pay immediately. 3 needs a signature table we must keep current. 4 is the
one with real upside and should be validated against the ledger corpus before it scores anything.

## Sources

- [Top 10 Phishing Kits Used by Hackers (July 20-26, 2026)](https://cybersecuritynews.com/top-10-phishing-kits-used-by-hackers/)
- [Datadog Security Labs — a technical deep dive into the 1Phish kit](https://securitylabs.datadoghq.com/articles/hook-line-vault-a-deep-dive-into-1phish/)
- [Sekoia — Tycoon 2FA in-depth analysis](https://www.sekoia.com/blog/tycoon-2fa-an-in-depth-analysis-of-the-latest-version-of-the-aitm-phishing-kit)
- [Sekoia — global analysis of AiTM phishing threats](https://blog.sekoia.io/global-analysis-of-adversary-in-the-middle-phishing-threats/)
- [Elastic Security Labs — Tycoon 2FA AiTM detection engineering](https://www.elastic.co/security-labs/tycoon-2fa-aitm-detection-engineering)
- [Microsoft Security — inside Tycoon2FA](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)
- [Characterizing Phishing Pages by JavaScript Capabilities (arXiv 2509.13186)](https://arxiv.org/pdf/2509.13186)
- [Push Security — analyzing the latest Sneaky2FA BITB page](https://pushsecurity.com/blog/analyzing-the-latest-sneaky2fa-phishing-page)
- [Push Security — device code phishing in 2026](https://pushsecurity.com/blog/device-code-phishing)
