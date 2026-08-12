# CLAUDE.md

## Ponytail Mode (Lazy Senior Dev)

Before you write code, stop at the first rung that holds:

1. Does this need to exist at all? (YAGNI)
2. Does it already exist in this codebase? Reuse it.
3. Does the standard library already do this? Use it.
4. Does a native platform feature cover it? Use it.
5. Does an already-installed dependency solve it? Use it.
6. Can this be one line? Make it one line.
7. Only then: write the minimum code that works.

Rules:
- No abstraction that nobody requested
- No new dependency if you can avoid it
- No boilerplate that nobody asked for
- Deletion over addition. Boring over clever. Fewest files possible.
- Shortest working diff wins
- Mark intentional simplifications with a `ponytail:` comment

Not lazy about: input validation, error handling, security, accessibility.

## Project Status

**Current focus:** URL/Page phishing detection toolkit

### Detection changes drive forward. Improve BOTH paths, never flip-flop

When a double-check of a URL exposes a miss, the fix must ratchet **both** paths forward.
The two paths are the deterministic heuristic core (`verdict.sh` / `page-fetch.sh`) and the
LLM. Never trade one against the other. A miss usually has two co-causes. First, the flaky
small LLM returns empty output, or contradicts a known fact like `HAS_LOGIN`. Second, a
heuristic floor scored 0 and let the LLM downgrade the verdict.

A patch to only the LLM (prompt tweaks), or to only the heuristic, moves the false result
around. The next scan then flips the other way. So every detection fix does three things:

1. **Make the deterministic floor catch it**, so the verdict holds whatever the LLM says.
   `classify_verdict` escalates over the LLM but never downgrades. Lean on that.
2. **Harden the LLM path too**: retry on empty, starve miscount fuel, feed it deterministic facts.
3. **Pin it** with a `test-verdict.sh` golden case. Confirm no regression on a known-good page.

Guard against false positives while you drive forward. Cap each new floor at the severity the
signal earns. A login page plus an off-CDN third-party host is SUSPICIOUS, not DANGEROUS.
Reuse the upstream filtering, such as the `cdnRe` regex in `page-fetch.sh`, so legit CDNs and
captchas do not trip the floor.

### Recommended models (CPU-only laptop: 14 cores, 30GB RAM, no GPU)

| Role | Model | Notes |
|------|-------|-------|
| Verdict LLM | `qwen2.5:1.5b` | URL benchmark (`14c-30g-cpu`): 100% (5/5), ~18s avg (~4-5s on clean pages), ~2× faster than gemma2:2b. Non-reasoning. `-m auto` picks it. |
| Runner-up | `gemma2:2b` | Also 100% on the URL corpus, but ~2× slower. Best on the email-spam benchmark (`benchmark.sh` plus `prompts/focused.txt`, 96%). |
| Vision | `openbmb/minicpm-v4.6:q4_K_M` | The only small VLM. ~50s per screenshot. Brand clone, missed credential input, and adult imagery (Phase 3.7). |
| Avoid for verdict | `llama3.2:3b`, `minicpm5` (1B), `minicpm4.1` (8B) | `llama3.2:3b` false-positived a real login page. Reasoning models whiff (1B) or take ~2min (8B). |

Ollama runs in the `llm-spam-test` container, which needs version 0.31 or later for the newer
VLM architectures.

### Tools

| Script | Purpose |
|--------|---------|
| `url-analyze.sh` | Full URL analysis (static plus dynamic plus LLM) |
| `url-benchmark.sh` | Compare models (plus the `none` no-model baseline) on a labeled URL corpus |
| `model-scout.sh` | Find small GGUF model contenders on Hugging Face (prints `ollama pull` commands) |
| `machine.sh` | Shared hardware fingerprint (cores/RAM/GPU) so benchmark timings group by machine |
| `page-fetch.sh` | Sandboxed page scraper with phishing signals |
| `js-deobfuscate.sh` | Sandboxed webcrack runner: obfuscated JS in, cleartext out |
| `js-signals.sh` | Extract phishing signals from deobfuscated JS (`source` it, `js_signals`) |
| `benchmark.sh` | Email spam classification benchmark |
| `test-verdict.sh` | Golden tests that pin the deterministic verdict core (`verdict.sh`). Pure: no LLM, no network |
| `feedback-report.sh` | Mine analyst feedback (the "Do you agree?" prompt in `url-analyze.sh`) from `.cache/*/feedback.txt` into an agreement-rate and disagreement report. `-f` prints only the **open** flags, one per line. `-i <url> <note>` records a deep inspection: it appends an `inspected` row with what you found, which closes the flag (`FB_CATEGORY=<category>` records what the page is, in column 6). Rows are append-only and the **latest row wins**, so an inspection supersedes the flag but never erases it, and a later re-flag re-opens the URL. The prompt also takes `i` (inspect now): it writes the flag, then runs headless `claude -p` (read-only tools) over the cached scan artifacts to triage the verdict, and records the `VERDICT:` and `NOTE:` lines it returns as the inspection that closes the flag. No `claude` on PATH, or a failed run, falls back to a note you type. `FB_VERDICT=<SAFE\|SUSPICIOUS\|DANGEROUS>` on `-i` writes that **corrected** verdict into the row, and an **interactive** re-scan then reports it in the banner instead of the freshly computed one, with the machine verdict named underneath. Benchmarks are non-interactive, so they always measure the raw core and an inspection can never hide a regression. `--corpus` exports every **settled and live** URL as a labeled `VERDICT URL` corpus for `url-benchmark.sh`, which is the weekly replay. `--host <host> [exclude-url]` prints the settled judgements for one exact host, which is how a scan reuses what the ledger already knows about it. `--settled <url>` answers "have we already looked at this?" for an **alerting pipeline**: exit **0** = settled SAFE (auto-resolve), **2** = settled bad (auto-confirm), **1** = unknown (a human must look), with one TSV line (verdict, category, scope, matched-url, note) when it knows. Only `inspected` rows answer, and the scope is the exact URL then the host — never the apex, because a wrong auto-resolve is a missed phish rather than a noisy alert. Thirty alerts in twenty minutes for a host inspected three hours earlier is how a real detection gets buried | Run `--self-test` for the self-check |
| `psl.sh` | Public Suffix List helper. `source` it, then `apex_of <host>` (the true registrable domain), `suffix_of <host>` (the public suffix — the tail nobody registers) or `head_of <host>` (the host **minus** that suffix: the only part the registrant chose). Caches the list in `.cache/` and refreshes it every 30 days. Run `./psl.sh` for the self-check |
| `brand-verify.sh` | Ask if the **brand's own site** links to a host. `PROVEN` suppresses a brand smell. `UNPROVEN` escalates nothing. Run `--self-test` for the self-check |
| `tor-up.sh` | Bring up the Tor sidecar (`llm-tor`) for scanner egress: exit country and circuit rotation. `--down` stops it |
| `llm-test.sh` | Single email test |
| `colors.sh` | Shared ANSI colors. `source` it, then use `${RED}..${RESET}` or `cecho` |

### colors.sh (shared)

Any tool can `source "$SCRIPT_DIR/colors.sh"` after it parses args. That gives:
- Vars: `RED GREEN YELLOW BLUE CYAN GREY BOLD DIM RESET`
- Readable helpers: `echo_red "..."`, `echo_green`, `echo_yellow`, `echo_blue`,
  `echo_cyan`, `echo_grey`, `echo_bold`, and `cecho <color> <text>`.

The helpers print color **only** when stdout is a terminal and color stays on. Three things
turn color off: the `-c mono` flag (the tool sets `MONO=1` before it sources the file), the
`NO_COLOR` env var, and a non-terminal stdout (a pipe or a capture). Machine-parsed output
therefore stays plain ASCII. Four tools use `colors.sh`: `url-analyze.sh`, `url-benchmark.sh`,
`benchmark.sh`, and `llm-test.sh`. All four accept `-c mono` as a leading flag.

### URL scan cache

`url-analyze.sh` caches the work for each URL in `.cache/<url-hash>/`: page content
(`page.json`), screenshot (`page.jpg`), the followed credential page and its screenshot
(`page-login.json`, `login.jpg`), the followed interstitial destination and its screenshot
(`page-redirect.json`, `redirect.jpg`), inline scripts
(`scripts/`), deobfuscation signals (`deob-signals.txt`), the vision VLM verdict
(`vision.txt`), the Wayback capture index (`wayback.json`, dead URLs only), and each LLM answer
(`llm-<hash>.txt`, keyed by model and request). A re-scan
therefore reuses the fetch, the ~1min vision call, and the LLM verdict instead of a re-compute.
`-r` forces a full refresh.

### Per-host cache (`.cache/host/<host>:<port>/`)

Domain metadata (`meta.env`: IP, geo, org, domain age, RDAP status and expiry, cert age and
issuer, A records, TTL) is a
fact about the **host**, never about the path or the query, so it caches per host instead of per
URL. A scan of a new path on a known host therefore skips the whole serial round-trip block (dig,
ip-api, RDAP, openssl): ~2.6s to ~0.2s. The facts expire after 7 days, and `-r` refreshes now.

The signals are derived from those facts **outside** the lookup, so a cached run and a fresh run
give the same signal list. They used to diverge: the cached branch re-added only the fast-flux
signal, so a re-scan silently dropped the domain-age, new-cert and low-TTL signals from the LLM's
context, and the same scan read differently depending on whether the cache was warm.

Only `AGE_DAYS` is really apex-scoped, so sibling subdomains re-fetch it. That is one RDAP call,
which does not earn a second cache tier keyed on the apex.

The cache also holds the feedback ledger (`feedback.txt`). Beside the judgement rows it carries
**liveness** rows: a failed fetch appends `gone`, and a later successful fetch appends `alive`.
Liveness is a separate axis from judgement, so a dead URL keeps its `inspected` label and its
place on the `-f` worklist (the cached page and screenshot are still there to read), it only
drops out of the replay corpus. Phishing kits die within days, so without this the weekly replay
would score the scanner on uptime instead of detection.

### Verdict category (what it is, not how bad it is)

Severity answers "how much should this scare me". The **category** answers "what am I looking
at", and the two are independent: a scam storefront and a credential harvester are both
DANGEROUS, a survey and a login page are both SAFE. Every verdict carries one, so the ledger can
be mined by kind and not only by severity. The banner prints it: `VERDICT: DANGEROUS (phishing)`.

The vocabulary is fixed (`VERDICT_CATEGORIES` in `verdict.sh`), because these get mined later and
free text does not group:

`phishing` `email-harvest` `scam` `malware` `adult` `spam` `unsubscribe` `marketing`
`questionnaire` `poll` `rating` `login` `content` `other`

`category_of` (also `verdict.sh`, pure and golden-tested) makes the deterministic guess from
evidence already extracted: a credential form means `phishing`, a mailing-list endpoint means
`email-harvest` when the verdict is bad and `unsubscribe` when it is not, a wallet address or a
VirusTotal hit means `scam`, and the benign shapes fall out of the URL and the page title.
`adult` is the one category with **no** trace in scraped text — the page is nothing but pictures,
and this class titles itself "No swiping. No ghosting." — so it comes from the VLM's `ADULT: yes`
line (see the vision escalation below) and from nowhere else. A credential form still outranks it:
an adult-baited harvester is `phishing` first. Two rules keep the rest honest: `malware` has no
reliable signal in what the scraper extracts,
so it is **never** guessed and only ever comes from a person or an inspection; and an UNCLEAR
verdict gets **no** category, because a category is a claim and a scan that could not judge the
page has nothing to claim from. The guess is not fed back to the LLM — it is derived from signals
the LLM already has, so it would only give a small model more to miscount.

An analyst answer or a deep inspection overrides the guess and is stored in the ledger (column 6),
so a re-scan reports the recorded category the same way it reports the recorded verdict.

### Disagreement records the correction

Answering `n` at the verdict prompt now asks what the verdict **should** be and what the page
actually **is**, then an optional why. A disagreement without the correction is a complaint the
toolkit cannot act on. Two rows are appended: the `disagree` row (which keeps the accuracy stat
honest — the scan *was* wrong) and an `inspected` row carrying the corrected verdict and category,
which is what makes the next scan report it and what puts the URL into the replay corpus with a
true label.

### Weekly replay

The settled ledger rows are labeled data, so the weekly accuracy check is the existing benchmark:

```bash
./feedback-report.sh --corpus > url-corpus-live.txt   # settled + live urls only
CORPUS=url-corpus-live.txt ./url-benchmark.sh         # accuracy-vs-time, writes results/url_benchmark.csv
```

`url-corpus-live.txt` is **gitignored**: live phishing URLs embed recipient email addresses and
reset tokens, so the export never gets committed or synced.

Flags:
- `-m <model>` picks the verdict LLM. `-m auto` picks the best model per
  `results/url_benchmark.csv` and falls back to `qwen2.5:1.5b`. `-m none` matches `-H`.
  **`-m claude-<id>`** (or bare `-m claude`, which aliases `claude-opus-4-8`) runs the verdict
  LLM through the **Anthropic API** instead of local Ollama. That path is opt-in and needs
  `ANTHROPIC_API_KEY` in `.env`. `VISION_MODEL=claude-<id>` does the same for the screenshot reader.
- `-s` skips the page fetch.
- `-V` turns off vision.
- `-H` is heuristic-only: no LLM, verdict straight from the decision table in `verdict.sh`.
- `-r` ignores the cache.
- `-c mono` turns off color.
- `-D` skips JS deobfuscation.
- `-t` adds third-party reputation (VirusTotal plus urlscan.io). Off by default, opt-in, not in
  the benchmarks. See below.
- `-p tor` routes scanner egress through Tor. `-g <cc>` sets the exit country. See below.

**A bare run** (`./url-analyze.sh <url>` with no flags at all) is the interactive analyst path, and
it is the only one that asks about the cache:

- **Already cached?** It prints when the cached scan was taken and offers `[R/u]` — re-use it
  (default, free, and it is what the recorded verdict was made from) or update, which re-fetches
  everything exactly like `-r`.
- **Fresh scan?** It asks at the very end whether to keep the artifacts. A scan of a live phish
  leaves the page, the screenshot, its scripts and often the victim's email address on disk.
  Declining wipes them; `feedback.txt` always survives, because the judgement is the one part a
  re-scan cannot regenerate. Asked last, because the deep inspection reads those very artifacts.

Any flag at all turns both prompts off, so the benchmarks (which always pass flags, and are never
interactive) can never be stopped by one.

Every run ends with a `scanned: <url>` line. A scan scrolls several screens, so the URL is gone by
the time you reach the bottom, and the next thing you do is paste it into a ticket or re-run it
with another flag.

On a bot gate the tool offers operator attach (see below). With no URL argument it prompts for
one. The interactive model menu lists `0: none (pure heuristic)` plus the installed models, and
defaults to the best one (press Enter). The LLM analysis line prints which model ran and how
long it took.

### Web archive history (automatic, dead URLs only)

A dead URL is a factless scan, and a factless scan has nothing to judge — the phantom-SAFE class
again. When there is no live page (no DNS A record, or the fetch errored) `url-analyze.sh` queries
the **Wayback CDX index** (`web.archive.org/cdx/search/cdx`, keyless, no account) for every capture
of the host. That answers what the failed fetch could not: how long did this host exist, and did
any crawler ever see it. A kit that was up for six days and never captured looks nothing like a
four-year-old business whose server happens to be down today. The output names the capture count,
the first and last dates, the span, and a direct link to **read the archived page** — which is
often the only way left to see what the kit actually asked for.

It is **gated on the page being dead**, so an ordinary scan and every benchmark run (which scan
live URLs) pay nothing for it. Caches per URL in `.cache/<hash>/wayback.json` and respects `-r`.

It is deliberately **informational only** and never touches the safety floor: most of the web is
uncrawled, so an archive gap is not evidence of phishing. A rate-limited or 503 response (both are
common — archive.org returns an HTML error body, not JSON) is discarded rather than cached, and
reports "lookup failed — unknown", never "never archived". Claiming a clean answer from a failed
lookup is precisely the bug this section exists to fix.

Google's cache is **not** an option: the `cache:` operator and the cached-page links were retired
in September 2024. Bing's is effectively gone too. Wayback is the only general archive left.

### Third-party reputation (`-t`, opt-in)

`-t` adds external verification from **VirusTotal** and **urlscan.io**. It stays off by default,
and the benchmarks never trigger it because they do not pass `-t`. Results cache per URL in
`.cache/<hash>/{virustotal,urlscan}.json` and respect `-r`. The tool does not cache a miss or an
error. Keys live in a gitignored `.env` (copy `.env.sample`). `VT_API_KEY` is mandatory and free
([docs](https://docs.virustotal.com/reference/overview)). `URLSCAN_API_KEY` is optional, because
urlscan search is a public API and the key only raises rate limits.

VirusTotal reads `last_analysis_stats` by base64url URL id, plus `first_submission_date`,
`last_submission_date` and `times_submitted` off the same response. First-to-last submission is the
window in which *anybody* saw this URL, which is the nearest thing to a lifespan for a page that is
already dead by the time we look at it: `linktoyourstore.com` spans 1689 days over 15 submissions,
a freshly minted kit spans 0. It prints on the VirusTotal line and costs no extra call. urlscan
**searches existing public
scans only** (no submission) and reads **both** `verdicts.overall` and `verdicts.engines` from the
latest scan. The two are separate judgements: `engines` carries urlscan's own ML classifier and it
often calls a page malicious while `overall` stays at 0, so reading only `overall` threw away a
score-96 hit on `healthlynotes.com`. Either verdict alone is **one** red flag, never two, and the
flag text names which one fired. A
confirmed-malicious hit from either source feeds the deterministic safety floor as a red flag
(appended to `SMELLS`), and both summaries go into the LLM context. A VirusTotal consensus of
**5 or more vendors** floors the verdict to DANGEROUS on its own, with no login form needed:
scam storefronts and droppers take money rather than passwords. **Rate limits:** the
VirusTotal free tier allows 4 requests per minute and 500 per day. The per-URL cache means a
re-scan costs zero API calls.

### Operator attach mode (bot gates: Turnstile / hCaptcha / reCAPTCHA)

Our headless container is the weakest tier against bot gates. See
`.planning/phases/anti-bot-rendering`. `page-fetch.sh` detects the major providers by the
scripts they load: **Cloudflare Turnstile**, **hCaptcha**, and **reCAPTCHA**. It then pushes a
smell that ends `... - real page gated from the scraper`. This fires whether the challenge is
invisible or an interactive click.

On any such smell, `url-analyze.sh` offers **operator attach**. It rings a terminal **bell** and
always asks first `[Y/n]`. It then opens a visible **Brave** (`/snap/bin/brave`) at the gated
URL, with a throwaway profile and `--remote-debugging-port=9222`. You have a residential IP and
a real browser, so you clear the gate and land on the real page. Press Enter, and the tool
re-scans by a CDP **attach** to your cleared tab. `page-fetch.sh` runs with `PAGE_ATTACH=<url>`,
calls `puppeteer.connect` over Docker `--network host`, and reads the live uncloaked DOM. That
path does no launch, no navigation, and no stealth.

The uncloaked `page.json` and screenshot overwrite the cache, so a re-scan reuses them and the
verdict and vision run on the real page. The tool **opens and closes** Brave, and kills it with
`pkill -f <profile>` on exit, INT, and TERM, because snap Brave daemonizes out of the process
group of the launcher. Attach is interactive-only (`[ -t 0 ]`), so it never fires in the
benchmarks. The tool **always prompts you before a window opens**. If Brave is missing, or you
decline attach, or attach fails, the tool falls back to the plain "open in your browser" offer.

Signal: `Operator attach: analyzed the uncloaked page past the <gate> gate`. Automated bypass
(patched drivers, xvfb, proxies, solvers) stays on hold, because research showed it unreliable
and high-maintenance.

### Scanner egress routing (`-p tor`, Wave 1)

Some kits only fire for in-zone (target-country) IPs and cloak to a benign page otherwise.
Others blacklist datacenter and scanner IPs. `-p tor` routes the egress of the **headless
scanner** through a free **Tor sidecar**, for geo-targeting, blacklist-dodging, and attribution
hygiene:

```bash
./url-analyze.sh -p tor -g us <url>   # scan as if from a US IP
./tor-up.sh -g gb                     # (called automatically) set exit country live
./tor-up.sh --rotate                  # fresh circuit / new exit IP
./tor-up.sh --down                    # stop the sidecar
```

`tor-up.sh` auto-builds a tiny `alpine+tor` image (`local-llm-tor`) and runs `llm-tor` on the
`llm-net` docker network. SOCKS listens on 9050, and the control port 9051 stays in-container.
`page-fetch.sh -p tor [-g cc]` joins `llm-net` and launches Chrome with
`--proxy-server=socks5://llm-tor:9050`. SOCKS5 gives remote DNS, so there is no leak. The
control port sets the exit country live (`SETCONF ExitNodes`) and rotates the circuit
(`NEWNYM`). The tool prints the **actual exit IP and geo the page saw**
(`- egress: <ip> (<cc>, <org>)`).

**Honest ceiling (by design, see `.planning/phases/ip-routing`):** Tor exits carry datacenter
reputation, and Cloudflare and others widely block or challenge them. Many kits block Tor
outright. So `-p tor` helps against naive geo and blacklist gates and helps opsec, but it is
useless against Tor-aware or residential-only kits. No free tool gives residential reputation.
For that, **operator attach** is the reliable path, because it uses your real residential IP and
your geo.

**Security:** the tool supports only Tor egress or your own VPN, never public proxy lists, which
carry a MITM risk on live malware. The default is direct egress (no `-p`), so the benchmarks
stay the same.

### url-benchmark.sh

`url-benchmark.sh` runs `url-corpus.txt` through each engine. The corpus holds labeled
`VERDICT URL` lines. The run prints an accuracy-vs-time matrix and writes
`results/url_benchmark.csv`. The `none` engine is the no-model if-then decision table baseline,
where empty and UNCLEAR normalize to a SAFE guess. Each row carries a `machine` fingerprint from
`machine.sh`, such as `14c-30g-cpu`. Timings only compare within one machine, and `-m auto` and
`best_model` only pick from the rows of **this** machine.

```bash
./url-benchmark.sh                      # none + qwen2.5:1.5b (default)
./url-benchmark.sh gemma2:2b minicpm4.1:8b
CORPUS=my-urls.txt ./url-benchmark.sh
```

### model-scout.sh: find new contenders

`model-scout.sh` queries the Hugging Face API for small GGUF text-generation models. It prints
an `ollama pull hf.co/<repo>:Q4_K_M` line for each one, so you can throw new models into the
ring. It filters by parameter size from the repo name. A MoE name like `35B-A3B` counts as 35B,
not 3B.

```bash
./model-scout.sh                # top small instruct GGUF models by downloads
./model-scout.sh qwen 4         # search "qwen", <= 4B params
# then: ollama pull hf.co/...   &&   ./url-benchmark.sh <model>
```

## url-analyze.sh: 3-Phase Analysis

### Phase 1: Static URL Analysis (no network)

| Detection | Description |
|-----------|-------------|
| High-risk TLD | `.cfd`, `.xyz`, `.top`, `.lol`, `.sbs`, `.icu`, `.buzz`, `.monster`, and more |
| Typosquatting | Brand name in the subdomain but not the apex domain. Matched against `head_of` only — the public suffix is the **provider's** name, so matching the whole hostname read the ordinary S3 bucket `wfse.s3.us-east-1.amazonaws.com` as "contains 'amazon'". A kit still flags, because `paypal-login.s3.amazonaws.com` puts its brand left of the suffix |
| Excessive subdomains | More than 3 levels **below the public suffix** (this hides the real domain). Same reason: the depth that hides a domain is the depth the registrant added, and an AWS regional endpoint is structurally deep before anyone registers anything. Equivalent to the old "more than 4 labels" on a single-label suffix, and finally right for `co.uk` and `s3.<region>.amazonaws.com` alike |
| Homograph attack | Non-ASCII characters in the domain |
| Random domain | High-entropy alphanumeric strings, in `head_of` only. Stripping just the last label left the provider's labels glued in, and `s3` + `us-east-1` supplied both digits `is_random_label` asks for — `wfses3useast1amazonaws`. `xk51.efast` still scores |
| Open-redirect abuse | A redirect-style query parameter (`redirect_uri`, `next`, `url`, `continue`, and more) that carries a whole URL to another site. The strongest way to hide a phish is to **not host it**: `accounts.google.com/o/oauth2/v2/auth?redirect_uri=...` really is Google — aged, Google-owned, valid cert — so every domain check passes and the page you fetch is a genuine login form. An off-site target alone is **not** a signal, because that is what OAuth is for. What scores is **hiding** it: gratuitous percent-encoding of unreserved characters (`h%74tps` is a plain `t`, which RFC 3986 forbids and no normal tool emits), and a machine-generated hostname or high-risk TLD at the far end. One red flag each, and they stack. The parameter is decoded (up to 3 rounds, kits double-encode) and the real destination is printed in clear |
| Email link-redirection service | Detected three ways, in order: the host itself (`mjt.lu`), the **CNAME behind it**, or the URL shape. Every ESP sells "branded links": the customer publishes `url8083.calvis.com -> sendgrid.net`, so the tracking URL wears an aged reputable domain and the host-name list never matches. Five consecutive scans of one campaign walked past the list for exactly that reason. One `dig CNAME` covers every service in the list at once. The shape rule (`/ls/click?upn=`, SendGrid's own click path) is the DNS-free backstop, because these links are usually dead by the time we look and a dead name has no CNAME to read |
| Tunneling service | Host on a free tunnel or port-forwarder (`ngrok`, `trycloudflare`, `portmap.io`, `serveo`, `loca.lt`, and more). The operator hides behind a tunnel. This is a deterministic red flag, so the URL reads SUSPICIOUS even when the tunnel is down and the fetch fails. |

### Phase 2: Domain Info Lookup

| Detection | Source |
|-----------|--------|
| IP geolocation | ip-api.com (country, org, ISP) |
| Domain age | RDAP (flags less than 30 days as high risk). The lookup uses the **registrable domain** from `psl.sh`, not the last two labels. `smithpower.autoit.za.com` gave `za.com` before, so the age read 28 years (the CentralNic registry) and every `*.za.com` phish inherited an "aged domain" pass. A host that sits directly on a shared namespace has no RDAP record, so the age reads unknown, which is the honest answer. Verisign is authoritative for `.com`/`.net`/`.org`; **every other TLD** goes through the `rdap.org` bootstrap. Two bugs used to make that whole branch dead: the lookup only ran for com/net/org at all, and `rdap.org` **302s** to the authoritative registry while the curl had no `-L`, so it returned an empty body. Every `.space`, `.co.ke`, `.icu` domain therefore read "age unknown", and `count_red_flags` does not count an unknown age — a structural aged-domain pass for exactly the TLDs kits prefer. A one-day-old `.space` host now scores the young-domain flag |
| Registry status / expiry | The `status[]` and `expiration` event on the **same** RDAP response. A failed fetch cannot tell a takedown from an unpaid invoice from a kit that was never really there; RDAP can. `client hold` / `server hold` means a registrar or registry pulled the delegation, which is how an abuse report ends — but it is also how an unpaid renewal on a legitimate domain ends, and RDAP cannot separate them, so it is **capped at SUSPICIOUS** in `verdict.sh` and excluded from `count_red_flags`. `redemption period` / `pending delete` / a past expiry date means the registration simply lapsed: display and LLM context only, because a lapse is not evidence of anything bad |
| SSL cert age | openssl (flags less than 7 days as suspicious) |
| SSL issuer | openssl |
| Fast-flux DNS | More than 5 A records, or TTL under 300s — **unless** the host's public suffix is shared cloud/CDN plumbing (`is_tenant_infra` in `verdict.sh`, a tail match over `TENANT_SUFFIXES`/`VANITY_SUFFIXES`, because the PSL spells AWS out per region). Fast-flux is a claim about the **registrant's** DNS; on an S3 endpoint or a CloudFront distribution the records are the provider's load balancer. Judged on the suffix, not the apex, so `efast.space` behind Cloudflare is still the registrant's own zone and still flags. `co.uk` matches nothing here — the point of asking the list rather than counting labels |
| Same campaign tag, any domain | The feedback ledger (`feedback-report.sh --campaign`). The last thing that survives a domain rotation is the affiliate / sub-id tag in the link: ten throwaway domains carrying `?s1=upg12` are one operator, which neither the host nor the apex rollup can see. `campaign_key` (`verdict.sh`) accepts a query pair only when the **value is an opaque short token** — letters and digits, nothing else, 3-16 chars. When no value matches, it falls back to a **shape** key for kits that mint a fresh token per victim (`state=<20-32 alnum>-<20+ digits>` linked both hops of the Google OAuth chain, with different values). A shape key must identify one **generator**, never a carrier: "any SendGrid `/ls/click` link" is deliberately not one, because it would group every legitimate mailshot on the platform with the phish. The **tracking blob** inside one is: SendGrid wraps the destination as `upn=u001.<per-recipient payload>_<tracking blob>`, and the blob's first 32 characters are constant across every link one operator sends (seven ledger links on seven unrelated customer domains open the same run and diverge at char 43) while unrelated legitimate senders open differently. That is what makes a **dead** tracker link worth scanning: the page is a 404 by the time we look, so the tag is the only thing left that says who sent it. That one rule does the filtering: `?p=unsubscribe`, `?lang=engb`, `?page=1234` and long per-recipient tokens all fail it. `utm_*` and the obvious per-recipient keys are dropped outright, because `utm_campaign` really is shared by unrelated legitimate sites in one mailshot. Same two shapes as the domain rollup (inspected DANGEROUS = red flag, inspected SUSPICIOUS = capped floor), and it only runs when the domain itself is unknown to us, so one piece of evidence never counts twice |
| Prior judgements on this domain | The feedback ledger (`feedback-report.sh --host` / `--apex`). Kits rotate paths, query strings **and subdomains** behind one registered domain, so a harvester settled at `lxu438.getnew.space` is evidence about `tyu620.getnew.space` the next day. Only **`inspected`** rows count: `agree` is one keypress (Enter is the default answer), so it would let a domain ratchet itself up on this tool's own output. An inspected **DANGEROUS** sibling is an ordinary red flag (SUSPICIOUS alone, DANGEROUS with a credential form). An inspected **SUSPICIOUS** sibling is real human evidence but weaker, so it is excluded from the red-flag count and floors at SUSPICIOUS only — it says the domain hosted something bad, not that this page is harvesting. Scope widens from the host to the **registrable domain** only when that domain means one owner: `psl.sh` already returns the tenant host for a public suffix (`github.io`, `pages.dev`, `azurewebsites.net`), and `TENANT_SUFFIXES` in `verdict.sh` covers what the PSL misses (`awsapprunner.com` is not in the list, and one operator's tenant must never taint another's) |

### Phase 3: Page Fetch (via page-fetch.sh)

| Detection | Description |
|-----------|-------------|
| Login form | Password field present |
| Off-domain form | Login submits to a different domain |
| IP fingerprinting | api.ipify.org, ipinfo.io, and similar |
| Compromised WordPress | Redirect to `/wp-include/` or `/wp-content/` with random paths |
| Silent refresh redirect | HTTP `Refresh:` response header, or in-body `<meta refresh>`. Not just a 3xx `Location` |
| Random URL path | High-entropy paths like `/kz51odwn/` |
| Urgency language | "suspended", "verify now", "24 hours", and similar |
| Hidden form fields | More than 3 hidden inputs |
| Sensitive field names | ssn, credit_card, cvv, routing, and similar |
| Known phishing kit | Attackers deploy **kits**, and a kit leaks its build. Brand imagery changes per campaign; the scraped design-system class, the hard-coded asset filename and the invented POST field do not, because changing them means rebuilding the kit. Matched against the page markup (classes, hidden input names, asset filenames, inline scripts) **after** invisible-character stripping. Table in `page-fetch.sh` (`kitSignatures`): 1Phish, Tycoon2FA, Kratos. Every entry needs a token distinctive on its own — a build hash, an invented field name, a pair of filenames — never a generic path like `login.php`, and `not` exempts the brand that legitimately owns the artifact (1Password's real site carries its own design-system classes). One red flag: SUSPICIOUS alone, DANGEROUS with a credential form. Provenance for each token is in `.planning/phases/kit-fingerprinting/RESEARCH.md` |
| Invisible-character padding | Zero-width characters (U+200B-200D, U+2060-2064, U+FEFF, U+00AD) sprinkled through the page. They exist for one reason: to break the string matching that every scanner does — `Micro<zwsp>soft` renders identically and matches nothing. **Stripped before every text comparison**, so brand and urgency matching see through it, and more than 20 of them is itself a smell. Cephas pads its source this way by design and Sneaky2FA breaks up UI labels with it |
| Clipboard hijacking | `oncopy`, clipboard API usage |
| Right-click disabled | `oncontextmenu` blocked |
| Crypto wallet addresses | BTC, ETH, TRX patterns |
| Brand impersonation | Brand in the page **title or form action** but not the domain (OAuth whitelist). `BRAND_MATCH=body` also matches body text (noisier) |
| Hotlinked brand image | An `<img>` served from a **brand's own domain** while the page is not that brand. A kit cloned from the real login page still points the logo at the victim brand's CDN, so the asset host gives the attribution. No logo database and no image matching. Legit pages also embed brand artwork (payment buttons, dealer logos), so this is context only: `count_red_flags` excludes it, and it floors to SUSPICIOUS **only with a login form**. Skips brands under 5 characters and the ubiquitous embed set (google, facebook, amazon, microsoft, apple, github, and the social networks) |
| Brand-lookalike subdomain | On a **vanity multi-tenant host** the apex confers no identity. So a subdomain that spells out the page `<title>` (8 chars or more) or a known brand, wrapped in extra lure text, is impersonation. Example: `supportimmigrationadviceserviceorg.github.io` = "Immigration Advice Service". This feeds the deterministic floor: SUSPICIOUS, or DANGEROUS with a login form. It catches what the static typosquat check misses, because `github.io` reads as brand-owned (`github` is a brand) and the brand list is fixed. The host list is **`VANITY_SUFFIXES`** in `verdict.sh`, not an inline regex — it used to be one, and it drifted from `TENANT_SUFFIXES` next door: `appspot.com` was a tenant suffix for the ledger rollup and *not* a lookalike host, so a Google App Engine service label spelling out a lure could never trip this. `is_tenant_suffix` is now the **union** of both lists (so a rollup also stops at `blogspot.com`), while the lookalike rule uses `is_vanity_suffix` alone. The split is deliberate: a vanity host hands out **customer-chosen** labels, but an S3 bucket or CloudFront distribution named after its own owner is ordinary, so `amazonaws.com`, `cloudfront.net` and the ESP infra hosts stay out — otherwise `acmecorp-assets.s3.amazonaws.com` titled "Acme Corp" reads as impersonation |
| Suspicious JS | eval(), atob(), document.write(), hex-encoded strings, obfuscator.io `_0x` identifiers, String.fromCharCode |
| External link ratio | Skewed external vs internal links |

### Phase 3.2: Follow the login link (escalation)

A marketing landing page or SPA shell often carries **no form at all**. The credential form sits
one click away behind a "Login" or "Member Portal" link. Every login-gated floor (off-CDN
third-party host, hotlinked brand artwork, brand-lookalike subdomain) stays a no-op until a
password field is seen, so a kit with a clean front page and the harvester at `/login` reads SAFE.
This is what `icamis.icam.mw` did: a SAFE verdict on a page with zero forms, and the vision model
never even ran.

`page-fetch.sh` puts the candidate links in `loginLinks` (strongest first, matched on link **text**
and path). `url-analyze.sh` spends **one** more fetch on the best one and caches it as
`page-login.json` plus `login.jpg`. If that page really asks for credentials, its smells merge as
if seen on the landed page, `HAS_LOGIN` becomes true, and the VLM reads the **credential page**
instead of the marketing shell.

Two caps hold the false positives down. The **link is never a signal**: a site that has a login
page is not suspicious, so only what the followed page contains can score. And only a
**same-registrable-domain** link is followed, because legit sites sign in off-domain
(`login.microsoftonline.com`) and following that would import the identity provider's signals as
this site's.

### Phase 3.2b: Follow the interstitial destination (escalation)

A **redirect-notice** page contains nothing of its own: zero forms, one outbound link, a
"Redirect Notice" title. Judging it judges the wrapper, not the thing the link opens — and every
wrapper of that shape scores 0 red flags, so the destination could be anything.
`help_genderise_biz-dot-mmemails.appspot.com/em_...?url=<dest>` did exactly that: an aged
Google-owned host, a valid cert, a clean empty shell, and the real destination sitting in `?url=`
**in cleartext that Phase 1 had already decoded and then dropped on the floor**. Nothing anywhere
fetched it.

`redirect_url` (`verdict.sh`, pure and golden-tested) returns the **whole** decoded destination,
not just the host that `redirect_target` gives — an interstitial hands the browser a URL with a
path, and fetching the bare host lands on a homepage the link never opened. `url-analyze.sh` spends
**one** more fetch on it and caches it as `page-redirect.json` plus `redirect.jpg`, and the VLM
reads the destination, because a screenshot of a redirect notice tells it nothing.

This does **not** relax the same-apex cap on scraped links above: the destination here is one *we*
parsed out of the URL, not one the page offered us. Three guards hold the false positives down:

1. **The wrapper must be contentless** — no credential form, no forms at all, 3 links or fewer. An
   OAuth consent screen has both a form and content, so a genuine
   `accounts.google.com/o/oauth2/v2/auth?redirect_uri=...` is never followed. That is the whole
   reason an off-site target is not a signal in the first place.
2. **The redirect is never a signal.** Only what the destination *contains* can score.
3. **The destination's own domain age decides whether its findings score at all.** Without this the
   first cut called the real LinkedIn tracker **DANGEROUS**: LinkedIn has a sign-in form and three
   iframes, which is "login form + 1 red flag" once you attribute them to the wrapper. Every large
   legitimate site would do the same. So an interstitial pointing at an **established** domain is
   the ordinary email-tracker shape and its findings are context — printed, and handed to the LLM,
   but never a floor — while one pointing at a domain **under 90 days old** is the kit shape and
   scores in full, re-arming `HAS_LOGIN` and every login-gated floor on the real credential
   surface. Unknown age reads as established, matching `count_red_flags`, which does not count an
   unknown age either: an absent fact must never manufacture one.

Verified both ways on the same wrapper: `?url=` to LinkedIn (8679-day domain) → context only, no
floor; `?url=` to a 1-day-old `.space` host → its `atob()`/redirect JS imported, floor SUSPICIOUS.

`FINAL_URL` and `TITLE` are deliberately **not** overridden by the destination — they feed the
brand-lookalike check, and the wrapper host is exactly where an impersonation lure lives on a
vanity multi-tenant host. Pointing them at the destination would trade one half of this fix for the
other. The destination's own hostile *shape* is already scored from the URL by the open-redirect
rule in Phase 1 (risky TLD / machine-generated host at the far end).

**ponytail ceiling:** domain age is the whole test, so a **compromised aged** domain serving a kit
lands as context. Scan the destination URL directly to judge it on its own facts.

### Phase 3.5: JS Deobfuscation (escalation)

When Phase 3 flags obfuscation, `url-analyze.sh` escalates. It deobfuscates the inline scripts
of the page with **webcrack**, a static AST tool that runs sandboxed and never executes attacker
JS. It then re-scans the cleartext for the signals the obfuscation hid.

| Detection | Description |
|-----------|-------------|
| Off-domain exfil URL | `fetch`/XHR/form target on a different host than the landed domain |
| Cookie / storage theft | `document.cookie`, localStorage/sessionStorage reads that feed a send |
| JS redirect | `location.href/replace/assign`, `window.location=` |
| Revealed crypto address | BTC/ETH/TRX wallet decoded from the string array |
| Anti-analysis code | The kit checking whether it is talking to **us**: enumerating browser-automation artifacts (`webdriver`, `__nightmare`, `callPhantom`, `_Selenium_IDE_Recorder`, …), a `debugger` trap inside a timer, blocked devtools keys, `ipapi.is` datacentre/VPN filtering, or a script deleting itself from the DOM. The **probe list** is the discriminator, not any one name: legitimate bot protection tests `navigator.webdriver`, kits enumerate the whole family in a fixed order, so the threshold is 4 distinct names. Zero of the 177 pages in the local cache trip it. Capped: **SUSPICIOUS**, excluded from the red-flag count, because commercial bot protection does some of this on real login pages — "hiding from analysis" is not the same claim as "harvesting credentials" |

An off-domain exfil, a JS redirect, or a crypto address counts as a deterministic red flag (see
`verdict.sh`). An obfuscated **login** page that deobfuscates to off-domain exfil therefore
floors to DANGEROUS. The escalation is gated: it only runs on obfuscation markers, and it caches
per URL. `-D` skips it. To run the deobfuscator standalone: `./js-deobfuscate.sh <file.js>`.

### Phase 3.7: Vision escalation (what the DOM cannot see)

The VLM reads the screenshot and answers three lines: `BRAND` (visual clone of a brand the landed
domain does not own), `PASSWORD` (a credential input the DOM missed — kits use non-password inputs
and shadow DOM), and `ADULT` (pornographic imagery). It is the most expensive step in a scan
(~50s on CPU), so it is gated on three triggers, caches in `vision.txt`, and `-V` turns it off:

1. A detected login form.
2. A form plus login-ish/exfil context in the title, URL or smells.
3. **A formless page that already carries a red flag.** Nothing on it to steal, so the only open
   question is *what it is* — and this is where `category_of` used to shrug and say `other`.

Trigger 3 is what makes the `adult` category possible: an adult gateway is nothing but images, so
the scraped text says nothing (`xk51.efast.space` titles itself "No swiping. No ghosting. Just
something that clicks.") and the DOM has zero forms, which disarms every other escalation. The
screenshot is the only witness left.

Trigger 3 is **category-only**, and that cap is load-bearing rather than tidy. The `PASSWORD` and
`BRAND` answers move the verdict (they can set `HAS_LOGIN` and push a red flag into `SMELLS`), and
a weak VLM says `PASSWORD: yes` readily — on a page with **zero forms** that claim is not credible,
because there is nothing to submit. Ungated it made a `github.io` environment newsletter DANGEROUS
(phishing) off one hallucinated field. Triggers 1 and 2 both require a form, so restricting the two
severity-bearing answers to them leaves their behaviour byte-identical.

`ADULT: yes` therefore sets the category and never the floor, which is also the honest reading:
porn is not phishing, and the severity on that page still comes from the 0-day domain, the
fast-flux TTL and the `atob()` redirect that earned the look in the first place. The prompt carves out lingerie, swimwear and dating photos, so
the soft dating-lure sibling on the same campaign (fully clothed, "Thousands of real women") answers
`ADULT: no` — verified, along with four ordinary pages (a bank e-statement, a competition landing
page, two webmail logins), all `ADULT: no`.

### Phase 4: LLM Analysis

- Reads all the signals in context
- Verdict: **SAFE** / **SUSPICIOUS** / **DANGEROUS**
- Strict mode: "when in doubt, choose DANGEROUS"

## Brand Detection (80+ brands)

| Category | Brands |
|----------|--------|
| Tech | google, microsoft, apple, amazon, paypal, netflix, zoom, slack |
| Crypto | coinbase, binance, metamask, ledger, trustwallet, kraken |
| US Banks | chase, wellsfargo, bankofamerica, citi, schwab, fidelity, amex |
| UK Banks | barclays, hsbc, lloyds, natwest, monzo, revolut |
| EU Banks | ing, bnp, deutsche, ubs, creditsuisse |
| African Banks | nedbank, standardbank, fnb, absa, capitec, investec |
| APAC Banks | dbs, ocbc, maybank, icici, hdfc, anz, westpac |

## Commands

```bash
# Full analysis with LLM
./url-analyze.sh -m qwen2.5:1.5b <url>

# Static analysis only (skip page fetch)
./url-analyze.sh -s <url>

# Page scraper only (JSON output)
./page-fetch.sh <url>

# Email spam benchmark
./benchmark.sh [model] [prompt]
```

## Config (env vars)

| Var | Default | Effect |
|-----|---------|--------|
| `BRAND_MATCH` | `strict` | Brand impersonation match scope. `strict` = title and form action. `body` = also body text |
| `VISION_MODEL` | `openbmb/minicpm-v4.6:q4_K_M` | VLM for the Phase 3.7 screenshot read (brand clone, credential input, adult imagery). Set it to `claude-<id>` (for example `claude-haiku-4-5`) to read the screenshot through the Anthropic API instead of local Ollama (needs `ANTHROPIC_API_KEY`) |
| `NO_COLOR` | (unset) | Turn off ANSI color (`-c mono` does the same) |
| `VT_API_KEY` | (unset) | VirusTotal key for `-t`, in `.env`. The VT lookup needs it |
| `URLSCAN_API_KEY` | (unset) | urlscan.io key for `-t`, in `.env`. Optional, it only raises rate limits |
| `ANTHROPIC_API_KEY` | (unset) | Claude API key for `-m claude-<id>` and `VISION_MODEL=claude-<id>`, in `.env`. Opt-in: it sends page text and screenshots to the API |

## Dependencies

- Docker with the Ollama image (`llm-spam-test` container)
- Docker with `ghcr.io/puppeteer/puppeteer` for page-fetch
- Docker `local-llm-webcrack` image (auto-builds on the first deobfuscation: `node:22-alpine`
  plus `webcrack`)
- `jq`, `bc`, `dig`, `openssl`, `curl`

## Skills Installed

- **GSD (Get Shit Done)**: project management for solo devs
- **Ponytail**: lazy senior dev mode (added from the marketplace)
