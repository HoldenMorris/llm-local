# Research — a web UI over the toolkit

*2026-08-21. Everything here was read out of the repo, not assumed.*

## What is actually being wrapped

23 shell scripts, 6,292 lines. `url-analyze.sh` (1,986) and `page-fetch.sh` (1,103) carry the
scan; `verdict.sh` (577) is the pure deterministic core with 236 golden cases pinning it;
`feedback-report.sh` (366) owns the ledger. On disk: **427** cache entries, **320** screenshots,
**403** ledger rows of which **180** are `inspected`.

## 1. `next-alert.sh` is already the prototype

It is the whole app in 348 lines of bash: read a queue, ask the ledger before the network, scan
only what the ledger cannot answer, show a verdict with its evidence, offer a deep inspection,
offer the screenshot, record the ruling. The web UI is that loop with a queue you can see and
artifacts you can read side by side. Nothing about the flow needs inventing — it needs a surface.

That also fixes the thing it cannot do today: it hands you **one** alert per invocation, and the
queue behind it is invisible.

## 2. The CLI's interactivity is the product, and it does not survive a subprocess

`url-analyze.sh` has **13** `read -r -p` sites. Every one is gated on `can_prompt` (`colors.sh`),
which compares the terminal's foreground process group with our own — from a web backend there is
no terminal, so `can_prompt` is false and **all 13 questions are silently skipped**. That is
correct behaviour and it is exactly what we want: the scripts run non-interactive, and the UI owns
every question.

The questions the UI therefore has to re-ask, because nobody else will:

| CLI prompt | Where it goes in the UI |
|---|---|
| re-use cache or update `[R/u]` | a toggle on the scan form, plus "last scanned" on the alert |
| do you agree with this verdict | the agree / correct control |
| what should the verdict be, what is it, why | the correction form (verdict, category, note) |
| record it / change category | the record control |
| deep inspect now (`i`) | the deep-inspect button |
| open the screenshot | the screenshot pane — free, it is already on screen |
| keep this scan cached | a wipe-on-record default, matching `next-alert.sh` |

**One prompt does not reduce to a form: operator attach.** It opens Brave, waits for a human to
clear a Turnstile gate, then re-reads the cleared tab over CDP on an Enter. That is a genuine
synchronous resume and it needs a two-step endpoint — start, then a "cleared, go" the job is
blocked on. It only works because we are on localhost with the analyst's own GUI.

## 3. The verdict is the one thing a scan does not persist

A scan already writes structured artifacts: `page.json`, `page-login.json`, `page-redirect.json`,
`meta.env`, `vision.txt`, `wayback.json`, `scripts/`, `deob-signals.txt`, and the per-URL
`feedback.txt`. What it does **not** write is its own answer — verdict, category, signals, red-flag
count, which floor fired, phase timings. Those live in shell variables and are echoed to a
terminal.

So the API's job is not to parse stdout. It is to have `url-analyze.sh` write **`verdict.json`**
into the cache dir at the end of a scan, from variables already in scope. That file is the API's
read model, and `cat`-ing it is the `--json` mode the CLI never had. One writer, ~25 lines, and the
427 existing cache dirs backfill lazily (absent file = "scanned before this existed", show what the
other artifacts hold).

The lazier alternative — scraping the banner — was rejected: the banner is colour-coded prose that
changes whenever the verdict wording changes, and a parser over it would break silently on exactly
the scans that matter.

## 4. Reads go to `.cache/`, writes go through one script

Reads are already structured JSON on disk, so the API reads them directly. **Writes are different.**
`feedback-report.sh -i` owns the ledger row format — `slack-harvest.sh` already routes through it
rather than touching `feedback.txt`, for the reason stated in CLAUDE.md, and the API must be the
second caller and not a second writer. A row written two ways is a row that drifts.

`--settled` already answers "have we looked at this?" with exit codes 0/2/1 and one TSV line. The
queue calls it before any network, the same as `next-alert.sh`.

## 5. Concurrency is one, and that is a fact about the hardware

Ollama runs in a single container on a 14-core CPU box with no GPU; a vision call is ~50s and a
verdict ~18s. `page-fetch.sh` launches a Docker container per fetch. The ledger is an append-only
text file. Two scans at once would contend on all three and make the timings in
`results/url_benchmark.csv` meaningless.

So: an in-process asyncio queue with **semaphore(1)**, jobs in a dict, SSE for progress. No Celery,
no Redis, no database. The queue depth is visible in the UI so a second scan reads as "waiting",
not "broken".

## 6. Streaming: SSE over the subprocess, with `-c mono`

`url-analyze.sh` prints phase by phase over 18s–2min. `-c mono` already strips ANSI (colours are
off for a non-terminal stdout anyway), so the stream is plain text. SSE one line per event; the
phase timeline in the UI is derived from the lines the script already prints. No new logging
format.

`PAGE_TIMEOUT` (default 180s) bounds a single fetch. The job needs its own wall-clock ceiling above
that, because a scan can chain a login-link follow, an interstitial follow and a vision call.

## 7. Slack is a subprocess, not a request

`next-alert.sh` reads Slack through `claude -p` with the Slack MCP tool — the connector lives in
Claude, not in the shell, and there is no bot token here. Measured this session: **~20–40s** per
channel read. That cannot sit inside an HTTP request. The queue refresh is a job like a scan, with
its result cached and a visible "last refreshed".

Two channels, in order: the LUCA DM (`D0BAMTCJE7K`), then `#luca-phishing-alerts`
(`C099U43SRS5`) only when the DM is empty. The open-worklist filter is the **absence of a
`Recorded:` line**, because LUCA rewrites its own message in place when somebody rules.

**The UI must not click either.** There is no block-action tool, and a recorded verdict has to mean
a human looked.

## 8. The genuinely new risk: the UI renders attacker-controlled content

The CLI never had this. A browser dashboard does, and it is the one part of this phase where
"lazy" is the wrong instinct:

- **Stored XSS.** Page titles, console text, form actions, redirect chains and JS snippets are
  written by the attacker and displayed by us. Jinja2 autoescape is on by default — the risk is any
  place we reach for `|safe` to render a highlighted signal.
- **Serving the payload back.** `.cache/<hash>/scripts/*.js` and cached HTML must be served
  `text/plain` with `X-Content-Type-Options: nosniff`, never `text/html`, or the dashboard becomes
  the delivery mechanism for the kit it is analysing.
- **Path traversal.** An artifact route takes a 16-hex cache hash and a filename; both need an
  allowlist, not a join.
- **Live URLs as links.** One misclick opens a live phish with the victim's token in it. URLs
  render as inert text with a copy button.
- **CSP.** `default-src 'self'`, no remote origins, no inline handlers — which also means Alpine
  needs a nonce or a local build. Worth knowing before choosing Alpine.
- **PII.** Screenshots and cached pages carry recipient email addresses and reset tokens. Bind
  `127.0.0.1` only, and keep the wipe-after-record behaviour `next-alert.sh` already has.
- **Command injection.** The URL goes into a subprocess. Exec array form, always; never a shell
  string.

## 9. No auth, and that is a decision not an omission

Single analyst, localhost, `127.0.0.1` bind. Adding auth would be scaffolding for a deployment
nobody has asked for. What replaces it is the bind address and the CSP — and a note that a server
deploy is a later phase that starts by revisiting exactly this line.

## Open questions

- **Which direction** the shell takes (queue-first / workbench-first / dashboard-first) — the four
  surfaces ship either way, only the landing surface and the nesting differ. See the design canvas.
- **Alpine vs no JS at all.** HTMX covers most of it; Alpine is for the keyboard layer and the tab
  panes. Decide when the CSP is written, not before.
- **Backfilling `verdict.json`** for the 427 existing scans. Probably not: a re-scan writes one, and
  the ledger already holds the settled answer for the ones that matter.
