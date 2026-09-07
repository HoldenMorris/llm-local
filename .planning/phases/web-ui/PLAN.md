# Plan — `scope`

Seven plans in four waves. Each is one atomic commit.

**Direction, decided 2026-08-21: the triage inbox is the app.** It is the landing surface; the
workbench and the ledger are drill-ins from it (`enter` to the workbench on this alert, a
`LEDGER SAYS` row to the ledger filtered to that host or campaign, `esc` back to the same queue
position) and standalone tabs besides. That reorders nothing below — the queue still depends on the
scan and ledger surfaces existing — but it adds one requirement to each of plans 03 and 04, marked
**[nav]**, and makes the shell itself part of plan 02.

Layout: everything new lives in `web/` — `web/app.py`, `web/jobs.py`, `web/templates/`,
`web/static/`. Nothing outside `web/` changes except `url-analyze.sh` (plan 01) and `next-alert.sh`
(plan 05), both additively.

---

## Wave 1 — foundations (independent, run in parallel)

### 01 · `verdict.json` — a scan persists its own answer — SHIPPED

**Goal:** every scan leaves a machine-readable record of what it decided, and the CLI gains a
`--json` for free.

`url-analyze.sh` writes `$CACHE_DIR/verdict.json` at the end of a scan, from variables already in
scope: `url`, `final_url`, `verdict`, `category`, `red_flags`, `signals[]`, `floor` (which rule
fired and what the LLM said), `model`, `phase_timings`, `artifacts[]`, `scanned_at`, and the
`inspected` row if one overrode the machine verdict.

- Written on every path that reaches a verdict, including the UNCLEAR degrades — a factless scan
  must produce a factless record, not an absent one.
- `-j` / `--json` cats it to stdout. Not a second code path.
- Existing 427 cache dirs have no `verdict.json`; absent means "scanned before this existed" and
  the reader falls back to the other artifacts. No backfill.

**Done when:** a scan of a known URL writes the file; `./test-verdict.sh` still passes 236/236;
`./url-analyze.sh -H -V <url>` output is byte-identical to before.

### 02 · The API skeleton, the job runner, and the fence — SHIPPED

**Goal:** a server that can safely run one script at a time and safely show what it produced.

- FastAPI bound to `127.0.0.1:8787`. `uvicorn`, no auth.
- `web/jobs.py`: asyncio subprocess runner, **semaphore(1)**, job dict, per-job wall-clock ceiling
  above `PAGE_TIMEOUT`, SSE endpoint streaming stdout lines. Exec array form only.
- The fence, all of it, in this plan and not retrofitted later:
  - Jinja autoescape on; a lint that fails the build on `|safe`.
  - `/artifact/{hash}/{name}` — `hash` must match `^[0-9a-f]{16}$`, `name` must be in an allowlist
    (`page.jpg`, `login.jpg`, `redirect.jpg`, `page.json`, `page-login.json`, `page-redirect.json`,
    `vision.txt`, `wayback.json`, `deob-signals.txt`, `scripts/<n>.js`). Images get their real type;
    **everything else is `text/plain` + `nosniff`**.
  - CSP `default-src 'self'`; no remote origins; no inline handlers.
  - A `url` template filter that renders inert text plus a copy control, never an `<a href>`.
- **The shell**, because the direction is decided: base template with the four tabs, the
  `esc` / `enter` keyboard layer, and a route shape that carries queue position through a drill-in
  (`/alert/{n}` -> `/alert/{n}/workbench`) so back is a route, not browser history.

**Done when:** two scans queued at once run in sequence with the second showing "waiting"; a
crafted `../` artifact path 404s; `curl` from another host on the LAN is refused; a `page.json`
containing `<script>` renders as text. **All four verified.**

**What changed from the plan, and why.** Python cannot be installed on this machine without a
`sudo apt` (no `python3-venv`, no pip, no uv), and the standing preference is that a language never
becomes a host dependency — so the web half runs in a container. That does not compose with
shelling out: `url-analyze.sh` needs docker, dig, openssl, jq, curl and bc, and `page-fetch.sh`
launches sibling containers with host paths. Reaching all of it from inside would mean mounting
`/var/run/docker.sock` — root on the host, handed to the process that renders attacker-controlled
strings.

So the runner split in two. `web/worker.sh` runs on the host and is the security boundary; the
container asks it for work through four files in `.cache/web-jobs/`, naming a **kind** rather than
a command line. The whitelist lives with the thing that executes, which is the same reasoning that
put `floor_parts` next to the printf that writes the floor notice, and `feedback-report.sh -i` in
sole charge of the ledger row format. Semaphore(1) came free: the worker is one bash loop.

Three bugs the tests found, all real:
- `web/queue.py` shadowed the stdlib `queue` that asyncio had already imported, so `import queue`
  silently returned the wrong module. Renamed to `web/jobs.py`.
- The security middleware assigned the page CSP over the artifact route's own stricter
  `default-src 'none'; sandbox`. `setdefault`, not assignment — a response carrying a kit's bytes
  must not be relaxed by the generic policy.
- The container wrote the spool as uid 10001 while the worker read it as the invoking user. It now
  runs as `--user $(id -u):$(id -g)`, and `up.sh` creates the spool before the mount, because
  docker creates a missing bind source as a **root-owned** directory — the trap `page-fetch.sh`
  already documents.

---

## Wave 2 — the two surfaces that read what already exists

### 03 · Scan workbench — SHIPPED

**Goal:** paste a URL, watch it scan, read every artifact on one screen, agree or correct.

- Scan form: URL plus the flag toggles (`-t -r -V -H -D -p tor -m`), defaults `-m auto -t` to match
  `next-alert.sh`.
- Live phase timeline derived from the streamed lines; evidence panes for signals, screenshots
  (`login.jpg` / `redirect.jpg` / `page.jpg`, in that order), DOM, `scripts/`, network, the LLM
  answer, and the raw log.
- The verdict panel names **which floor fired and what the LLM said** — that disagreement is the
  most useful line in the whole scan and today it scrolls past.

**[nav]** Opening the workbench from a queued alert must re-fetch **nothing** — the alert was
already scanned to get its verdict, so the drill-in renders `verdict.json`, `page.json` and the
screenshots straight off disk. If the drill-in triggers a scan, the navigation is wrong.
Recording a verdict here is the same action as recording it in the inbox.

**Done when:** a live scan streams phase by phase; a cached scan renders with no subprocess at all;
the screenshot the VLM read is the one shown; `enter` from an alert reaches the workbench in under
a second and `esc` returns to the same queue row. **All verified**: 97 lines streamed over SSE on a
live scan, the timeline lit `domain facts → verdict llm → verdict` (no fetch phase, correctly — the
page was cached), and `1c4533a72ebf2521` renders `login.jpg` before `page.jpg` with the caption
naming it as the one the VLM read.

**The bug this plan found, and it was in plan 02's whitelist.** The first real scan submitted
through the UI was refused: `not an http(s) url`. `is_url` rejected shell metacharacters, and the
url was a DICOM WADO request carrying `&`. Every tracking link this toolkit exists to read carries
`&`, so the whitelist would have refused most of the corpus.

The blacklist was answering a question that does not arise: the argv is a bash array handed
straight to exec and never becomes a shell string, so `&`, `;`, `|`, `$` and backticks are just
characters. What actually has to be refused is whitespace and control characters — a newline in
particular, which would otherwise reach the log and state files that carry the job protocol. Three
new cases pin the accept side (ampersands, metacharacters, percent-encoding plus a fragment) and
three the reject side (tab, space, newline). Removing the wrong check made the whitelist both
correct and shorter, which is usually the sign it was wrong.

### 04 · Ledger surface — SHIPPED

**Goal:** the report nobody remembers to run, always on screen; and one place to record a ruling.

- Reads: `feedback-report.sh` report, `-f` open flags, `--host` / `--apex` / `--campaign` rollups,
  `--corpus` export, and the agreement / category figures.
- Writes: **only** `feedback-report.sh -i` with `FB_VERDICT` / `FB_CATEGORY`, and the two-row
  disagreement shape (the `disagree` row that keeps the stat honest, plus the corrected `inspected`
  row).
- The deep inspection (`inspect.sh` → `claude -p` over the cached artifacts) as a job, with its
  `VERDICT:` / `CATEGORY:` / `NOTE:` parsed by the existing parsers.

**[nav]** Every rollup is addressable, because the inbox links into it: `/ledger?host=`,
`?apex=`, `?campaign=`. Clicking "3 settled DANGEROUS on this campaign" in the inbox lands on those
three rows, not on the front page of a report. This is the half of the ledger surface worth
building carefully — the tab is the easy half.

**Done when:** recording a correction through the UI produces a ledger row byte-identical in shape
to one the CLI writes; `--settled` then answers with it; `--corpus` includes it; and a campaign
link from the inbox lands on the filtered rows. **All verified** on a throwaway url: rc 1 before,
rc 2 after, the standard six-column row on disk, and present in `--corpus`.

**What this needed that the plan did not name:** `feedback-report.sh --json`. The rollups were
already machine-readable TSV, but the aggregate report was prose, and the alternative was the web
side computing its own agreement rate — a second owner for the arithmetic. Same reasoning as
`verdict.json` in plan 01, and a self-test asserts the JSON and the prose agree.

Two bugs, both found by running it:
- The worker was executing its **pre-edit** `build_argv` — bash had already parsed the functions
  into memory, so editing the file mid-run changed nothing until a restart. The repo's own
  "never edit a running script" note, met from the other side.
- The heartbeat only ticked **between** jobs, so a worker busy with a two-minute scan read as
  "worker down" — precisely the confusion the heartbeat was added to remove. It now has its own
  background ticker: it means "this process is alive", and the job states beside it already say
  whether anything is running.

---

## Wave 3 — the daily job

### 05 · Triage queue

**Goal:** every unruled LUCA alert on one screen, each already answered by the ledger or scanned.

- `next-alert.sh` gains a JSON mode that returns the **whole open list** rather than the newest one
  — the DM first, the channel only when the DM is empty, filtered on the absence of a `Recorded:`
  line. The existing single-alert behaviour is untouched.
- Refresh is a job (`claude -p` costs ~20–40s per channel), with a visible "last refreshed".
- Per alert: `--settled` first, scan only what the ledger cannot answer, then the recommended
  button, the evidence, and the record control.
- **[nav]** the three exits — `enter` to the workbench on this alert, a `LEDGER SAYS` row to the
  filtered ledger, the tabs for either standalone. `esc` returns to the same queue row.
- **No clicking.** The UI says which button; a human presses it in Slack.

**Done when:** the queue shows the same alert `./next-alert.sh` picks, plus the ones behind it;
a settled alert costs zero network; ruling on one removes it from the queue only after the ledger
row exists.

### 06 · Tool runner

**Goal:** the periodic work is a button, and its output is readable.

`url-benchmark.sh` (weekly replay, `results/url_benchmark.csv` as a chart), `slack-harvest.sh -n`
then the real run, `intel-feed.sh` with `NO MATCHING DETECTION` items pulled to the top,
`model-scout.sh`, `tor-up.sh`. All through the same job runner and the same one-at-a-time rule.

**Done when:** the weekly replay runs from the UI and writes the same CSV row the CLI does.

---

## Wave 4 — the one thing that needs a real conversation

### 07 · Operator attach over the wire

**Goal:** clear a Turnstile gate in Brave and have the scan continue, from the browser.

Two-step: the job opens Brave with the throwaway profile and the debugging port, then blocks; the
UI shows "clear the gate, then continue"; a POST releases it and `page-fetch.sh` re-reads the
cleared tab with `PAGE_ATTACH=`. The kill-on-exit behaviour (`pkill -f <profile>`) has to survive
the request lifecycle, which is why this is last and its own plan.

**Done when:** a gated URL scans to the uncloaked page from the UI, and Brave is gone afterwards
whether the scan succeeded, failed or was abandoned.

---

## Not in this phase

- Auth, multi-user, a server deploy. A later phase that starts by revisiting the `127.0.0.1` bind.
- Backfilling `verdict.json` into the 427 existing cache dirs.
- Any change to how a verdict is computed. If this phase moves a benchmark number, something is
  wrong.
