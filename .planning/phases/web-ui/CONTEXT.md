# Context — `scope`, a local dashboard over the toolkit

*Opened 2026-08-21.*

## Why

The toolkit works and the ledger proves it — 180 inspected rows, 100% agreement on DANGEROUS, a
weekly replay that scores the detector against real labels. What it does not have is a surface. The
daily job is: run `next-alert.sh`, read three screens of scrolling output, remember which flag
mattered, open a screenshot in another program, type a note, run `feedback-report.sh -i` to record
it, then do it again. Every one of those steps exists and works; none of them can see each other.

Three things are lost to that:

1. **The queue is invisible.** `next-alert.sh` hands you one alert per invocation. You cannot see
   how many are waiting, which are already settled, or which host keeps coming back.
2. **The evidence is scattered.** A scan writes `page.json`, two more page JSONs, a screenshot for
   each, `scripts/`, `vision.txt`, `wayback.json` and `meta.env` — and shows you a bullet list. To
   read the deobfuscated JS beside the screenshot beside the LLM's answer you open three programs.
3. **The ledger is a report you have to remember to run.** 5 open flags, SUSPICIOUS sitting at 77%
   agreement, 16 URLs categorised `other` — all of it is a `feedback-report.sh` invocation nobody
   makes on a Tuesday.

## What this is not

Not a rewrite. Not a service. Not a product for the team. The detection logic does not move, does
not fork, and does not get a second implementation — the rule in CLAUDE.md about both paths moving
together applies with more force here, because a UI that computes its own verdict is a third path.

## Decisions taken (2026-08-21)

| Decision | Choice | Why |
|---|---|---|
| Deployment | **localhost, single analyst, no auth** | The ledger, Ollama, Docker and Brave already live here, and `127.0.0.1` is a stronger boundary than a login form |
| v1 scope | **all four surfaces** — triage queue, scan workbench, ledger dashboard, tool runner | They share one backend; splitting them costs more than it saves |
| Backend ↔ bash | **subprocess, plus `verdict.json`** | Scripts stay the single source of truth for detection. The one thing a scan does not persist is its own answer, so it starts persisting it |
| Stack | **FastAPI + Jinja + HTMX** | No build step, no bundler, `python3` is already a dependency. SSE for the live scan stream |
| Direction | **triage inbox is the app** | It is what opens and what you look at all day. The workbench and the ledger are one keystroke away from it, not places you navigate to |

## Navigation, which is the direction decision made concrete

The inbox is the shell. Three ways out of it, all reversible without losing your place in the
queue:

| From | To | How |
|---|---|---|
| an alert | the **workbench**, on that alert | `enter`, or the workbench chip on the alert header |
| a `LEDGER SAYS` row | the **ledger**, filtered to that host / apex / campaign | click the row |
| anywhere | either surface, standalone | the top tabs |

`esc` always returns to the same queue position. Two things make the drill-in cheap rather than a
context switch:

- **The workbench opens on artifacts already on disk.** The alert was scanned to produce its
  verdict, so the drill-in re-fetches nothing — it renders `page.json`, the screenshots and
  `verdict.json` that already exist.
- **Recording a verdict is the same action on both surfaces.** You never have to go back to the
  inbox to finish what you started in the workbench.

The ledger jump is the half worth building carefully. As a tab it is the Tuesday-morning read; as a
jump target it answers a question the inbox just raised — "3 settled DANGEROUS on this campaign"
should land on those three, not on the front page of a report.

## Constraints that shape everything

- **One job at a time.** Ollama, the scan container and the append-only ledger are all
  single-tenant. Semaphore of 1, jobs in memory, queue depth on screen.
- **The scripts run non-interactive.** `can_prompt` is false without a terminal, so all 13 prompts
  in `url-analyze.sh` are skipped and the UI has to ask them itself. Operator attach is the one
  that needs a real synchronous resume.
- **Writes go through `feedback-report.sh -i`.** One owner for the row format, as `slack-harvest.sh`
  already does.
- **The UI never clicks a Slack button.** No block-action tool exists, and a recorded verdict has
  to mean a human looked.
- **It renders attacker-controlled content.** Escaping, `text/plain` artifact serving, an artifact
  path allowlist, inert URLs, a CSP, and `127.0.0.1` — this is the part not to be lazy about.

## Success, stated backward

The phase is done when, on an ordinary morning:

- Opening one page shows every LUCA alert nobody has ruled on, each already answered by the ledger
  or scanned, and says which button to click.
- Disagreeing with a verdict takes one click to the evidence and one form to record the correction,
  and the corrected row is in the ledger and in next week's replay corpus.
- The screenshot, the signals, the deobfuscated JS and the LLM's reasoning are on one screen.
- The 5 open flags and the SUSPICIOUS agreement rate are visible without remembering to run
  anything.
- `./url-analyze.sh`, `./next-alert.sh` and `./test-verdict.sh` still behave exactly as they do
  today, and the benchmark numbers do not move.

That last line is the real test. If the CLI changes behaviour, the wrap was done wrong.
