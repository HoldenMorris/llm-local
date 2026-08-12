# Plan: run the slack-auto-triage loop over Claude's own Slack connection

Context, decisions and the honest limits: [CONTEXT.md](CONTEXT.md).
The plan this delivers: [`../slack-auto-triage/INTAKE.md`](../slack-auto-triage/INTAKE.md).

**Goal (what must be TRUE):** a URL posted in @Luca Phishing Alerts, or sent to Holden, gets checked
against the ledger and — only if unknown — scanned, with a reply drafted and waiting for him to
send. Nothing posts itself, nothing re-scans what we already settled, and no victim PII accumulates
on disk because a loop turned the prompts off.

**Shape, before any code:** there is no daemon to write. `/loop` already runs a slash command on an
interval, `--settled` already answers the ledger question, and `url-analyze.sh` already scans. The
deliverable is **one skill** that does a single pass, plus the retention step nobody needs while a
human is driving. Build it in the order below; each task stands alone and commits on its own.

---

## 1. Connect Slack here and find out what it actually gives us

**Why first:** this machine has only the `pencil` MCP server. Every task below assumes a way to read
a channel and post a draft, and nobody has verified which of those the connection exposes. Design
built on a guessed API is the thing that wastes the phase.

**Do:** connect Slack to Claude on this box (Holden's account, the same way it is set up on the
other PC). Then answer, by calling them, not by reading docs:
- can it **read** @Luca Phishing Alerts history, and filter to messages since a timestamp?
- can it read **DMs and @-mentions** to Holden?
- can it post — and can it prepare something *without* posting (a draft, or just returning text)?
- what is the rate limit shape?

**Done when:** those four answers are written into this file, with the tool names used.

**If drafting turns out to be impossible** — some integrations only send — stop and re-decide. The
"draft, do not post" call is what makes the rest of this safe, and it is not mine to overturn.

## 2. `feedback-report.sh --settled` over one channel message

**Why:** the cheapest half of the whole plan, and the earlier intake's first proposal. Most alerts
are hosts we have already judged.

**Do:** for each URL in a message, call `--settled`. Exit **0** → already settled SAFE, **2** →
already settled bad, **1** → unknown. Draft the answer straight from the TSV line for 0 and 2. Only
**1** goes on to a scan.

**Done when:** a message naming a host already in the ledger produces a drafted reply quoting the
prior inspection, with no scan run at all.

## 3. The pass itself, as a skill

**Do:** `.claude/skills/scan-slack/SKILL.md`, one pass:

1. read messages since the last pass — seen-state in `.cache/`, modelled on `intel-feed.sh`
2. extract URLs; **dedupe on host + leading token block**, not the whole URL (the intake found 31
   alerts were 6 recipients — a varying middle block made each look new)
3. `--settled` (task 2); unknowns only continue
4. scan with explicit flags — never a bare run, so the interactive prompts stay off
5. **cap the scans per pass** and stop; an alert storm must not become an unattended scan storm
6. draft the reply: verdict, category, the evidence lines, and the `scanned:` URL

**Then:** `/loop 10m /scan-slack`. Start the interval long. It is easier to explain a slow reply
than a rate-limit ban.

**Done when:** one pass over a channel with a known-settled URL, a known-bad URL and a fresh URL
produces exactly one scan and three drafts.

## 4. Retention — the part a loop breaks

**Why:** `url-analyze.sh` asks "keep the artifacts?" only on a bare run, and **any** flag turns that
off. A loop always passes flags. So an unattended loop silently accumulates `page.json`, screenshots
and scripts containing recipient email addresses and reset tokens — exactly the PII the interactive
prompt exists to offer to wipe.

**Do:** after each pass, wipe the page artifacts for URLs it scanned itself, keeping `feedback.txt`
— the same split the interactive prompt makes, because the judgement is the one part a re-scan
cannot regenerate. Make it the default for loop-initiated scans; a human scan keeps its prompt.

**Done when:** a loop pass over a live phishing URL leaves the ledger row and no page artifacts.

**Not optional, and not last because it is least important** — it is last because it needs the
loop to exist to be testable.

## 5. Deep inspection for the unknowns

**Why:** the intake's second proposal. The `i` prompt in `url-analyze.sh` already runs a headless
`claude -p` over the cached artifacts and returns `VERDICT:`/`NOTE:`.

**Do:** for a scanned unknown, run that same inspection and put its verdict and note into the
**draft**. Do not write an `inspected` row from the loop.

**Why not write it:** `inspected` means somebody looked, and `--settled` refuses to act on `agree`
rows for precisely that reason. If the loop writes inspections, the ledger starts asserting human
review that did not happen — and the corpus those rows feed is what the weekly replay scores
against. The row gets written when Holden sends the reply, not when the machine drafts it.

---

## Open, deliberately not decided here

- **Suppression stays with the gateway.** This route cannot stop an alert being posted (CONTEXT).
  When authorisation unblocks, move the task-2 check into `poll_once` — that is where the 31-in-20
  problem is actually solved.
- **`POST /reporting/` idempotency** — still unanswered from the earlier intake, and still needed
  before anything writes back to Luca.
- **Auto-posting** is out of scope by decision, not oversight. Revisit only with the drafts from a
  few weeks of real passes to look at.

## Not doing

- A daemon, a queue, or a service. `/loop` plus a skill covers it; add more only when that
  measurably falls short.
- Any change to `luca-ecosystem`. The whole point of this route is that it needs none.
