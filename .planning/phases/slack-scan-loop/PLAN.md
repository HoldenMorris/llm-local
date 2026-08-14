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

## 1. Connect Slack here and find out what it actually gives us — DONE (2026-08-13)

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

**Answered 2026-08-13, by calling them.** Slack is connected here as Holden (`U024KJMFC`), workspace
`synaq.slack.com`. The channel is **`#luca-phishing-alerts` = `C099U43SRS5`**, public, created by
samg 2025-08-07, and live — alerts arriving the morning this was written.

| Question | Answer | Tool |
|---|---|---|
| Read the channel, filter since a timestamp? | **Yes.** `oldest`/`latest` take a Slack `ts`, newest-first, 100 max per page with a `next_cursor` | `slack_read_channel` |
| Read DMs and @-mentions? | **Yes**, via search modifiers (`to:me`, `from:`, `in:`) with `channel_types: im,mpim` | `slack_search_public_and_private` |
| Post? | Yes | `slack_send_message` |
| Prepare *without* posting? | **Yes** — saves to the user's Drafts & Sent, never sends. Schema-verified only; no test draft has been created yet | `slack_send_message_draft` |
| Rate limit shape? | **Still unknown.** No call has surfaced a limit or a header. Treat as unmeasured, which is why the loop interval starts long | — |

Three things learned that the design has to respect:

1. **`response_format: "concise"` omits the message `ts`.** It prints the rendered text and a
   human-readable local time and nothing else. Seen-state needs the raw `ts`, so the pass that
   records the watermark must ask for `detailed` — reading only `concise` gives you no watermark to
   store, and a loop that cannot store one re-reads the same messages forever.
2. **`oldest` is inclusive**, so the stored `ts` comes back again on the next pass. Add one
   microsecond (`.969619` → `.969620`) or drop the first message.
3. **`slack_search_public_and_private` output is large** — one `to:me` query with `limit: 5`
   returned 61,275 characters, over the tool-result ceiling. Narrow queries, `include_context:
   false`, or `response_format: "concise"`. This is a real constraint on the DM path, not a nuisance.

**Alert shape** (what task 2's URL extraction parses):

```
:fishing_pole_and_fish: *Phishing alert* — `https://hn551.revibesocialclub.com/?s1=snm3`
:white_check_mark: Recorded: <@U024KH6KT|samg> marked this *phishing*.
```

Posted by the **`Luca Phishing Alerts` bot (`U098UR256TZ`)**, URL in backticks, and a second line
appearing once a human has ruled. That `Recorded:` line is a **human judgement already in Slack** —
worth reconciling against the ledger, and not something the earlier intake accounted for.

**Also live now:** a read-only poll of this channel on `/loop 5m`, watermark in
`.planning/slack-states/slack-luca-alerts-state.json` (gitignored). It summarises new alerts and
does **not** scan, reply, or open a URL. That is task 3's step 1 running ahead of the rest, and it
is the safe half — no live infrastructure is fetched.

**If drafting turns out to be impossible** — some integrations only send — stop and re-decide. The
"draft, do not post" call is what makes the rest of this safe, and it is not mine to overturn.

## 2. `feedback-report.sh --settled` over one channel message — DONE (2026-08-13, `next-alert.sh`)

**Why:** the cheapest half of the whole plan, and the earlier intake's first proposal. Most alerts
are hosts we have already judged.

**Do:** for each URL in a message, call `--settled`. Exit **0** → already settled SAFE, **2** →
already settled bad, **1** → unknown. Draft the answer straight from the TSV line for 0 and 2. Only
**1** goes on to a scan.

**Done when:** a message naming a host already in the ledger produces a drafted reply quoting the
prior inspection, with no scan run at all.

## 3. The pass itself — SHIPPED AS A SCRIPT, NOT A SKILL (2026-08-13)

**What actually shipped:** `next-alert.sh`, one alert per invocation, run by hand. It reads the
channel through `claude -p`, picks the newest alert with **no `Recorded:` line** (LUCA rewrites its
own message when somebody rules, so the buttons still showing *is* the open-worklist filter — a
watermark was not needed), asks `--settled`, scans only the unknown, and prints the button the
evidence earns. `-u <url>` rules on one URL, `-a` re-offers one already shown.

Two things the plan below got wrong, both found by building it: the seen-state file was
unnecessary (the message carries its own state), and the scans must **close stdin** — four prompts
in `url-analyze.sh` are gated on `[ -t 0 ]` alone, so a scripted caller hangs on a question nobody
can see. A periodic `/loop` pass is still open, and is the cheap add when volume asks for it.

**Original shape (kept for the reasoning):**

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

## 4. Retention — DONE (2026-08-13). `next-alert.sh` wipes the page artifacts of a scan it ran
itself and keeps `feedback.txt`; `KEEP=1` overrides. A human's own scan keeps its prompt.

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

## 5. Deep inspection for the unknowns — DONE (2026-08-14). The prompt moved into `inspect.sh` so
the `i` branch of `url-analyze.sh` and `next-alert.sh` share one copy; a scan that lands on Skip is
resolved by that inspection instead of being handed back unfinished. It still writes no
`inspected` row — the row gets written when a human rules, for the reason below.

**Why:** the intake's second proposal. The `i` prompt in `url-analyze.sh` already runs a headless
`claude -p` over the cached artifacts and returns `VERDICT:`/`NOTE:`.

**Do:** for a scanned unknown, run that same inspection and put its verdict and note into the
**draft**. Do not write an `inspected` row from the loop.

**Why not write it:** `inspected` means somebody looked, and `--settled` refuses to act on `agree`
rows for precisely that reason. If the loop writes inspections, the ledger starts asserting human
review that did not happen — and the corpus those rows feed is what the weekly replay scores
against. The row gets written when Holden sends the reply, not when the machine drafts it.

## 6. Harvest the rulings that only ever lived in Slack — SHIPPED (2026-08-14), not in the original plan

A click on a LUCA alert is a real human judgement, and it was invisible to us: `--settled` could not
answer with it and the weekly replay never scored against it. `slack-harvest.sh` reads those
`Recorded:` lines and writes them through `feedback-report.sh -i` (`FB_EXTERNAL=1`), deduped on the
message `ts`. It guesses **no** category — a button press says a page is bad, not what it is. First
run: 98 rulings, and the earlier alert sample went from **0 of 22** settled to **19 of 22**.

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
