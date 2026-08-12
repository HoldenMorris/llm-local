# Context: scan URLs from Slack, on a loop, from this machine

Captured 2026-08-12.

## What Holden asked for

Use the Slack connection to Claude to watch **@Luca Phishing Alerts** and respond to requests to
scan URLs — a loop that picks up URLs sent to him in Slack and scans them with the toolkit in this
repo.

## This is how we get the slack-auto-triage plan working

[`../slack-auto-triage/INTAKE.md`](../slack-auto-triage/INTAKE.md) planned automated triage *inside*
`luca-slack-gateway`: `poll_once` asks the ledger, then `submit_report()` + `chat_update()` closes
the alert. It has not moved, and its blockers are all **access**, not design: "Authorisation hasn't
been set up for this app. Contact samg", plus "where does the gateway run, and does that host have
Docker?" and "the ledger lives in `local-llm/.cache`, which is machine-local".

Holden's own Slack session through Claude sidesteps every one of those. No app authorisation, no
gateway deploy, no change to `luca-ecosystem`, and the scan runs on the machine that already has
Docker, Ollama and the ledger. So this phase is the **vehicle** for the earlier plan, not a rival to
it: the same three things it asked for — ask the ledger before paging anyone, deep-inspect the
unknowns, record the response — delivered over a path that is open today.

**What this route genuinely cannot do.** The gateway's biggest win was *suppression*: `poll_once`
checks the ledger **before posting**, so a settled alert never reaches the channel at all. That is
what fixes thirty alerts in twenty minutes for one host inspected three hours earlier. Claude sees a
message only once it has been posted, so this route cannot prevent the noise — it can only answer
it. Suppression still needs the gateway, and this phase does not pretend otherwise.

**What carries over.** The dedupe key, the ledger-first check and the inspection wrapper built here
are the same pieces `poll_once` needs. When authorisation unblocks, the gateway inherits working,
exercised code instead of a design document.

## Decisions taken (2026-08-12)

- **Runs on this machine.** Slack gets connected to Claude here. The scanner, Ollama, the puppeteer
  container and the ledger in `.cache/` are all local, so scanning stays a local call with local
  state. This deliberately avoids the split the gateway plan is stuck on — its own notes flag
  "where does the gateway run, and does that host have Docker?" and "the ledger lives in
  `local-llm/.cache`, which is machine-local".
- **It drafts, it does not post.** A verdict is prepared with its evidence and waits for Holden to
  send it. Nothing is published into a shared channel by a loop.

That second decision also settles the attribution problem the gateway intake raised. Its worry was
that recording "as me" makes the audit trail claim a human reviewed something no human saw — and
`inspected` meaning *somebody looked* is the whole reason `--settled` refuses to act on `agree`
rows. If a human sends every reply, the ledger stays honest by construction.

## What already exists (verified in this repo, not assumed)

- **`feedback-report.sh --settled <url>`** was built for exactly this caller: exit **0** settled
  SAFE, **2** settled bad, **1** unknown, with a TSV line when it knows. Shipped 2026-08-11
  (`2df1c2f`) with the note that it exists so "alerting can ask the ledger before it pages anyone".
- **`url-analyze.sh`** does the scan. Its two interactive prompts (re-use cache, keep artifacts)
  are disabled the moment **any** flag is passed, so a scripted call can never be blocked by one.
- **`/loop`** already runs a slash command on an interval. There is no daemon to write.
- **`intel-feed.sh`** is the working model for "what is new since last time": a seen-list in
  `.cache/`, and a hard failure rather than a silent empty result when the source misbehaves.

## The constraints that shape the design

1. **Only this machine has the scanner.** No Slack MCP is configured here yet (`pencil` is the only
   MCP server), so task 1 is establishing the connection and finding out what it actually exposes.
2. **A looped scan fetches live phishing infrastructure unattended.** That is the tool's normal job,
   but a human currently decides each time. On a loop nobody does, so the ledger must be asked
   first and the per-pass volume must be capped.
3. **Scanned URLs carry victim PII.** Recipient addresses and reset tokens sit in the URL, and land
   in `page.json` and the screenshots. The "wipe the artifacts?" prompt is interactive-only — and a
   loop passes flags, which turns it off. Unattended scanning therefore accumulates PII silently
   unless retention is handled explicitly.
