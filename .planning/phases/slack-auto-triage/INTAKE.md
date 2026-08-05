# Intake: automated deep-inspect triage for the Luca phishing-alert channel

Captured 2026-08-05 for a GSD planning session on 2026-08-06. Everything under "How it works
today" was read from `synaq/luca-ecosystem` at HEAD (shallow clone; there is no local checkout --
`sync-to-luca.sh` clones to a temp dir and deletes it).

## What Holden asked for

An automated deep-inspect tool that watches the `luca-phishing-alerts` Slack channel and, in auto
mode, deep-scans each alert and records the response — "as me", so the loop closes without a human
in it.

## How it works today (verified, not assumed)

`services/luca-slack-gateway`, a Socket Mode app (bot token + app token):

- `app/poller.py` — `poll_once` pulls `luca.fetch_alerts(date, min_confidence, limit)`, drops ones
  in `seen_store`, checks `_is_blacklisted`, picks an assignee from `pool_store` respecting DND,
  and posts the alert.
- `app/main.py` — `_handle_block_actions` verifies `is_trusted_origin` (team id + app id), parses
  the click into a `Verdict(action_id, classification, url, slack_user_id, slack_username,
  channel_id, message_ts)`, and on a correction calls `luca_client.submit_report(url,
  new_classification)` → `POST /reporting/`, then `_finalize_alert_message` does a `chat_update`
  that swaps the buttons for "✅ Recorded: @user marked this *clean*".

**The important consequence: the "click" is just `submit_report()` + `chat_update()`.** Auto mode
never needs to simulate a Slack click, never needs a user token, and never needs to impersonate
anyone at the Slack layer. It calls the same two functions the button handler calls.

## Proposed shape

1. **Ask the ledger before paging anyone.** In `poll_once`, before posting:
   `feedback-report.sh --settled <url>` → `0` settled-safe, `2` settled-bad, `1` unknown. Only `1`
   becomes a human alert. This alone is the fix for 31 alerts in 20 minutes on one Mailercloud
   unsubscribe host that had been inspected three hours earlier.
2. **Deep inspect the unknowns.** Run `url-analyze.sh` non-interactively, then the `claude -p`
   inspection that already exists behind the `i` prompt, and record the result through
   `submit_report`.
3. **Auto-record policy — the part that needs care.** Auto-confirm *phishing* on a deterministic
   floor of DANGEROUS, or a settled-bad host/apex/campaign. **Never auto-mark clean on a page the
   scanner could not see**: a failed fetch, a bot gate and an empty DOM all look identical to a
   clean page downstream, and that mistake has already been made four times in this toolkit
   (see the phantom-SAFE class). Unknown stays unknown and pages a human.
4. **Dedupe on (host + leading token block)**, not on the whole URL. The 31 alerts were 6
   recipients; the varying middle block made each one look new to `seen_store`.

## The attribution question — raise before building

Holden asked for it to record "as me". The audit trail then says a human reviewed something no
human saw, and the ledger's whole value is that `inspected` means somebody looked — `--settled`
deliberately refuses to act on `agree` rows for exactly this reason.

Recommend recording under a distinct auto identity, with the alert posted **already annotated but
still actionable**: the evidence and proposed verdict shown, buttons live for a human to confirm or
overturn. Same latency benefit, honest provenance, and it keeps the corpus labels trustworthy —
they are what the weekly replay scores against. Holden's call; note the trade if he wants it as-is.

## Blockers and open questions

- **Authorisation.** The Slack app page shows "Authorisation hasn't been set up for this app.
  Contact samg." Needs resolving before anything can run under Holden's account.
- **Where does the gateway run**, and does that host have Docker? The scanner needs the puppeteer
  container and (unless `-H`) Ollama. If not, auto-inspect has to be a separate worker with a queue
  rather than an inline call from `poll_once`.
- **Is `POST /reporting/` idempotent** for repeated auto-submissions of the same URL?
- **Quiet or visible?** Should auto-resolved alerts be suppressed entirely, or posted in a resolved
  state so the channel still shows what was decided?
- The scanner's ledger lives in `local-llm/.cache`, which is machine-local. A shared deployment
  needs that state somewhere both the gateway and the scanner can reach.
