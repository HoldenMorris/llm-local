#!/usr/bin/env bash
# Take the newest LUCA alert nobody has ruled on, scan it, and say which button to click.
#
# The three buttons on a LUCA alert are "Verify phish", "False positive" and "Skip". This maps
# a scan verdict onto one of them. It reads Slack through `claude -p` (the connector lives in
# Claude, not in this shell) and answers the ledger before it ever fetches anything.
#
# It NEVER clicks. Clicking is submit_report()+chat_update() inside the gateway, and a recorded
# verdict is supposed to mean a human looked. You look at this, then you click.
#
#   ./next-alert.sh                # newest unruled alert in Holden's LUCA DM
#   ./next-alert.sh C099U43SRS5    # ...in the shared alerts channel instead
#   ./next-alert.sh -u <url>       # skip Slack, just rule on one URL
#   ./next-alert.sh -a             # re-offer an alert already shown (ignore the seen-list)
#   ./next-alert.sh --self-test
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source "$SCRIPT_DIR/colors.sh"

DM_CHANNEL="D0BAMTCJE7K"     # "You're up" prompts land here; the shared channel is mostly settled
SCAN_FLAGS=(-c mono)         # any flag at all disables url-analyze's interactive prompts

# Verdict -> button. UNCLEAR and SUSPICIOUS deliberately do NOT get a confident button: a scan
# that could not decide is not evidence for either "phish" or "false positive", and Skip is the
# only honest answer a machine can give there.
button_for() {
    case "$1" in
        DANGEROUS)  echo "VERIFY PHISH|$RED|the scan found this actively malicious" ;;
        SAFE)       echo "FALSE POSITIVE|$GREEN|the scan found nothing malicious" ;;
        SUSPICIOUS) echo "SKIP|$YELLOW|worth your eyes -- the scan smelled something but not enough to call it" ;;
        *)          echo "SKIP|$CYAN|the scan could not decide; do not let it vote" ;;
    esac
}

if [ "${1:-}" = "--self-test" ]; then
    for pair in "DANGEROUS:VERIFY PHISH" "SAFE:FALSE POSITIVE" "SUSPICIOUS:SKIP" "UNCLEAR:SKIP" ":SKIP"; do
        got=$(button_for "${pair%%:*}" | cut -d'|' -f1)
        [ "$got" = "${pair#*:}" ] || { echo "FAIL ${pair%%:*} -> $got"; exit 1; }
    done
    echo "self-test ok"; exit 0
fi

URL=""; FROM_SLACK=0; ALL=0
[ "${1:-}" = "-a" ] && { ALL=1; shift; }
if [ "${1:-}" = "-u" ]; then
    URL="${2:?-u needs a url}"
else
    FROM_SLACK=1
    CHANNEL="${1:-$DM_CHANNEL}"
    command -v claude >/dev/null 2>&1 || { echo_red "need 'claude' on PATH to read Slack"; exit 1; }
    echo_grey "reading $CHANNEL for an alert nobody has ruled on..."
    # A ruled alert has been rewritten in place with a "Recorded: <user> marked this ..." line,
    # so absence of that line IS the open-worklist filter. Read-only tool, so it cannot reply.
    URL=$(claude -p "Read Slack channel $CHANNEL (limit 15, response_format concise).
Find the NEWEST message that is a LUCA phishing alert AND has NO 'Recorded:' line in it --
that means nobody has given it a verdict yet.
Print ONLY that message's URL. Bare, no backticks, no markdown, no explanation.
If every alert already carries a 'Recorded:' line, print exactly: NONE" \
        --allowedTools "mcp__claude_ai_Slack__slack_read_channel" 2>/dev/null \
        | tr -d '`' | grep -oE 'https?://[^[:space:]]+|^NONE$' | tail -1)
    # LUCA's extractor swallows trailing punctuation from the source mail (seen: "yhopecn.com/)")
    URL="${URL%)}"
fi

if [ -z "$URL" ] || [ "$URL" = "NONE" ]; then
    echo_green "nothing waiting -- every alert already has a verdict"
    exit 0
fi

# On a loop this runs every few minutes against the same open alert, so without a seen-list it
# nags about one URL forever -- and an alert you have already declined to scan is not news.
# Same shape as intel-feed.sh's seen-list. `-a` re-offers one you have already been shown.
SEEN="$SCRIPT_DIR/.cache/next-alert-seen.txt"
if [ "$FROM_SLACK" = 1 ] && [ "$ALL" = 0 ] && [ -f "$SEEN" ] && grep -qxF "$URL" "$SEEN"; then
    echo_grey "nothing new -- newest open alert ($URL) was already offered"
    exit 0
fi
[ "$FROM_SLACK" = 1 ] && { mkdir -p "$SCRIPT_DIR/.cache"; printf '%s\n' "$URL" >>"$SEEN"; }

echo ""
echo_bold "alert: $URL"

# Ask the ledger before touching the network. A settled URL costs one grep instead of a scan of
# live phishing infrastructure, which is the whole reason --settled exists.
if settled=$(./feedback-report.sh --settled "$URL" 2>/dev/null); then rc=0; else rc=$?; fi
# Take the verdict from the TSV, not from the exit code. Exit 2 only means "settled bad", which
# lumps SUSPICIOUS in with DANGEROUS -- and a ledger row reading SUSPICIOUS ("list-validation,
# not credential theft") must not come back as a confident "Verify phish". The row already
# carries the real severity; use it.
case "$rc" in
    0|2) VERDICT=$(printf '%s' "$settled" | head -1 | cut -f1)
         SOURCE="the ledger already settled this"
         case "$VERDICT" in SAFE|SUSPICIOUS|DANGEROUS) ;; *) VERDICT=$([ "$rc" = 0 ] && echo SAFE || echo DANGEROUS) ;; esac ;;
    *)   VERDICT="" ;;
esac

if [ -z "$VERDICT" ]; then
    SOURCE="fresh scan"
    # The ledger could not answer, so the next step fetches live phishing infrastructure. Ask
    # first when a human is watching. Non-interactive callers (a loop, cron) are unaffected --
    # same [ -t 0 ] convention url-analyze.sh uses for its own prompts.
    if [ -t 0 ]; then
        printf '\a'
        read -r -p "${CYAN}Not in the ledger. Scan it? (fetches the live page) [Y/n] ${RESET}" _ans
        [[ "$_ans" =~ ^[Nn] ]] && { echo_grey "skipped -- nothing scanned"; echo "alert: $URL"; exit 0; }
    fi
    LOG=$(mktemp); trap 'rm -f "$LOG"' EXIT
    echo_grey "scanning (this fetches the live page, ~1-2 min)..."
    # stdin from /dev/null, deliberately. Four prompts in url-analyze.sh (bot-gate attach, open
    # screenshot, open in browser, "do you agree?") are gated on [ -t 0 ] ALONE -- passing flags
    # does not disable them. With our stdout on a pipe, such a prompt is invisible and the whole
    # thing looks hung. Closing stdin makes every one of them self-disable.
    # It also means no ledger row is written from here, which is what we want: `inspected` has
    # to mean a human looked, and this tool exists precisely because one has not yet.
    # tee, not >, so a long scan visibly progresses instead of looking stuck.
    ./url-analyze.sh "${SCAN_FLAGS[@]}" "$URL" </dev/null 2>&1 | tee "$LOG"
    VERDICT=$(grep -oE 'VERDICT: (SAFE|SUSPICIOUS|DANGEROUS|UNCLEAR)' "$LOG" | tail -1 | awk '{print $2}')
    # The "Signals (N):" block is the scan's actual findings. Grepping every "- " line instead
    # scoops up progress chatter ("- Restarting existing Ollama container...") and reports it as
    # evidence, which is worse than showing nothing.
    EVIDENCE=$(awk '/^Signals \(/{f=1;print;next} f&&/^- /{print;next} f{exit}' "$LOG" | head -9)
    # ponytail: retention. url-analyze only offers "keep the artifacts?" on a bare run, and we
    # always pass flags, so nothing would ever ask -- and these URLs carry recipient tokens.
    # feedback.txt survives, because a judgement is the one part a re-scan cannot regenerate.
    if [ "${KEEP:-0}" != "1" ]; then
        d="$SCRIPT_DIR/.cache/$(printf '%s' "$URL" | sha256sum | cut -c1-16)"
        [ -d "$d" ] && find "$d" -mindepth 1 ! -name feedback.txt -delete 2>/dev/null
    fi
fi

IFS='|' read -r BTN COLOR WHY <<<"$(button_for "${VERDICT:-UNCLEAR}")"
echo ""
echo "${COLOR}${BOLD}=============================================="
echo " CLICK:  $BTN"
echo "==============================================${RESET}"
echo_grey " verdict ${VERDICT:-UNCLEAR} -- $WHY"
echo_grey " source:  $SOURCE"
[ -n "${settled:-}" ] && printf '%s\n' " $settled" | sed "s/^/${GREY}/;s/\$/${RESET}/"
[ -n "${EVIDENCE:-}" ] && printf '%s\n' "$EVIDENCE" | sed "s/^/${GREY}/;s/\$/${RESET}/"
echo ""
echo_grey "nothing was clicked or posted -- that is yours to do"
# Say "scanned" only when something was actually fetched; the ledger path touches no network.
echo "$([ "$SOURCE" = "fresh scan" ] && echo scanned || echo alert): $URL"
