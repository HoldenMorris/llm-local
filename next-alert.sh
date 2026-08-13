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
source "$SCRIPT_DIR/inspect.sh"   # deep_inspect + its parsers, shared with url-analyze.sh

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
# Append-only, "<verdict>\t<url>", latest line wins -- the same shape as feedback.txt, so a URL
# offered again is re-answered rather than merely suppressed. "?" is written before the scan (so
# declining still stops the nagging) and the real verdict is appended after it.
SEEN="$SCRIPT_DIR/.cache/next-alert-seen.txt"
seen_verdict() {
    [ -f "$SEEN" ] || return 0
    awk -F'\t' -v u="$1" '$2==u{v=$1} (NF==1 && $1==u){v="?"} END{print v}' "$SEEN"
}
if [ "$FROM_SLACK" = 1 ] && [ "$ALL" = 0 ] && _prev=$(seen_verdict "$URL") && [ -n "$_prev" ]; then
    echo ""
    echo_bold "alert: $URL"
    # Repeating "nothing new" is useless when the answer is already known -- say it again.
    if [ "$_prev" = "?" ]; then
        echo_yellow "already offered, but never got a verdict (declined or interrupted)"
        echo_grey "  ./next-alert.sh -a   to rule on it now"
    else
        IFS='|' read -r BTN COLOR WHY <<<"$(button_for "$_prev")"
        echo "${COLOR}${BOLD} CLICK: $BTN${RESET}"
        echo_grey " verdict $_prev -- $WHY"
        echo_grey " source:  the earlier run; no new alert has arrived since"
    fi
    exit 0
fi
[ "$FROM_SLACK" = 1 ] && { mkdir -p "$SCRIPT_DIR/.cache"; printf '?\t%s\n' "$URL" >>"$SEEN"; }

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

    # SUSPICIOUS and UNCLEAR both map to Skip, which hands the work straight back to you. So
    # before giving up, spend the deep inspection: claude reads the cached artifacts and says
    # what the page actually is. Same prompt url-analyze.sh's `i` uses (inspect.sh).
    # MUST run before the wipe below -- the inspection reads exactly the artifacts that removes.
    case "${VERDICT:-UNCLEAR}" in SUSPICIOUS|UNCLEAR|"")
        echo ""
        echo_grey "verdict is a Skip -- running the deep inspection instead of handing it back..."
        _cache="$SCRIPT_DIR/.cache/$(printf '%s' "$URL" | sha256sum | cut -c1-16)"
        _hostdir="$SCRIPT_DIR/.cache/host/$(printf '%s' "$URL" | sed -E 's#^[a-z]+://([^/]+).*#\1#' | tr -c 'a-zA-Z0-9.:_-' '_')"
        _smells=$(printf '%s' "$EVIDENCE" | sed '1d;s/^- //' | paste -sd, -)
        if _iout=$(deep_inspect "$URL" "$URL" "${VERDICT:-UNCLEAR}" "$_smells" "$_cache" "$_hostdir" </dev/null); then
            _iv=$(inspect_verdict "$_iout"); INOTE=$(inspect_note "$_iout")
            _ic=$(inspect_category "$_iout")
            # Only ever replace the verdict with one the inspection actually stated. An
            # unparseable reply leaves the scan's own verdict standing rather than inventing one.
            if [ -n "$_iv" ]; then
                [ "$_iv" != "$VERDICT" ] && echo_cyan "inspection corrects $VERDICT -> $_iv"
                VERDICT="$_iv"; SOURCE="fresh scan + deep inspection${_ic:+ ($_ic)}"
            fi
        else
            echo_yellow "deep inspection unavailable -- keeping $VERDICT"
        fi
        ;;
    esac

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
# The inspection's one-line conclusion is the "real response": what the page actually is, not
# just how the heuristics scored it.
[ -n "${INOTE:-}" ] && { echo ""; printf '%s\n' " $INOTE" | fold -s -w 96 | sed "s/^/${CYAN}/;s/\$/${RESET}/"; }
echo ""
# Record the answer so the next pass can repeat it instead of saying "nothing new".
[ "$FROM_SLACK" = 1 ] && printf '%s\t%s\n' "${VERDICT:-UNCLEAR}" "$URL" >>"$SEEN"
echo ""
echo_grey "nothing was clicked or posted -- that is yours to do"
# Say "scanned" only when something was actually fetched; the ledger path touches no network.
case "$SOURCE" in *scan*) echo "scanned: $URL" ;; *) echo "alert: $URL" ;; esac
