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
# any flag at all disables url-analyze's interactive prompts. -m auto picks the best model per
# results/url_benchmark.csv (without it a flagged run takes whatever model is installed first);
# -t adds VirusTotal + urlscan, which is what a LUCA alert deserves -- these URLs are already
# reported as phish, and VT's 5-vendor quorum floors DANGEROUS with no credential form needed.
SCAN_FLAGS=(-c mono -m auto -t)

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

SEEN="$SCRIPT_DIR/.cache/next-alert-seen.txt"
# Reads the last row for this url, across all three row formats this file has had: a bare url,
# "<verdict>\t<url>", and today's "<verdict>\t<resolved>\t<url>\t<note>". The url is NOT always the
# last field -- the note is -- so its position comes from the column count, not from $NF.
seen_field() {
    [ -f "$SEEN" ] || return 0
    awk -F'\t' -v u="$1" -v f="$2" '
        { urlcol = (NF==1 ? $1 : (NF==2 ? $2 : $3)) }
        urlcol==u { v = (NF==1 ? "?" : (f=="v" ? $1 : (f=="r" && NF>=3 ? $2 : (f=="n" && NF>=4 ? $4 : "")))) }
        END { print v }' "$SEEN"
}

if [ "${1:-}" = "--self-test" ]; then
    for pair in "DANGEROUS:VERIFY PHISH" "SAFE:FALSE POSITIVE" "SUSPICIOUS:SKIP" "UNCLEAR:SKIP" ":SKIP"; do
        got=$(button_for "${pair%%:*}" | cut -d'|' -f1)
        [ "$got" = "${pair#*:}" ] || { echo "FAIL ${pair%%:*} -> $got"; exit 1; }
    done
    SEEN=$(mktemp)
    printf 'SUSPICIOUS\thttps://legacy2col\n'                 >>"$SEEN"   # written before the flag existed
    printf 'SAFE\thttps://legacy-safe\n'                      >>"$SEEN"
    printf 'https://legacy-bare\n'                            >>"$SEEN"   # the original bare-url row
    printf 'DANGEROUS\ti\thttps://done\tcredential form\n'   >>"$SEEN"
    printf 'SUSPICIOUS\t\thttps://unfinished\t\n'            >>"$SEEN"
    _sf() { [ "$(seen_field "$1" "$2")" = "$3" ] || { echo "FAIL seen_field $1 $2: want [$3] got [$(seen_field "$1" "$2")]"; exit 1; }; }
    _sf https://done v DANGEROUS; _sf https://done r i; _sf https://done n "credential form"
    _sf https://unfinished v SUSPICIOUS; _sf https://unfinished r ""
    _sf https://legacy2col v SUSPICIOUS; _sf https://legacy2col r ""
    _sf https://legacy-safe v SAFE
    _sf https://legacy-bare v "?"
    _sf https://never-seen v ""
    rm -f "$SEEN"
    echo "self-test ok"; exit 0
fi

URL=""; FROM_SLACK=0; ALL=0; RESOLVED=""
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
# Append-only, "<verdict>\t<resolved>\t<url>\t<note>", latest line wins -- the same shape as
# feedback.txt, so a URL offered again is re-answered rather than merely suppressed. "?" is
# written before the scan (so declining still stops the nagging) and the real answer after it.
#
# `resolved` is the field that matters. A stored SUSPICIOUS is NOT an answer -- it is a Skip, the
# work handed back -- so replaying it as though it were settled is how this tool silently stops
# doing its job. Only a verdict the deep inspection has already been spent on counts as resolved;
# anything else is unfinished and gets re-offered. Rows written before the inspection existed
# carry no flag and are therefore correctly treated as unfinished.
if [ "$FROM_SLACK" = 1 ] && [ "$ALL" = 0 ] && _prev=$(seen_field "$URL" v) && [ -n "$_prev" ]; then
    _res=$(seen_field "$URL" r)
    # Settled means: a real verdict AND the inspection has already been spent on it. Anything
    # else falls through to a fresh run rather than being replayed as an answer.
    if [ "$_prev" != "?" ] && { [ "$_res" = i ] || [ "$_prev" = SAFE ] || [ "$_prev" = DANGEROUS ]; }; then
        echo ""
        echo_bold "alert: $URL"
        IFS='|' read -r BTN COLOR WHY <<<"$(button_for "$_prev")"
        echo "${COLOR}${BOLD} CLICK: $BTN${RESET}"
        echo_grey " verdict $_prev -- $WHY"
        echo_grey " source:  the earlier run (inspected); no new alert has arrived since"
        _n=$(seen_field "$URL" n)
        [ -n "$_n" ] && printf '%s\n' " $_n" | fold -s -w 96 | sed "s/^/${CYAN}/;s/\$/${RESET}/"
        exit 0
    fi
    # Unfinished. On a loop, say so and stop -- an unattended re-scan of live phishing every few
    # minutes is exactly what the seen-list exists to prevent. With a human here, carry on: the
    # confirm prompt below asks before anything is fetched.
    if [ ! -t 0 ]; then
        echo ""
        echo_bold "alert: $URL"
        echo_yellow "offered before but never resolved (${_prev/\?/no verdict}) -- needs a person"
        echo_grey "  ./next-alert.sh -a   to scan and deep-inspect it"
        exit 0
    fi
    echo_grey "offered before but never resolved (${_prev/\?/no verdict}) -- finishing it now"
fi
[ "$FROM_SLACK" = 1 ] && { mkdir -p "$SCRIPT_DIR/.cache"; printf '?\t\t%s\t\n' "$URL" >>"$SEEN"; }

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
         SOURCE="the ledger already settled this"; RESOLVED=i
         case "$VERDICT" in SAFE|SUSPICIOUS|DANGEROUS) ;; *) VERDICT=$([ "$rc" = 0 ] && echo SAFE || echo DANGEROUS) ;; esac ;;
    *)   VERDICT="" ;;
esac

if [ -z "$VERDICT" ]; then
    SOURCE="fresh scan"
    # ponytail: no confirm before the live fetch. The whole point of this tool is "tell me which
    # button to click", and the ledger has already been asked -- an unsettled alert has exactly
    # one next step, so asking permission for it is a keypress that only ever answers Y.
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
            RESOLVED=i   # spent, whatever it concluded -- a re-run would only repeat it
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
# Record the answer so the next pass can repeat it instead of re-doing the work. A SAFE or
# DANGEROUS is final on its own; a Skip only counts as final once the inspection has been spent,
# otherwise the next pass must pick it back up rather than replay an unfinished result.
if [ "$FROM_SLACK" = 1 ]; then
    case "${VERDICT:-UNCLEAR}" in SAFE|DANGEROUS) RESOLVED=i ;; esac
    printf '%s\t%s\t%s\t%s\n' "${VERDICT:-UNCLEAR}" "${RESOLVED:-}" "$URL" \
        "$(printf '%s' "${INOTE:-}" | tr '\t\n' '  ')" >>"$SEEN"
fi
echo ""
echo_grey "nothing was clicked or posted -- that is yours to do"
# Say "scanned" only when something was actually fetched; the ledger path touches no network.
case "$SOURCE" in *scan*) echo "scanned: $URL" ;; *) echo "alert: $URL" ;; esac
