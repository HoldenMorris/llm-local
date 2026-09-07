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
#   ./next-alert.sh                # newest unruled alert: the LUCA DM, then #luca-phishing-alerts
#   ./next-alert.sh C099U43SRS5    # ...in that one channel only
#   ./next-alert.sh -u <url>       # skip Slack, just rule on one URL
#   ./next-alert.sh -a             # re-offer an alert already shown (ignore the seen-list)
#   ./next-alert.sh --self-test
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source "$SCRIPT_DIR/colors.sh"
source "$SCRIPT_DIR/inspect.sh"   # deep_inspect + its parsers, shared with url-analyze.sh

DM_CHANNEL="D0BAMTCJE7K"     # "You're up" prompts land here: the open worklist, read first
VERIFY_CHANNEL="C099U43SRS5" # #luca-phishing-alerts, the "Phishing alert N -- verify?" feed.
# Two places to look, in that order: the DM is where work is handed to you personally, and the
# channel is the shared feed anyone may already have taken. Falling back only when the DM is
# empty keeps one person's queue ahead of the pile, and stops a channel alert being offered
# while a DM alert is still waiting.
# any flag at all disables url-analyze's interactive prompts. -m auto picks the best model per
# results/url_benchmark.csv (without it a flagged run takes whatever model is installed first);
# -t adds VirusTotal + urlscan, which is what a LUCA alert deserves -- these URLs are already
# reported as phish, and VT's 5-vendor quorum floors DANGEROUS with no credential form needed.
SCAN_FLAGS=(-c mono -m auto -t)
LAST_RULED=""   # what the newest already-ruled alert was ruled, for the empty-queue line
OPEN_N=""       # how many alerts in the channel are still open, so a backlog cannot hide

# How far back to look, and NOT a detail. At 15 this tool reported "nothing waiting" while
# **sixteen** unruled alerts sat in the channel: rulings land newest-first, so the recently-answered
# ones fill the top of the window and push the backlog out of sight. That is the one failure mode a
# worklist tool must not have, because "nothing waiting" and "I cannot see the work" read
# identically. The open COUNT that read_channel now returns is the other half of the fix -- any
# window can be too small, and a number you can compare against the channel makes it visible when
# it is.
READ_LIMIT="${READ_LIMIT:-60}"

# One channel, newest alert nobody has ruled on, or NONE. A ruled alert has been rewritten in
# place with a "Recorded: <user> marked this ..." line, so absence of that line IS the
# open-worklist filter. Read-only tool, so it cannot reply.
#
# When everything IS ruled it returns "NONE: <what the newest one was ruled>". A bare "nothing
# waiting" is indistinguishable from "the read failed and found no alerts at all" -- and the two
# want opposite reactions. Naming the last verdict is the cheapest possible proof the read
# actually worked and that the queue really is empty rather than unreachable.
read_channel() {   # <channel-id> -> "<open count>\t<url | NONE: what the newest one was ruled>"
    claude -p "Read Slack channel $1 (limit $READ_LIMIT, response_format concise).
A LUCA phishing alert is a message about a reported URL, which may read like
'Phishing alert 0 -- verify?'. An alert is OPEN when it carries NO 'Recorded:' line, which means
nobody has given it a verdict yet.
Print EXACTLY TWO LINES and nothing else.
Line 1: OPEN: <how many alerts are open, as a plain number>
Line 2: the URL of the NEWEST open alert, bare -- no backticks, no markdown, no explanation.
        If none are open, print instead NONE followed by a colon, a space, and what the NEWEST
        alert's Recorded: line says: who ruled it and what they called it. For example:
        NONE: Sam marked this Verify phish" \
        --allowedTools "mcp__claude_ai_Slack__slack_read_channel" 2>/dev/null | parse_reply
}

# The reply, as "<open count>\t<url | NONE:... | ERR>". A read that produced NEITHER a url NOR a
# NONE line did not find an empty queue -- it FAILED, and saying "nothing waiting" for that is the
# phantom-SAFE shape one layer out: the two sentences read identically and want opposite reactions.
# The usual cause is mundane and invisible from here -- `claude` is logged out, so the headless
# Slack read errors out on stderr and stdout is empty, while sixteen alerts sit in the DM.
parse_reply() {
    tr -d '`' | awk '
        /^[[:space:]]*OPEN:/ { c = $0; gsub(/[^0-9]/, "", c); if (c != "") n = c; next }
        /^https?:\/\// || /^NONE/ { line = $0 }
        END { printf "%s\t%s\n", (n == "" ? "?" : n), (line == "" ? "ERR" : line) }'
}

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

cache_dir_of() { printf '%s/.cache/%s' "$SCRIPT_DIR" "$(printf '%s' "$1" | sha256sum | cut -c1-16)"; }

# The scan already took the picture, and before you press a button that says "a human looked" it
# is worth actually looking. Interactive + GUI only, so a looped or piped run is untouched.
# Offered whichever path produced the verdict: a ledger hit does no scan, but an earlier run may
# have left the screenshot behind (KEEP=1), and "if available" is the whole test.
offer_shot() {   # <url>
    local d s _a
    can_prompt || return 0
    command -v xdg-open >/dev/null 2>&1 || return 0
    d=$(cache_dir_of "$1")
    # The followed credential page / interstitial destination is the page worth seeing when there
    # is one -- the landing page is a marketing shell in exactly those cases. Same order
    # url-analyze.sh uses when it picks the shot the vision model reads.
    for s in "$d/login.jpg" "$d/redirect.jpg" "$d/page.jpg"; do [ -s "$s" ] && break; s=""; done
    [ -n "$s" ] || return 0
    read -r -p "${CYAN}Open the screenshot ($(basename "$s"))? [y/N] ${RESET}" _a
    [[ "$_a" =~ ^[Yy] ]] || return 0
    xdg-open "$s" >/dev/null 2>&1 &
    # The viewer reads the file after it starts, and the wipe below deletes it -- so wait for you
    # rather than race the image out from under it.
    [ "${WIPE:-0}" = 1 ] && read -r -p "${GREY}Enter when done (the cached page and screenshot are then wiped)${RESET}" _a
    return 0
}

# One live scan -> VERDICT + EVIDENCE. Leaves the artifacts in the cache: the inspection reads
# exactly those, and the wipe at the very end is what removes them.
run_scan() {
    SOURCE="fresh scan"
    # ponytail: no confirm before the live fetch. The whole point of this tool is "tell me which
    # button to click", and the ledger has already been asked -- an unsettled alert has exactly
    # one next step, so asking permission for it is a keypress that only ever answers Y.
    LOG=$(mktemp); trap 'rm -f "$LOG"' EXIT
    echo_grey "scanning (this fetches the live page, ~1-2 min)..."
    # stdin from /dev/null, deliberately. Four prompts in url-analyze.sh (bot-gate attach, open
    # screenshot, open in browser, "do you agree?") are gated on the TERMINAL (can_prompt) and not
    # on flags. With our stdout on a pipe, such a prompt is invisible and the whole thing looks
    # hung. Closing stdin makes every one of them self-disable.
    # It also means no ledger row is written from here, which is what we want: `inspected` has
    # to mean a human looked, and this tool exists precisely because one has not yet.
    # tee, not >, so a long scan visibly progresses instead of looking stuck.
    ./url-analyze.sh "${SCAN_FLAGS[@]}" "$URL" </dev/null 2>&1 | tee "$LOG"
    VERDICT=$(grep -oE 'VERDICT: (SAFE|SUSPICIOUS|DANGEROUS|UNCLEAR)' "$LOG" | tail -1 | awk '{print $2}')
    # The "Signals (N):" block is the scan's actual findings. Grepping every "- " line instead
    # scoops up progress chatter ("- Restarting existing Ollama container...") and reports it as
    # evidence, which is worse than showing nothing.
    EVIDENCE=$(awk '/^Signals \(/{f=1;print;next} f&&/^- /{print;next} f{exit}' "$LOG" | head -9)
    WIPE=1   # the wipe itself happens at the very end, after the offers below
}

# claude reads the CACHED artifacts and says what the page really is; it may correct VERDICT.
# Same prompt url-analyze.sh's `i` uses (inspect.sh), deliberately shared.
run_inspection() {
    local _cache _hostdir _smells _iout _iv
    INSPECTED=1
    _cache=$(cache_dir_of "$URL")
    # A verdict that came from the ledger did no scan, so there is nothing on disk to inspect --
    # and disagreeing with a settled row is exactly when you want this. Fetch first, then read.
    [ -s "$_cache/page.json" ] || { echo_grey "no cached artifacts to read -- scanning first"; run_scan; }
    _hostdir="$SCRIPT_DIR/.cache/host/$(printf '%s' "$URL" | sed -E 's#^[a-z]+://([^/]+).*#\1#' | tr -c 'a-zA-Z0-9.:_-' '_')"
    _smells=$(printf '%s' "${EVIDENCE:-}" | sed '1d;s/^- //' | paste -sd, -)
    if _iout=$(deep_inspect "$URL" "$URL" "${VERDICT:-UNCLEAR}" "$_smells" "$_cache" "$_hostdir" </dev/null); then
        RESOLVED=i   # spent, whatever it concluded -- a re-run would only repeat it
        _iv=$(inspect_verdict "$_iout"); INOTE=$(inspect_note "$_iout")
        ICAT=$(inspect_category "$_iout")
        # Only ever replace the verdict with one the inspection actually stated. An
        # unparseable reply leaves the scan's own verdict standing rather than inventing one.
        if [ -n "$_iv" ]; then
            [ "$_iv" != "$VERDICT" ] && { echo_cyan "inspection corrects $VERDICT -> $_iv"; settled=""; }
            VERDICT="$_iv"; SOURCE="$SOURCE + deep inspection${ICAT:+ ($ICAT)}"
        fi
    else
        echo_yellow "deep inspection unavailable -- keeping $VERDICT"
    fi
}

print_banner() {
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
    return 0
}

# A verdict you disagree with is the reason this offer exists: the scan says "False positive" and
# you can see that it is not one. Offered on ANY verdict -- SAFE and DANGEROUS included, which the
# automatic run above never touches -- and after the banner, so you decide with the button in
# front of you. It re-prints the banner, because the button is the thing that may change.
# Not offered when the inspection already ran this pass (it would only repeat itself), and never
# when nobody is watching.
offer_deep_scan() {
    local _a
    can_prompt && [ "${INSPECTED:-0}" != 1 ] || return 0
    read -r -p "${CYAN}Disagree? Run the deep inspection on this verdict [y/N] ${RESET}" _a
    [[ "$_a" =~ ^[Yy] ]] || return 0
    run_inspection
    print_banner
    record_inspection
}

# ponytail: retention. url-analyze only offers "keep the artifacts?" on a bare run, and we always
# pass flags, so nothing would ever ask -- and these URLs carry recipient tokens. feedback.txt
# survives, because a judgement is the one part a re-scan cannot regenerate. Called last on every
# path that fetched anything, so the deep inspection and the screenshot offer still have the
# artifacts they read -- including the replay path, where a disagreement can trigger a first scan.
wipe_artifacts() {
    local d
    [ "${WIPE:-0}" = 1 ] && [ "${KEEP:-0}" != "1" ] || return 0
    d=$(cache_dir_of "$URL")
    [ -d "$d" ] && find "$d" -mindepth 1 ! -name feedback.txt -delete 2>/dev/null
    return 0
}

# Record the answer in the seen-list so the next pass can repeat it instead of re-doing the work.
# A SAFE or DANGEROUS is final on its own; a Skip only counts as final once the inspection has been
# spent, otherwise the next pass must pick it back up rather than replay an unfinished result.
record_seen() {
    [ "$FROM_SLACK" = 1 ] || return 0
    case "${VERDICT:-UNCLEAR}" in SAFE|DANGEROUS) RESOLVED=i ;; esac
    printf '%s\t%s\t%s\t%s\n' "${VERDICT:-UNCLEAR}" "${RESOLVED:-}" "$URL" \
        "$(printf '%s' "${INOTE:-}" | tr '\t\n' '  ')" >>"$SEEN"
}

# A correction only sticks if it is written down: an `inspected` row is what --settled replays,
# what the next scan reports in its own banner, and what the weekly corpus scores against. This
# tool writes no ledger rows anywhere else, on purpose -- but here a human asked for the
# inspection and is reading its answer, which is precisely what `inspected` means.
record_inspection() {
    local _a
    can_prompt && [ -n "${INOTE:-}" ] || return 0
    read -r -p "${CYAN}Record ${VERDICT}${ICAT:+ ($ICAT)} in the ledger as the settled verdict? [y/N] ${RESET}" _a
    [[ "$_a" =~ ^[Yy] ]] || return 0
    FB_VERDICT="$VERDICT" FB_CATEGORY="${ICAT:-}" ./feedback-report.sh -i "$URL" "$INOTE"
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
    _pr() { [ "$(printf '%s' "$2" | parse_reply)" = "$1" ] || { echo "FAIL parse_reply [$2] -> [$(printf '%s' "$2" | parse_reply)] want [$1]"; exit 1; }; }
    _pr "3	https://x/?a=1" "$(printf 'OPEN: 3\nhttps://x/?a=1')"
    _pr "0	NONE: Sam marked this Verify phish" "$(printf 'OPEN: 0\nNONE: Sam marked this Verify phish')"
    _pr "?	ERR" ""                                            # logged out: nothing on stdout
    _pr "?	ERR" "Invalid API key . Please run /login"          # logged out, but chatty
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

# A rule across the terminal, first thing, so a run on a loop is visibly separate from the last
# one. Before the Slack read, so everything a run prints sits under its own line.
_w=${COLUMNS:-$(tput cols 2>/dev/null)}; printf '%*s\n' "${_w:-80}" '' | tr ' ' '-' \
    | sed "s/^/${GREY}/;s/\$/${RESET}/"

URL=""; FROM_SLACK=0; ALL=0; RESOLVED=""
[ "${1:-}" = "-a" ] && { ALL=1; shift; }
if [ "${1:-}" = "-u" ]; then
    URL="${2:?-u needs a url}"
else
    FROM_SLACK=1
    command -v claude >/dev/null 2>&1 || { echo_red "need 'claude' on PATH to read Slack"; exit 1; }
    CHANNELS=("$@"); [ ${#CHANNELS[@]} -eq 0 ] && CHANNELS=("$DM_CHANNEL" "$VERIFY_CHANNEL")
    for CHANNEL in "${CHANNELS[@]}"; do
        echo_grey "reading $CHANNEL for an alert nobody has ruled on..."
        _reply=$(read_channel "$CHANNEL")
        OPEN_N="${_reply%%$'\t'*}"; URL="${_reply#*$'\t'}"
        # Keep the last channel's "NONE: ..." so the empty-queue line below can name the verdict
        # it saw. The DM answering NONE and the channel answering NONE are both worth reporting;
        # the one printed is the last channel actually read.
        case "$URL" in NONE*) LAST_RULED="${URL#NONE}"; LAST_RULED="${LAST_RULED#:}" ;; esac
        # A failed read is not an empty queue. Stop here rather than fall through to the
        # "nothing waiting" line, which is what this looked like for a whole logged-out day.
        [ "$URL" = ERR ] && {
            echo_red "could not read Slack ($CHANNEL) -- the queue is UNKNOWN, not empty"
            echo_grey "  headless 'claude -p' returned nothing usable; usually it is logged out."
            echo_grey "  run 'claude' and then /login, then try again."
            exit 1
        }
        case "$URL" in NONE*|"") ;; *) break ;; esac
    done

    # How deep the queue is. One alert per invocation is fine; not knowing there are twenty-three
    # behind it is not -- that is how a backlog stops being merely long and becomes invisible.
    case "$OPEN_N" in
        ""|0|1|"?") ;;
        *) echo_yellow "  $OPEN_N open in this channel -- this is the newest; run again for the next" ;;
    esac
    # LUCA's extractor swallows trailing punctuation from the source mail (seen: "yhopecn.com/)")
    URL="${URL%)}"
fi

case "${URL:-NONE}" in NONE*)
    # Name what the newest alert was ruled. "Nothing waiting" on its own is the same sentence a
    # broken Slack read would produce, and the two need opposite reactions from you.
    _lr=$(printf '%s' "${LAST_RULED:-}" | sed 's/^ *//; s/ *$//')
    echo_green "nothing waiting -- every alert already has a verdict${_lr:+  [$_lr]}"
    [ -n "$_lr" ] || echo_grey "  (Slack answered, but did not say what the last verdict was)"
    exit 0
esac

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
        # Same banner and the same two offers as a fresh run: a replayed answer is exactly the
        # one you are most likely to disagree with, because nothing new was looked at to produce it.
        VERDICT="$_prev"; SOURCE="the earlier run (inspected); no new alert has arrived since"
        INOTE=$(seen_field "$URL" n)
        print_banner
        offer_shot "$URL"
        offer_deep_scan
        # Only write a row when the inspection actually ran -- otherwise this is a replay of an
        # answer that is already in the file, and appending it again says nothing new.
        [ "${INSPECTED:-0}" = 1 ] && { wipe_artifacts; record_seen; }
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
    run_scan
    # SUSPICIOUS and UNCLEAR both map to Skip, which hands the work straight back to you. So
    # before giving up, spend the deep inspection automatically.
    case "${VERDICT:-UNCLEAR}" in SUSPICIOUS|UNCLEAR|"")
        echo ""
        echo_grey "verdict is a Skip -- running the deep inspection instead of handing it back..."
        run_inspection ;;
    esac
fi

print_banner
offer_shot "$URL"

offer_deep_scan

wipe_artifacts
record_seen
echo ""
echo_grey "nothing was clicked or posted -- that is yours to do"
# Say "scanned" only when something was actually fetched; the ledger path touches no network.
case "$SOURCE" in *scan*) echo "scanned: $URL" ;; *) echo "alert: $URL" ;; esac
