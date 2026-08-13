#!/usr/bin/env bash
# Harvest the verdicts analysts have already recorded in Slack back into the ledger.
#
# When somebody clicks "Verify phish" or "False positive" on a LUCA alert, the bot rewrites its
# own message in place with a "Recorded: <user> marked this <phishing|clean>" line. That is a real
# human judgement on a real URL -- exactly what `inspected` is supposed to mean -- and today it
# exists only in Slack. The ledger never learns it, --settled cannot answer with it, and the
# weekly replay never scores against it.
#
# This reads those lines and writes them through `feedback-report.sh -i`, which already owns every
# rule about how a row is formed. Nothing here writes to feedback.txt directly.
#
#   ./slack-harvest.sh -n          # show what WOULD be written, touch nothing (do this first)
#   ./slack-harvest.sh             # harvest the DM and the shared alerts channel
#   ./slack-harvest.sh C099U43SRS5 # one channel
#   ./slack-harvest.sh --self-test
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source "$SCRIPT_DIR/colors.sh"

CHANNELS=(D0BAMTCJE7K C099U43SRS5)   # Holden's LUCA DM, then the shared alerts channel
SEEN="$SCRIPT_DIR/.cache/slack-harvest-seen.txt"
LIMIT="${LIMIT:-60}"

# LUCA's two words -> our severity. "phishing" means the analyst confirmed it is bad; it does NOT
# say WHAT it is, so no category is guessed here -- a category is a claim, and a button press is
# not evidence for one. An unknown word is skipped rather than guessed at.
verdict_for() {
    case "$1" in
        phishing) echo DANGEROUS ;;
        clean)    echo SAFE ;;
        *)        echo "" ;;
    esac
}

if [ "${1:-}" = "--self-test" ]; then
    _f=0
    [ "$(verdict_for phishing)" = DANGEROUS ] || { echo "FAIL phishing"; _f=1; }
    [ "$(verdict_for clean)" = SAFE ]         || { echo "FAIL clean"; _f=1; }
    [ -z "$(verdict_for skipped)" ]           || { echo "FAIL unknown word must not map"; _f=1; }
    [ -z "$(verdict_for '')" ]                || { echo "FAIL empty must not map"; _f=1; }
    # The parse must survive the real message shape: a URL in backticks and a <@U..|name> mention.
    _line=$(printf '1786594703.969619\tphishing\tsamg\thttps://x.example/a?b=c')
    IFS=$'\t' read -r _ts _v _u _url <<<"$_line"
    [ "$_ts" = 1786594703.969619 ] && [ "$_v" = phishing ] && [ "$_u" = samg ] \
        && [ "$_url" = "https://x.example/a?b=c" ] || { echo "FAIL tsv parse"; _f=1; }
    [ "$_f" = 0 ] && echo "self-test ok"; exit "$_f"
fi

DRY=""
[ "${1:-}" = "-n" ] && { DRY=1; shift; }
[ $# -gt 0 ] && CHANNELS=("$@")
command -v claude >/dev/null 2>&1 || { echo_red "need 'claude' on PATH to read Slack"; exit 1; }

_new=0 _skipped=0
for ch in "${CHANNELS[@]}"; do
    echo_grey "reading $ch..."
    # Ask for TSV rather than prose: this feeds a ledger write, and a free-text answer would need
    # parsing that fails silently. detailed format, because concise omits the message ts and the
    # ts is the dedupe key -- one Slack ruling harvested once, even if the URL recurs.
    rows=$(claude -p "Read Slack channel $ch (limit $LIMIT, response_format detailed).
For EVERY message that contains a line matching 'Recorded: <@...|NAME> marked this *WORD*',
output one tab-separated line:
<message ts><TAB><WORD><TAB><NAME><TAB><the alert URL from that same message>
The URL is the one in backticks on the 'Phishing alert' line. Strip the backticks.
Output nothing else -- no header, no commentary, no markdown. If there are none, output nothing." \
        --allowedTools "mcp__claude_ai_Slack__slack_read_channel" 2>/dev/null)

    while IFS=$'\t' read -r ts word who url; do
        [ -z "${url:-}" ] && continue
        url="${url%\)}"          # LUCA's extractor swallows trailing punctuation ("yhopecn.com/)")
        v=$(verdict_for "$word")
        if [ -z "$v" ]; then
            echo_grey "  skip (unmapped '$word'): $url"; _skipped=$((_skipped+1)); continue
        fi
        if [ -f "$SEEN" ] && grep -qxF "$ts" "$SEEN"; then continue; fi
        printf '  %s%-9s%s %s %s(%s in %s)%s\n' \
            "$([ "$v" = DANGEROUS ] && printf '%s' "$RED" || printf '%s' "$GREEN")" "$v" "$RESET" \
            "$url" "$GREY" "$who" "$ch" "$RESET"
        if [ -z "$DRY" ]; then
            # FB_EXTERNAL: a Slack ruling has no cached scan and never will -- the analyst looked
            # at the live URL, not at our artifacts. feedback-report.sh owns the row format.
            FB_EXTERNAL=1 FB_VERDICT="$v" ./feedback-report.sh -i "$url" \
                "recorded in Slack by @$who on a LUCA alert (no local scan)" >/dev/null \
                && { mkdir -p "$SCRIPT_DIR/.cache"; printf '%s\n' "$ts" >>"$SEEN"; _new=$((_new+1)); } \
                || echo_red "  write failed: $url"
        else
            _new=$((_new+1))
        fi
    done <<<"$rows"
done

echo ""
if [ -n "$DRY" ]; then
    echo_yellow "dry run: $_new row(s) would be written, $_skipped skipped. Re-run without -n to apply."
else
    echo_green "harvested $_new ruling(s) into the ledger${_skipped:+, $_skipped skipped}"
    echo_grey "these now answer ./feedback-report.sh --settled and appear in --corpus"
fi
