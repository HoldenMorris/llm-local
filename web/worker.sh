#!/usr/bin/env bash
#
# The host half of the web UI. The other half is a container that serves HTML and never runs
# anything.
#
# WHY THE SPLIT. The web server runs in Docker so nothing new has to be installed on this machine.
# But the toolkit it wraps runs *here*: url-analyze.sh needs docker, dig, openssl, jq, curl, bc and
# claude, and page-fetch.sh launches sibling containers with host paths. A container could reach
# all of that by mounting /var/run/docker.sock -- which is root-equivalent on the host, handed to
# the one process in this repo that renders attacker-controlled strings. So instead the container
# asks, and this script decides.
#
# THIS SCRIPT IS THE SECURITY BOUNDARY, and it works by never trusting the request. The container
# does not send a command line; it sends a **kind** and a few named values. This script owns the
# whitelist -- which scripts may run, which flags they may carry, what a url is allowed to look
# like -- and builds the argv itself. There is no path here by which a value from the request
# becomes the name of a program, and no `eval`, no `sh -c`, no word-splitting of anything that
# came in over the wire.
#
# One job at a time falls out for free: this is one bash loop. Ollama, the scan container and the
# append-only ledger are all single-tenant, so that is the correct concurrency anyway.
#
#   ./web/worker.sh              # run it (foreground; web/up.sh starts it beside the container)
#   ./web/worker.sh --self-test  # the whitelist tests: pure, no network, no docker
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source "$SCRIPT_DIR/colors.sh"
source "$SCRIPT_DIR/verdict.sh"   # is_category: the category vocabulary has one owner

JOBS="$SCRIPT_DIR/.cache/web-jobs"
POLL="${WORKER_POLL:-0.25}"

# A scan can chain a page fetch (PAGE_TIMEOUT, 180s), a followed login link, a followed
# interstitial, a ~50s vision call and an LLM verdict, so the ceiling sits above the sum of those
# rather than above any one. It still has to exist: a hung container otherwise holds this loop,
# and this loop is the whole application's concurrency.
CEILING="${WORKER_CEILING:-900}"

# --- the whitelist -------------------------------------------------------------------------
#
# Flags a scan may carry. Everything else in a request is dropped in silence -- the container is
# not an authority on what is safe to run, so a rejected flag is not an error worth reporting to
# it. Deliberately absent: -p/-g (tor egress) and -m claude-* are opt-in operator decisions that
# spend money or change egress, and they stay on the command line until somebody asks for them.
SCAN_FLAGS_OK=" -t -r -V -H -D -s "

# is_url <s> -> a url this toolkit will accept as an argument.
# The scheme test is not decoration: getopts stops at the first non-option argument, so a value
# beginning with "-" would be read as a flag. Requiring a scheme makes that impossible, and http
# and https are the only two the scanner fetches anyway.
is_url() {
    case "$1" in
        http://?*|https://?*) ;;
        *) return 1 ;;
    esac
    # Whitespace and control characters only. Both are absent from any real url unencoded, and a
    # newline in particular must never reach the log or state files that carry the job protocol.
    #
    # Shell metacharacters are deliberately NOT rejected. `&`, `;`, `|`, `$` and backticks are
    # ordinary in a query string, the argv here is a bash array handed straight to exec, and there
    # is no point at which it becomes a shell string -- so blacklisting them bought nothing and
    # refused most real phishing urls, every tracking link among them. The first live scan through
    # the web UI was rejected for containing `&`.
    case "$1" in
        *[[:space:]]*|*[[:cntrl:]]*) return 1 ;;
    esac
    [ "${#1}" -le 2000 ]
}

# is_word <s> -> a bare identifier: model names, categories, verdicts, hosts, campaign tags.
is_word() { case "$1" in ""|*[!a-zA-Z0-9._:@=-]*) return 1 ;; *) [ "${#1}" -le 200 ] ;; esac; }

# build_argv <kind> -> fills the global ARGV array, or returns 1 with REASON set.
# Every branch names its script literally. Nothing from the request is ever ARGV[0].
build_argv() {
    ARGV=(); REASON=""
    case "$1" in
        scan)
            is_url "$R_url" || { REASON="not an http(s) url"; return 1; }
            ARGV=(./url-analyze.sh -c mono)
            # $R_flags is split on whitespace ON PURPOSE and then matched against the whitelist
            # above, so an unknown token cannot survive to reach the script.
            local f
            for f in $R_flags; do
                case "$SCAN_FLAGS_OK" in *" $f "*) ARGV+=("$f") ;; esac
            done
            if [ -n "$R_model" ]; then
                is_word "$R_model" || { REASON="bad model name"; return 1; }
                case "$R_model" in claude*) REASON="the anthropic backend is cli-only"; return 1 ;; esac
                ARGV+=(-m "$R_model")
            fi
            ARGV+=(-j "$R_url")
            ;;
        settled)
            is_url "$R_url" || { REASON="not an http(s) url"; return 1; }
            ARGV=(./feedback-report.sh --settled "$R_url")
            ;;
        report)  ARGV=(./feedback-report.sh --json) ;;
        prose)   ARGV=(./feedback-report.sh) ;;
        flags)   ARGV=(./feedback-report.sh -f) ;;
        corpus)  ARGV=(./feedback-report.sh --corpus) ;;
        rollup)
            is_word "$R_key" || { REASON="bad rollup key"; return 1; }
            case "$R_scope" in
                host|apex|campaign) ARGV=(./feedback-report.sh "--$R_scope" "$R_key") ;;
                *) REASON="unknown rollup scope"; return 1 ;;
            esac
            ;;
        # WRITING. The only kind that changes anything, and it goes through feedback-report.sh -i
        # like every other writer in this repo -- slack-harvest.sh already does, and the row format
        # having exactly one owner is what stops two writers drifting apart.
        #
        # The verdict and category are checked against fixed lists HERE rather than trusted from
        # the form: a category outside VERDICT_CATEGORIES is a row that will not group when the
        # ledger is mined later, and a bogus verdict is one the replay corpus cannot score.
        record)
            is_url "$R_url" || { REASON="not an http(s) url"; return 1; }
            case "$R_verdict" in
                SAFE|SUSPICIOUS|DANGEROUS) ;;
                *) REASON="verdict must be SAFE, SUSPICIOUS or DANGEROUS"; return 1 ;;
            esac
            if [ -n "$R_category" ]; then
                is_category "$R_category" || { REASON="not a known category"; return 1; }
            fi
            # A note is free text a human typed; only its length and its newlines are our business,
            # because the ledger is one row per line.
            R_note=$(printf '%s' "$R_note" | tr '\t\n\r' '   ' | cut -c1-500)
            [ -n "$R_note" ] || { REASON="a recorded verdict needs a note saying what you found"; return 1; }
            ARGV=(env "FB_VERDICT=$R_verdict" "FB_CATEGORY=$R_category" ./feedback-report.sh -i "$R_url" "$R_note")
            ;;
        # The deep inspection: claude -p reads the CACHED artifacts of one scan, read-only, no live
        # fetch. Its own prompt lives in inspect.sh, shared with url-analyze.sh so the two callers
        # cannot start disagreeing about the same page.
        inspect)
            is_url "$R_url" || { REASON="not an http(s) url"; return 1; }
            ARGV=(./inspect-one.sh "$R_url")
            ;;
        *) REASON="unknown job kind"; return 1 ;;
    esac
    return 0
}

# --- running -----------------------------------------------------------------------------------

run_job() {   # <id>
    local id="$1" req="$JOBS/$1.req" kind rc
    kind=$(jq -r '.kind // ""' "$req" 2>/dev/null)
    R_url=$(jq -r '.url // ""' "$req" 2>/dev/null)
    R_flags=$(jq -r '.flags // ""' "$req" 2>/dev/null)
    R_model=$(jq -r '.model // ""' "$req" 2>/dev/null)
    R_scope=$(jq -r '.scope // ""' "$req" 2>/dev/null)
    R_key=$(jq -r '.key // ""' "$req" 2>/dev/null)
    R_verdict=$(jq -r '.verdict // ""' "$req" 2>/dev/null)
    R_category=$(jq -r '.category // ""' "$req" 2>/dev/null)
    R_note=$(jq -r '.note // ""' "$req" 2>/dev/null)

    if ! build_argv "$kind"; then
        printf 'refused: %s\n' "$REASON" > "$JOBS/$id.log"
        echo refused > "$JOBS/$id.state"
        echo 64 > "$JOBS/$id.rc"
        echo_yellow "  refused $id ($kind): $REASON"
        return
    fi

    echo running > "$JOBS/$id.state"
    echo_grey "  run $id: ${ARGV[*]}"
    # Both streams into one log, in the order they happened -- a scan's narration is on stdout and
    # its floor notice on stderr, and reading them apart loses which came first.
    # stdin from /dev/null: can_prompt() asks whether a human is watching a terminal, not whether
    # flags were passed, so a script that would have asked a question skips it instead of hanging.
    timeout --foreground -k 5 "$CEILING" "${ARGV[@]}" </dev/null >"$JOBS/$id.log" 2>&1
    rc=$?
    echo "$rc" > "$JOBS/$id.rc"
    case "$rc" in
        0)   echo done    > "$JOBS/$id.state" ;;
        124) echo timeout > "$JOBS/$id.state"; printf -- '-- killed after %ss --\n' "$CEILING" >> "$JOBS/$id.log" ;;
        *)   echo failed  > "$JOBS/$id.state" ;;
    esac
}

# --- self-test: ./web/worker.sh --self-test ------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
    p=0; f=0
    R_url=""; R_flags=""; R_model=""; R_scope=""; R_key=""
    t() {  # t <name> <expected argv, space-joined>
        local name="$1" want="$2"; shift 2
        if build_argv "$KIND"; then got="${ARGV[*]}"; else got="REFUSED:$REASON"; fi
        if [ "$got" = "$want" ]; then p=$((p+1)); printf 'ok   %s\n' "$name"
        else f=$((f+1)); printf 'FAIL %s\n       want [%s]\n       got  [%s]\n' "$name" "$want" "$got"; fi
    }

    KIND=scan; R_url="https://example.com/x"; R_flags=""; R_model=""
    t "plain scan" "./url-analyze.sh -c mono -j https://example.com/x"

    R_flags="-t -V"; R_model="qwen2.5:1.5b"
    t "whitelisted flags and model" "./url-analyze.sh -c mono -t -V -m qwen2.5:1.5b -j https://example.com/x"

    # The container is not an authority on what may run. An unknown flag is dropped, not obeyed.
    R_flags="-t --evil -p tor -rf"; R_model=""
    t "unknown flags are dropped" "./url-analyze.sh -c mono -t -j https://example.com/x"

    # A value must never become a program, an option, or a second command.
    R_flags=""; R_url="-rf /"
    t "a url that is really a flag" "REFUSED:not an http(s) url"
    # These characters are ORDINARY in a url and must survive: the argv is an array, never a shell
    # string, and refusing them refused every tracking link this toolkit exists to read.
    R_url="http://1.2.3.4/wado?requestType=WADO&studyUID=void&objectUID=1.3.6"
    t "ampersands in a query string" "./url-analyze.sh -c mono -j http://1.2.3.4/wado?requestType=WADO&studyUID=void&objectUID=1.3.6"
    R_url="https://x.com/a;b\$c|d\`e\`"
    t "metacharacters are not a shell here" "./url-analyze.sh -c mono -j https://x.com/a;b\$c|d\`e\`"
    R_url="https://x.com/p?u=a%20b&t=1#frag"
    t "percent-encoding and a fragment" "./url-analyze.sh -c mono -j https://x.com/p?u=a%20b&t=1#frag"

    R_url="file:///etc/passwd"
    t "non-http scheme" "REFUSED:not an http(s) url"
    R_url="https://x.com/$(printf 'a\tb')"
    t "a tab in a url" "REFUSED:not an http(s) url"
    R_url="https://x.com/a b"
    t "a space in a url" "REFUSED:not an http(s) url"
    R_url="$(printf 'https://x.com/a\nfake: line')"
    t "a newline in a url" "REFUSED:not an http(s) url"

    R_url="https://example.com/x"; R_model="../../bin/sh"
    t "path traversal as a model name" "REFUSED:bad model name"
    R_model="claude-opus-4-8"
    t "the paid backend stays cli-only" "REFUSED:the anthropic backend is cli-only"

    R_model=""
    KIND=rollup; R_scope="campaign"; R_key="s1=upg12"
    t "campaign rollup" "./feedback-report.sh --campaign s1=upg12"
    R_scope="../../etc"
    t "rollup scope is an enum" "REFUSED:unknown rollup scope"
    R_scope="host"; R_key="a b; rm -rf /"
    t "rollup key is a bare word" "REFUSED:bad rollup key"

    KIND=report; t "report takes no input" "./feedback-report.sh --json"

    # Recording is the one kind that writes. It goes through feedback-report.sh -i, and the
    # vocabulary is checked here rather than trusted from the form.
    KIND=record; R_url="https://example.com/x"; R_verdict="DANGEROUS"; R_category="phishing"; R_note="credential form"
    t "record a correction" "env FB_VERDICT=DANGEROUS FB_CATEGORY=phishing ./feedback-report.sh -i https://example.com/x credential form"
    R_verdict="TOTALLY BAD"
    t "verdict is an enum" "REFUSED:verdict must be SAFE, SUSPICIOUS or DANGEROUS"
    R_verdict="DANGEROUS"; R_category="made-up-thing"
    t "category must be in the vocabulary" "REFUSED:not a known category"
    R_category="phishing"; R_note=""
    t "a recorded verdict needs a note" "REFUSED:a recorded verdict needs a note saying what you found"
    R_note="$(printf 'line one\nRecorded: forged row')"
    t "a newline cannot forge a second ledger row" "env FB_VERDICT=DANGEROUS FB_CATEGORY=phishing ./feedback-report.sh -i https://example.com/x line one Recorded: forged row"
    R_note="ok"; R_url="-rf /"
    t "record still checks the url" "REFUSED:not an http(s) url"
    KIND=exec;   t "unknown kind" "REFUSED:unknown job kind"
    KIND="";     t "empty kind" "REFUSED:unknown job kind"

    echo; echo "passed $p, failed $f"; [ "$f" -eq 0 ]; exit $?
fi

# --- the loop ------------------------------------------------------------------------------------
mkdir -p "$JOBS"
echo_bold "scope worker"
echo_grey "  watching $JOBS"
echo_grey "  one job at a time, ${CEILING}s ceiling. ctrl-c to stop."
echo ""

# The heartbeat has to keep ticking WHILE a job runs, not only between jobs. The loop below blocks
# for as long as a scan takes -- up to the 900s ceiling -- and a heartbeat that only updated at the
# top of the loop made a busy worker indistinguishable from a dead one, which is the exact
# confusion the heartbeat exists to remove. So it gets its own ticker: it means "this process is
# alive", and the job states next to it already say whether anything is running.
( while :; do : > "$JOBS/heartbeat"; sleep 5; done ) &
HEARTBEAT=$!

trap 'kill "$HEARTBEAT" 2>/dev/null; echo ""; echo_grey "worker stopped"; exit 0' INT TERM EXIT

while true; do
    # Oldest request first, so the queue is the order things were asked for. A request is claimed
    # by renaming it, which is atomic on the same filesystem -- so a second worker started by
    # accident takes different work rather than the same work twice.
    found=""
    for req in $(ls -tr "$JOBS"/*.req 2>/dev/null); do
        id=$(basename "$req" .req)
        mv -n "$req" "$JOBS/$id.claimed" 2>/dev/null || continue
        [ -f "$JOBS/$id.claimed" ] || continue
        mv "$JOBS/$id.claimed" "$JOBS/$id.req"
        found=1
        run_job "$id"
        mv "$JOBS/$id.req" "$JOBS/$id.done-req" 2>/dev/null
        break
    done
    [ -n "$found" ] || sleep "$POLL"
done
