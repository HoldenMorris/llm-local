#!/bin/bash

# Mine analyst feedback (url-analyze.sh's "Do you agree?" prompt) into a review report.
# Reads every .cache/*/feedback.txt (TSV: timestamp <TAB> verdict <TAB> agree|disagree|skip <TAB> url),
# prints agreement rate per verdict and lists the disagreements -- the cases worth tuning.
#   ./feedback-report.sh           # human report
#   ./feedback-report.sh -c mono   # no color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ "$1" = "-c" ] && [ "$2" = "mono" ] && { MONO=1; shift 2; }
source "$SCRIPT_DIR/colors.sh"

shopt -s nullglob
FILES=("$SCRIPT_DIR"/.cache/*/feedback.txt)
[ ${#FILES[@]} -eq 0 ] && { echo_grey "No feedback yet (.cache/*/feedback.txt empty)."; exit 0; }

cat "${FILES[@]}" | awk -F'\t' -v R="$RED" -v G="$GREEN" -v Y="$YELLOW" -v C="$CYAN" -v GY="$GREY" -v B="$BOLD" -v X="$RESET" '
NF < 4 { next }
{ tot++; v=$2; fb=$3
  seen[v]++
  if (fb=="agree")    { agree++;    aV[v]++ }
  else if (fb=="disagree") { dis[v]++; disN++; DL[disN]=$1" "v" "$4 }
  else                skipN++
}
END {
  if (tot==0) { print GY "No parseable feedback rows." X; exit }
  printf "%s%s== Analyst feedback: %d responses ==%s\n", B, C, tot, X
  printf "  %sagree %d   disagree %d   skip %d%s\n\n", GY, agree+0, disN+0, skipN+0, X
  print B "Agreement by verdict" X
  for (v in seen) {
    scored = aV[v]+dis[v]        # skips excluded from the rate
    rate = scored ? (100*aV[v]/scored) : 0
    col = (dis[v] ? Y : G)
    printf "  %s%-10s%s %s%3d%%%s agree  (%d agree, %d disagree, %d total)\n", B, v, X, col, rate, X, aV[v]+0, dis[v]+0, seen[v]
  }
  if (disN) {
    printf "\n%s%sDisagreements (retune these)%s\n", B, R, X
    for (i=1;i<=disN;i++) print "  " R "x" X " " DL[i]
  }
}'
