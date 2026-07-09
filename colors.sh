#!/bin/bash

# Shared ANSI colors + echo_* helpers for every tool in the repo.
# Source it AFTER argument parsing (so MONO is known):
#   source "$SCRIPT_DIR/colors.sh"
#
# Color is emitted ONLY when stdout is a terminal AND color isn't disabled. Disable via:
#   -c mono   (the tool sets MONO=1 before sourcing this)
#   NO_COLOR  (env, https://no-color.org)
#   a non-terminal stdout (piped / captured), so machine-parsed output stays plain ASCII.
if [ -t 1 ] && [ -z "${MONO:-}" ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
    BLUE=$'\033[34m'; CYAN=$'\033[36m'; GREY=$'\033[90m'
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' GREY='' BOLD='' DIM='' RESET=''
fi

# cecho <color> <text...>  -> echo text wrapped in the given color var.
cecho() { local c="$1"; shift; echo "${c}$*${RESET}"; }

# Named shortcuts so call sites read as intent (echo_red "..."). No-ops for color when
# disabled above -- the vars are empty, so these just echo plain text.
echo_red()    { echo "${RED}$*${RESET}"; }
echo_green()  { echo "${GREEN}$*${RESET}"; }
echo_yellow() { echo "${YELLOW}$*${RESET}"; }
echo_blue()   { echo "${BLUE}$*${RESET}"; }
echo_cyan()   { echo "${CYAN}$*${RESET}"; }
echo_grey()   { echo "${GREY}$*${RESET}"; }
echo_bold()   { echo "${BOLD}$*${RESET}"; }
