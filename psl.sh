#!/bin/bash

# Public Suffix List helper. Source it, then call apex_of <host>.
# Run it directly (./psl.sh) to execute the self-check at the bottom.
#
# Why this exists: "last two labels" is wrong whenever the public suffix has two or more labels.
# smithpower.autoit.za.com resolved to an apex of "za.com" -- but za.com is a CentralNic shared
# namespace anyone can register under, so the RDAP age lookup reported za.com's 1998 registration:
# a 28-year "aged domain, low risk" reading for a name that could have been bought this morning.
# The same hole covers *.us.com, *.uk.com, *.eu.com, *.ddns.net, *.hopto.org, *.herokuapp.com and
# roughly 9000 other shared namespaces. Under-counting a domain's youth is a false NEGATIVE, which
# is the expensive direction, so this is one of the places not to be lazy.
#
# ponytail: no vendored copy and no hand-curated subset -- both rot silently, and a stale phishing
# heuristic is worse than none. Cache the real list and refresh it monthly.

PSL_URL="https://publicsuffix.org/list/public_suffix_list.dat"
PSL_FILE="${PSL_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.cache/public_suffix_list.dat}"
PSL_MAX_AGE_DAYS="${PSL_MAX_AGE_DAYS:-30}"

# psl_ensure -> exit 0 if a usable list is on disk, refreshing it when older than
# PSL_MAX_AGE_DAYS. Never fails the caller: a stale list beats no list, and no list at all just
# drops apex_of back to the old heuristic.
psl_ensure() {
    [ -s "$PSL_FILE" ] && [ -z "$(find "$PSL_FILE" -mtime +"$PSL_MAX_AGE_DAYS" 2>/dev/null)" ] && return 0
    mkdir -p "$(dirname "$PSL_FILE")" 2>/dev/null
    # Download to a temp path first: a truncated or failed fetch must never replace a good list.
    if curl -sf --max-time 20 "$PSL_URL" -o "$PSL_FILE.tmp" 2>/dev/null && [ -s "$PSL_FILE.tmp" ]; then
        mv -f "$PSL_FILE.tmp" "$PSL_FILE"
    else
        rm -f "$PSL_FILE.tmp" 2>/dev/null
    fi
    [ -s "$PSL_FILE" ]
}

# suffix_of <host> -> the public suffix: the tail NOBODY registers (com, co.uk, github.io,
# s3.us-east-1.amazonaws.com). Everything a brand or entropy check may judge lies to its left --
# see head_of. apex_of is this plus the one label below it.
suffix_of() {
    local host="${1,,}"
    host="${host%.}"
    [ -z "$host" ] && return 0

    if ! psl_ensure; then
        # Fallback = the pre-PSL heuristic's implied suffix: a known ccTLD second level (co.uk),
        # else the last label. apex_of below then rebuilds exactly what it used to return, so
        # losing the list still changes nothing else.
        if printf '%s' "$host" | grep -qE '\.(co|com|net|org|ac|gov|edu|ne|or|in)\.[^.]+$'; then
            printf '%s' "$host" | grep -oE '[^.]+\.[^.]+$'
        else
            printf '%s' "$host" | grep -oE '[^.]+$'
        fi
        return 0
    fi

    # Longest matching rule wins, so walk the candidates longest-first and stop at the first hit.
    # ponytail: a few grep passes over a 16k-line file (~100ms worst case, once per scan) next to a
    # ~50s vision call. Load it into an associative array only if that ever shows up in a profile.
    local rest="$host" up suffix=""
    while [ -n "$rest" ]; do
        case "$rest" in *.*) up="${rest#*.}" ;; *) up="" ;; esac
        # Exception rule (!city.kawasaki.jp): the suffix is one label SHORTER than the rule.
        if grep -qxF "!$rest" "$PSL_FILE"; then suffix="$up"; break; fi
        # Normal rule (za.com), or a wildcard one label up (*.ck makes every foo.ck a suffix).
        if grep -qxF "$rest" "$PSL_FILE" || { [ -n "$up" ] && grep -qxF "*.$up" "$PSL_FILE"; }; then
            suffix="$rest"; break
        fi
        rest="$up"
    done
    # No rule matched: the PSL's implicit "*" rule makes the last label the suffix.
    [ -z "$suffix" ] && suffix="${host##*.}"
    printf '%s' "$suffix"
}

# head_of <host> -> the host with its public suffix removed: the part the REGISTRANT chose, and
# the ONLY part a brand or entropy check may judge. `wfse.s3.us-east-1.amazonaws.com` is `wfse`,
# not `wfses3useast1amazonaws` -- gluing the provider's own labels on manufactured both a fake
# amazon typosquat and a fake random domain out of an ordinary S3 bucket. Empty when the host IS
# a public suffix, because then the registrant chose nothing.
head_of() {
    local host="${1,,}" suffix
    host="${host%.}"
    [ -z "$host" ] && return 0
    suffix=$(suffix_of "$host")
    [ "$suffix" = "$host" ] && return 0
    printf '%s' "${host%.$suffix}"
}

# apex_of <host> -> the registrable domain: the public suffix plus the one label below it.
# Echoes the host unchanged when the host IS a public suffix (za.com, github.io, co.uk) -- there
# is no registrable domain there, and a caller must not read that as an owned apex.
apex_of() {
    local host="${1,,}" suffix head
    host="${host%.}"
    [ -z "$host" ] && return 0
    suffix=$(suffix_of "$host")
    [ "$suffix" = "$host" ] && { printf '%s' "$host"; return 0; }
    head="${host%.$suffix}"
    printf '%s.%s' "${head##*.}" "$suffix"
}

# --- self-check: ./psl.sh -------------------------------------------------------------------
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    p=0 f=0
    t() { # t <host> <expected apex>
        local got; got=$(apex_of "$1")
        if [ "$got" = "$2" ]; then p=$((p+1)); printf 'ok   %-38s -> %s\n' "$1" "$got"
        else f=$((f+1)); printf 'FAIL %-38s -> %s (want %s)\n' "$1" "$got" "$2"; fi
    }
    psl_ensure || echo "WARN: no public suffix list available - testing the fallback path only"
    t smithpower.autoit.za.com  autoit.za.com   # the miss this fixes: was za.com (28y "aged")
    t evil.us.com               evil.us.com     # CentralNic shared namespaces, same shape
    t login.paypal.uk.com       paypal.uk.com
    t kit.ddns.net              kit.ddns.net    # dynamic-DNS namespaces are shared too
    t www.google.com            google.com      # ordinary gTLD, unchanged
    t barclays.co.uk            barclays.co.uk  # ccTLD second level, unchanged
    t accounts.barclays.co.uk   barclays.co.uk
    t user.github.io            user.github.io  # multi-tenant hosting: apex confers no identity
    t za.com                    za.com          # a bare public suffix has no registrable domain
    t co.uk                     co.uk
    t localhost                 localhost       # single label, no TLD

    h() { # h <host> <expected head>
        local got; got=$(head_of "$1")
        if [ "$got" = "$2" ]; then p=$((p+1)); printf 'ok   head %-33s -> %s\n' "$1" "$got"
        else f=$((f+1)); printf 'FAIL head %-33s -> %s (want %s)\n' "$1" "$got" "$2"; fi
    }
    # The registrant chose one word here. Judging the whole hostname invented an amazon typosquat
    # AND a random domain out of `wfses3useast1amazonaws`.
    h wfse.s3.us-east-1.amazonaws.com  wfse
    h xk51.efast.space          xk51.efast      # still the full lure: entropy check must see this
    h www.google.com            www.google
    h accounts.barclays.co.uk   accounts.barclays
    h user.github.io            user
    h za.com                    ""              # host IS a public suffix: registrant chose nothing
    echo; echo "passed $p, failed $f"; [ "$f" -eq 0 ]
fi
