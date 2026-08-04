#!/bin/bash

# Rung 3 of the brand-authorisation ladder: does the BRAND's own site vouch for this host?
#
# Every other brand signal in this toolkit detects that a brand is *claimed* (title, form action,
# hotlinked logo, the vision model reading a screenshot). None of them answer the question that
# actually decides the verdict: is the claim AUTHORISED? A dealer portal, a tenant SaaS host and a
# regional microsite all show a brand they do not own, and all are legitimate.
#
# The one thing a phisher cannot forge is an inbound link from the brand's real website. So:
#   brand-verify.sh <brand-domain> <suspect-host|url>
# fetches the brand's homepage and looks for a reference to the suspect host, or to any host under
# the suspect's registrable domain (the brand links the vendor platform, the suspect is a tenant on
# it). A hit is PROVEN. Anything else is UNPROVEN -- which means "no link found", NOT "phishing".
#
# ASYMMETRIC BY DESIGN, and this is the whole point: PROVEN is strong enough to SUPPRESS a brand
# smell, UNPROVEN must never escalate anything. Measured recall is low -- smithpower.co.za does not
# link its own Auto-IT parts portal from anywhere on the homepage, /parts or /contact, so the real
# case that motivated this tool comes back UNPROVEN. It suppresses false positives when it fires
# and costs nothing when it does not.
#
# Exit: 0 PROVEN, 1 UNPROVEN, 2 could not fetch the brand site (unknown, not a judgement).
#
# ponytail: homepage only. Not a crawler -- if a brand hides the link three clicks deep we take the
# UNPROVEN. Egress is direct: this fetches the BRAND's legitimate site, never the suspect, so it
# needs no Tor sidecar and leaks nothing about the scan target to the suspect.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ "$1" = "-c" ] && [ "$2" = "mono" ] && { MONO=1; shift 2; }
source "$SCRIPT_DIR/psl.sh"

# _bv_hosts <html> -> every host referenced by an absolute URL in the markup or inline JS, one per
# line, lowercased. Pure: no network, so the self-check below can exercise the matching logic.
_bv_hosts() {
    printf '%s' "$1" | grep -oiE 'https?://[a-zA-Z0-9._%-]+' \
        | sed -E 's#^[a-zA-Z]+://##' | tr 'A-Z' 'a-z' | sed 's/\.$//' | sort -u
}

# _bv_match <html> <suspect-host> <suspect-apex> -> echoes the vouching host and how it matched.
# Pure. Exit 0 when the brand site references the suspect directly or its registrable domain.
_bv_match() {
    local html="$1" host="$2" apex="$3" h
    while IFS= read -r h; do
        [ -z "$h" ] && continue
        [ "$h" = "$host" ] && { printf '%s\texact' "$h"; return 0; }
    done <<< "$(_bv_hosts "$html")"
    # No exact hit: accept a host sharing the suspect's registrable domain. The brand linking
    # portal.autoit.za.com vouches for Auto-IT as a real vendor of theirs, which is meaningful
    # evidence for a tenant at smithpower.autoit.za.com -- weaker than exact, still unforgeable.
    while IFS= read -r h; do
        [ -z "$h" ] && continue
        [ "$(apex_of "$h")" = "$apex" ] && { printf '%s\tsame-registrable-domain' "$h"; return 0; }
    done <<< "$(_bv_hosts "$html")"
    return 1
}

# --- self-check: ./brand-verify.sh --self-test ----------------------------------------------
if [ "$1" = "--self-test" ]; then
    p=0 f=0
    t() { # t <desc> <expected: PROVEN|UNPROVEN> <html> <host>
        local want="$2" got
        if got=$(_bv_match "$3" "$4" "$(apex_of "$4")"); then got=PROVEN; else got=UNPROVEN; fi
        if [ "$got" = "$want" ]; then p=$((p+1)); printf 'ok   %s\n' "$1"
        else f=$((f+1)); printf 'FAIL %s: expected %s got %s\n' "$1" "$want" "$got"; fi
    }
    t "exact host linked"       PROVEN   '<a href="https://portal.brand.com/x">p</a>' portal.brand.com
    t "tenant under a linked platform" PROVEN \
        '<a href="https://portal.autoit.za.com/">dealer login</a>' smithpower.autoit.za.com
    t "unrelated links only"    UNPROVEN '<a href="https://facebook.com/brand">fb</a>' login.brand-secure.tk
    # The FP this must not create: za.com is a SHARED namespace, so a brand linking anything at
    # some-other-tenant.za.com must NOT vouch for a phish at paypal.za.com. apex_of stops at the
    # public suffix, so the two apexes differ and no match is possible.
    t "shared namespace is not a link" UNPROVEN \
        '<a href="https://someoneelse.za.com/">x</a>' paypal.za.com
    t "brand site links nothing" UNPROVEN '<p>no links here</p>' portal.brand.com
    echo; echo "passed $p, failed $f"; [ "$f" -eq 0 ]; exit
fi

source "$SCRIPT_DIR/colors.sh"

BRAND_DOMAIN="$1"; SUSPECT="$2"
if [ -z "$BRAND_DOMAIN" ] || [ -z "$SUSPECT" ]; then
    echo "usage: $(basename "$0") [-c mono] <brand-domain> <suspect-host|url>" >&2
    echo "       $(basename "$0") --self-test" >&2
    exit 2
fi

# Normalise the suspect to a bare host: strip scheme, credentials, port and path.
SUSPECT_HOST=$(printf '%s' "$SUSPECT" | sed -E 's#^[a-zA-Z]+://##; s#^[^/@]*@##; s#[/?#].*##; s#:[0-9]+$##' | tr 'A-Z' 'a-z')
BRAND_HOST=$(printf '%s' "$BRAND_DOMAIN" | sed -E 's#^[a-zA-Z]+://##; s#^[^/@]*@##; s#[/?#].*##; s#:[0-9]+$##' | tr 'A-Z' 'a-z')

# Validate before either value reaches curl. Hostnames only -- no schemes, no shell metacharacters,
# no argument injection via a leading dash.
for _h in "$BRAND_HOST" "$SUSPECT_HOST"; do
    if ! printf '%s' "$_h" | grep -qE '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'; then
        echo_red "Not a valid hostname: ${_h:-(empty)}" >&2; exit 2
    fi
done

SUSPECT_APEX=$(apex_of "$SUSPECT_HOST")
BRAND_APEX=$(apex_of "$BRAND_HOST")

# Same registrable domain: the brand IS the host, nothing to prove.
if [ "$BRAND_APEX" = "$SUSPECT_APEX" ]; then
    echo_green "PROVEN   $SUSPECT_HOST is on the brand's own registrable domain ($BRAND_APEX)"
    exit 0
fi

# ponytail: head -c caps the download even when the server sends no content-length, which
# --max-filesize alone does not cover.
HTML=$(curl -sL --max-time 25 --max-filesize 3000000 \
    -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36' \
    -- "https://$BRAND_HOST/" 2>/dev/null | head -c 3000000)
if [ -z "$HTML" ]; then
    echo_yellow "UNKNOWN  could not fetch https://$BRAND_HOST/ - no evidence either way"
    exit 2
fi

if MATCH=$(_bv_match "$HTML" "$SUSPECT_HOST" "$SUSPECT_APEX"); then
    echo_green "PROVEN   $BRAND_HOST links to $(printf '%s' "$MATCH" | cut -f1) ($(printf '%s' "$MATCH" | cut -f2) as $SUSPECT_HOST)"
    exit 0
fi

echo_yellow "UNPROVEN $BRAND_HOST does not reference $SUSPECT_HOST or anything under $SUSPECT_APEX"
echo_grey   "         Absence of a link is NOT evidence of phishing - it only means this check could not vouch for the host."
exit 1
