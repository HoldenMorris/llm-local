#!/bin/bash

# Read a threat-intel feed and say what is NEW since the last check, and -- for each new post --
# which of this toolkit's detections already cover the mechanism it describes.
#
# The point is not to read the feed. It is to notice the posts describing something we have no
# handle on: those are the ones worth an hour. A post about yet another obfuscated redirector is
# already covered and can be skipped.
#
#   ./intel-feed.sh          new items since the last run (and record them as seen)
#   ./intel-feed.sh -a       every item in the feed, and leave the seen-list alone
#   ./intel-feed.sh -n       new items, but do NOT record them (dry run)
#   FEED_URL=<url> ./intel-feed.sh      read a different feed
#
# ponytail: python3 (stdlib only) parses the XML. The descriptions are CDATA blocks of arbitrary
# HTML, and regex-scraping those in awk is the classic way to ship a parser that works until it
# does not. No new package: python3 is already on the box.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ALL=""; NO_MARK=""
while [ $# -gt 0 ]; do
    case "$1" in
        -a) ALL=1; NO_MARK=1 ;;
        -n) NO_MARK=1 ;;
        -c) shift; [ "${1:-}" = mono ] && MONO=1 ;;
        -h|--help) sed -n '3,17p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
    shift
done
source "$SCRIPT_DIR/colors.sh"

# joesecurity.org/rss is the working one. /blog/feed and /blog/rss return 200 with the SPA shell
# rather than XML, which is exactly the sort of thing that makes a feed reader silently show zero
# new items forever -- so the parser below hard-fails on non-XML instead of reporting "nothing new".
FEED_URL="${FEED_URL:-https://www.joesecurity.org/rss}"
SEEN_FILE="$SCRIPT_DIR/.cache/intel-feed-seen.txt"
mkdir -p "$SCRIPT_DIR/.cache"; touch "$SEEN_FILE"

# To a file, not a variable: the feed is ~70KB and the environment is not a pipe -- passing it
# through one gives "Argument list too long" the moment a feed grows.
FEED_TMP=$(mktemp); trap 'rm -f "$FEED_TMP"' EXIT INT TERM
curl -sL --max-time 30 --max-filesize 8000000 "$FEED_URL" -o "$FEED_TMP" \
    || { echo_red "feed fetch failed: $FEED_URL"; exit 1; }
[ -s "$FEED_TMP" ] || { echo_red "feed fetch returned nothing: $FEED_URL"; exit 1; }

# Which of OUR detections speak to the mechanism a post describes. Each entry is
# <regex>|<what we already do>. A post matching nothing is the interesting case: read that one.
# Grounded in what actually ships -- do not add a row here for something we only intend to build,
# because a false "covered" is worse than no answer at all.
COVERAGE='
browser.in.the.middle|bitm|socket\.io|websocket|domdiffer≡BitM relay: same-origin socket on a credential page + Socket.IO/domdiffer kit signature
turnstile|hcaptcha|recaptcha|captcha|bot gate|bot-gate≡Bot-gate detection ("gated from the scraper") + operator attach
obfuscat|deobfuscat|_0x|atob|packer|eval\(≡JS deobfuscation escalation (js-deobfuscate.sh + js-signals.sh)
anti.analysis|anti.sandbox|sandbox.aware|sandbox.evasion|webdriver|automation detect|evasion≡Anti-analysis probe detection (capped SUSPICIOUS)
open redirect|redirect_uri|redirect chain|interstitial≡Open-redirect abuse (Phase 1) + interstitial destination follow (Phase 3.2b)
typosquat|homograph|punycode|lookalike|idn≡Typosquat / homograph / brand-lookalike subdomain
zero.width|invisible char|homoglyph≡Invisible-character padding (stripped before every text match)
shortener|redirector|tracking link|click track≡Email link-redirection service (host, CNAME and URL shape)
wallet|bitcoin|ethereum|crypto address≡Crypto wallet address extraction
phishing kit|kit analysis|credential harvest|login form≡Kit fingerprinting (kitSignatures) + credential-page floors
cloudflare worker|tunnel|ngrok|trycloudflare≡Tunneling-service detection
fast.flux|domain age|newly registered≡Domain age (RDAP) + fast-flux DNS
'

export COVERAGE ALL NO_MARK
python3 - "$FEED_TMP" "$SEEN_FILE" <<'PY'
import os, re, sys, html
import xml.etree.ElementTree as ET

cov_raw, show_all = os.environ["COVERAGE"], os.environ.get("ALL")
feed_file, seen_file = sys.argv[1], sys.argv[2]
feed = open(feed_file, encoding="utf-8", errors="replace").read()

# A feed is remote input, and FEED_URL is overridable, so treat it as hostile. ElementTree does
# not resolve EXTERNAL entities (it raises on them), but expat does expand INTERNAL ones, which is
# the billion-laughs / quadratic-blowup DoS. Both need an <!ENTITY> in a DTD, and a DTD must sit in
# the prolog -- so refuse a prolog that declares one. Scanning only the prolog matters: a security
# blog quotes "<!DOCTYPE html>" inside a CDATA body all the time, and scanning the whole document
# would reject the very feed we want.
# ponytail: 3 lines instead of the defusedxml dependency, which exists for the general case where
# you must ACCEPT a DTD. We never do -- no RSS feed needs one.
prolog = re.split(r"<(?:rss|feed|rdf:RDF)\b", feed, maxsplit=1, flags=re.I)[0]
if re.search(r"<!(?:DOCTYPE|ENTITY)\b", prolog, re.I):
    sys.stderr.write("refusing feed: the XML prolog declares a DTD/entity (entity-expansion DoS)\n")
    sys.exit(1)

# This feed is not well-formed XML: Blogger emits bare ampersands in titles ("Malware & Phishing
# Analyst"), which every strict parser rejects. Escaping a & that does not already start an entity
# is the whole repair. Inside CDATA it turns & into the literal text "&amp;", which the
# html.unescape below turns back -- so no text is lost either way.
# Done AFTER the DTD check above, so the repair can never manufacture an entity we just refused.
feed = re.sub(r"&(?!(?:#\d+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);)", "&amp;", feed)

try:
    root = ET.fromstring(feed)
except ET.ParseError as e:
    # A 200 that is not XML is the failure mode this guards: the SPA shell parses as nothing and
    # would otherwise read as "no new items", forever.
    sys.stderr.write("feed is not valid XML (a 200 HTML shell?): %s\n" % e)
    sys.exit(1)

coverage = []
for line in cov_raw.strip().splitlines():
    if "≡" in line:
        pat, label = line.split("≡", 1)
        coverage.append((re.compile(pat, re.I), label.strip()))

seen = set(open(seen_file).read().split()) if os.path.exists(seen_file) else set()

items, fresh = [], []
for it in root.iter("item"):
    def txt(tag):
        el = it.find(tag)
        return (el.text or "").strip() if el is not None and el.text else ""
    guid = txt("guid") or txt("link")
    if not guid:
        continue
    body = html.unescape(re.sub(r"<[^>]+>", " ", txt("description")))
    items.append({"guid": guid, "title": txt("title"), "link": txt("link"),
                  "date": txt("pubDate")[:16], "body": body, "new": guid not in seen})
    if guid not in seen:
        fresh.append(guid)

show = items if show_all else [i for i in items if i["new"]]
if not show:
    print("nothing new (%d items in feed, all seen)" % len(items))
    sys.exit(0)

for i in show:
    # Name the term that matched, not just the verdict. Matching is keywords over the whole post
    # body, so it WILL over-claim -- one passing mention of "captcha" in a product release marks it
    # covered. Printing the term makes that visible instead of hiding it behind a confident label.
    hits = {}
    for rx, label in coverage:
        m = rx.search(i["title"] + " " + i["body"])
        if m:
            hits.setdefault(label, m.group(0).lower())
    print()
    print(("[NEW] " if i["new"] else "[   ] ") + i["title"])
    print("      %s  %s" % (i["date"], i["link"]))
    if hits:
        for label in sorted(hits):
            print('      covered: %s  [matched "%s"]' % (label, hits[label]))
    else:
        print("      NO MATCHING DETECTION -- read this one")
print()
print("%d shown, %d new, %d in feed" % (len(show), sum(1 for i in show if i["new"]), len(items)))

# Record what we showed, so the next run is genuinely "since last time". -a and -n skip this: -a
# is a browse, and -n exists precisely to look without committing.
if fresh and not os.environ.get("NO_MARK"):
    with open(seen_file, "a") as fh:
        fh.write("\n".join(fresh) + "\n")
PY
