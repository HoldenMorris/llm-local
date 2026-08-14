#!/bin/bash
# Golden tests for the deterministic verdict core (verdict.sh). Pure: no LLM, no network.
# Pins the decision table so Phase 2 (demoting the LLM in url-analyze.sh) -- and any future
# edit -- can't silently change what the signals mean. See docs/determinism-plan.md (Phase 3).
#
# Run: ./test-verdict.sh    (exit 0 = all pass, non-zero = a case drifted)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/verdict.sh"

pass=0 fail=0
# check <description> <expected> <actual>
check() {
    if [ "$2" = "$3" ]; then
        pass=$((pass+1)); printf 'ok   %s\n' "$1"
    else
        fail=$((fail+1)); printf 'FAIL %s\n       expected [%s] got [%s]\n' "$1" "$2" "$3"
    fi
}
# expect <description> <yes|no> <predicate...> -- asserts a predicate's exit status
expect() {
    local desc="$1" want="$2"; shift 2
    local got; if "$@" >/dev/null 2>&1; then got=yes; else got=no; fi
    check "$desc" "$want" "$got"
}
# classify_verdict <has_login> <tld> <age> <final_url> <url> <smells> <susp_js> <deobfus> <llm>
# (2>/dev/null drops the "[floor] Safety floor..." notice verdict.sh writes to stderr)
cv() { classify_verdict "$@" 2>/dev/null; }

echo "== is_risky_tld =="
expect "top is risky"      yes is_risky_tld top
expect "xyz is risky"      yes is_risky_tld xyz
expect "zip is risky"      yes is_risky_tld zip
expect "com is not risky"  no  is_risky_tld com

echo "== is_unsub_url =="
expect "unsubscribe url"   yes is_unsub_url "https://x.com/unsubscribe?e=aGk"
expect "opt-out url"       yes is_unsub_url "https://x.com/opt-out"
expect "normal login url"  no  is_unsub_url "https://x.com/login"

echo "== count_red_flags <tld> <age> <final_url> <smells> <susp_js> <deobfus> =="
check "hidden-field smell not counted"  0 "$(count_red_flags com '' '' '3 hidden form fields' '' '')"
check "third-party hosts not counted"   0 "$(count_red_flags com '' '' 'Third-party hosts referenced (scripts/iframes/images/JS): a.com b.com' '' '')"
check "third-party hosts don't mask a real smell" 1 "$(count_red_flags com '' '' 'Urgency language detected, Third-party hosts referenced (scripts/iframes/images/JS): a.com b.com' '' '')"
check "one real smell counts"           1 "$(count_red_flags com '' '' 'Urgency language detected' '' '')"
check "two smells count"                2 "$(count_red_flags com '' '' 'Urgency language detected, IP fingerprinting: x' '' '')"
check "suspicious JS counts"            1 "$(count_red_flags com '' '' '' 'eval(), atob()' '')"
# Minifier-emitted markers alone are not evidence: Closure/Vite bundles trip all three, and they
# no longer trigger deob, so counting them here would just relocate the youtube.com false positive.
check "minifier-only JS marker not counted" 0 "$(count_red_flags com '' '' '' 'hex-encoded strings' '')"
check "fromCharCode alone not counted"  0 "$(count_red_flags com '' '' '' 'String.fromCharCode' '')"
check "weak markers together not counted" 0 "$(count_red_flags com '' '' '' 'hex-encoded strings, String.fromCharCode, location redirect' '')"
check "strong marker among weak counts" 1 "$(count_red_flags com '' '' '' 'hex-encoded strings, atob()' '')"
check "_0x obfuscation counts"          1 "$(count_red_flags com '' '' '' 'obfuscated identifiers (_0x)' '')"
check "_0x adjudicated by deob not double-counted" 1 "$(count_red_flags com '' '' '' 'obfuscated identifiers (_0x)' 'off-domain URL: evil.com')"
check "same-domain deobfus not counted" 0 "$(count_red_flags com '' '' '' '' 'localStorage read fed nothing')"
check "off-domain deobfus counts"       1 "$(count_red_flags com '' '' '' '' 'off-domain URL: evil.com')"
check "risky TLD + young age = 2"       2 "$(count_red_flags xyz 10 '' '' '' '')"
check "old domain age not counted"      0 "$(count_red_flags com 400 '' '' '' '')"
check "wp-content redirect counts"      1 "$(count_red_flags com '' 'http://x.com/wp-content/ab12/' '' '' '')"
# Legit WordPress serves its OWN media from uploads/plugins/themes -- a real gov PDF
# (siu.org.za/wp-content/uploads/.../Judgment-...pdf) must not score as a compromised-WP redirect.
check "wp-content/uploads NOT counted"  0 "$(count_red_flags za '' 'https://www.siu.org.za/wp-content/uploads/2025/11/Judgment-Tepa-Trading.pdf' '' '' '')"
check "wp-content/plugins NOT counted"  0 "$(count_red_flags com '' 'http://x.com/wp-content/plugins/akismet/x.js' '' '' '')"
check "wp-content/themes NOT counted"   0 "$(count_red_flags com '' 'http://x.com/wp-content/themes/twenty/style.css' '' '' '')"
check "wp-includes random still counts" 1 "$(count_red_flags com '' 'http://x.com/wp-includes/9fz2k/' '' '' '')"

echo "== classify_verdict (the decision table) =="
check "login + risky TLD -> DANGEROUS"              DANGEROUS  "$(cv true top '' '' 'http://x.top/login' '' '' '' '')"
check "login + exfil smell -> DANGEROUS"            DANGEROUS  "$(cv true com '' '' 'https://x.com' 'Off-domain exfil endpoint(s) in page code: evil.com' '' '' SAFE)"
check "off-domain deobfus -> DANGEROUS (exfil)"     DANGEROUS  "$(cv false com '' '' 'https://x.com' '' '' 'off-domain URL: evil.com' '')"
check "obfuscated network call -> DANGEROUS"        DANGEROUS  "$(cv true com '' '' 'https://x.com' 'obfuscated network call' '' '' '')"
check "one flag, no login -> SUSPICIOUS"            SUSPICIOUS "$(cv false xyz '' '' 'https://x.xyz' '' '' '' '')"
check "unsubscribe + young domain -> SUSPICIOUS"    SUSPICIOUS "$(cv false com 10 '' 'https://x.com/unsubscribe?e=aGk' '' '' '' '')"
check "clean login + LLM SAFE -> SAFE"              SAFE       "$(cv true com '' '' 'https://chase.com/login' '' '' '' SAFE)"
check "clean page + LLM empty -> UNCLEAR (empty)"   ""         "$(cv false com '' '' 'https://x.com' '' '' '' '')"
check "escalate: floor SUSP, LLM DANGEROUS -> DANGEROUS" DANGEROUS "$(cv false xyz '' '' 'https://x.xyz' '' '' '' DANGEROUS)"
check "never downgrade: floor DANGEROUS, LLM SAFE -> DANGEROUS" DANGEROUS "$(cv true top '' '' 'http://x.top/login' '' '' '' SAFE)"
check "floor imposes nothing, LLM SUSPICIOUS kept"  SUSPICIOUS "$(cv false com '' '' 'https://x.com' '' '' '' SUSPICIOUS)"
# login page + off-CDN third-party host: flaky LLM says SAFE, heuristic floors to SUSPICIOUS anyway
check "login + off-CDN third-party host -> SUSPICIOUS" SUSPICIOUS "$(cv true com '' '' 'https://x.com' 'Third-party hosts referenced (scripts/iframes/images/JS): kalcij.cyberfolks.hr' '' '' SAFE)"
check "content page + third-party host (no login) -> SAFE kept" SAFE "$(cv false com '' '' 'https://x.com' 'Third-party hosts referenced (scripts/iframes/images/JS): a.com' '' '' SAFE)"
# brand-lookalike subdomain smell counts as a red flag -> floors over an LLM SAFE (no login: SUSPICIOUS)
check "brand-lookalike subdomain -> SUSPICIOUS" SUSPICIOUS "$(cv false io '' '' 'https://x.github.io' 'brand-lookalike subdomain - impersonates \"Immigration Advice Service\" on shared host github.io' '' '' SAFE)"
check "brand-lookalike + login -> DANGEROUS"    DANGEROUS  "$(cv true io '' '' 'https://x.github.io' 'brand-lookalike subdomain - impersonates \"PayPal\" on shared host github.io' '' '' SAFE)"

# Cloaked page gated from the scraper (custom JS challenge): the blank land floors the verdict so a
# flaky LLM SAFE can't downgrade it (dhlpayonline.com cloak). Login behind the gate -> DANGEROUS.
check "gate smell (no login) -> SUSPICIOUS"     SUSPICIOUS "$(cv false com '' '' 'https://x.com' 'Unrecognized bot/cloak challenge - real page gated from the scraper' '' '' SAFE)"
check "gate smell + login -> DANGEROUS"         DANGEROUS  "$(cv true com '' '' 'https://x.com' 'Cloudflare Turnstile challenge - real page gated from the scraper' '' '' SAFE)"

# Email-redirector link (Mailjet mjt.lu etc.) that never left the service -- dead/expired token landed
# on the "this subdomain is for link redirection" placeholder. The unresolved-destination smell floors
# it to SUSPICIOUS so a flaky LLM SAFE can't call the placeholder clean.
check "unresolved redirector -> SUSPICIOUS"     SUSPICIOUS "$(cv false lu '' '' 'https://04l5p.mjt.lu/' 'link-redirection service mjt.lu - destination unresolved (dead/expired link on a phishing-prone redirector)' '' '' SAFE)"

# Hotlinked brand artwork: the page shows a brand's own image off the brand's own CDN. Legit pages
# do this too (PayPal buttons, dealer logos), so it is display evidence only -- never a red flag,
# and it floors to SUSPICIOUS only on a credential page. Guards both directions of that cap.
HL='Hotlinked brand image: "paypal" artwork served from its own domain (www.paypalobjects.com) but page is "secure-pay.example.com"'
check "hotlinked brand image not counted"    0          "$(count_red_flags com '' '' "$HL" '' '')"
check "hotlink alone does not floor"         SAFE       "$(cv false com '' '' 'https://x.com' "$HL" '' '' SAFE)"
check "hotlink + login -> SUSPICIOUS"        SUSPICIOUS "$(cv true  com '' '' 'https://x.com' "$HL" '' '' SAFE)"
check "hotlink + login never downgrades"     DANGEROUS  "$(cv true  com '' '' 'https://x.com' "$HL" '' '' DANGEROUS)"
check "hotlink doesn't mask a real smell"    DANGEROUS  "$(cv true  com '' '' 'https://x.com' "Urgency language detected, $HL" '' '' SAFE)"

# Follow-the-login-link escalation (url-analyze.sh Phase 2): when the landed page has no form but
# links to one, the followed credential page is merged with has_login=true. The contract these pin:
# every login-gated floor must then fire exactly as if the form had been on the landed page, and
# the escalation itself must add NO red flag -- a site having a login page is not suspicious.
check "followed cred page re-arms off-CDN floor"  SUSPICIOUS "$(cv true com '' '' 'https://x.com' 'Third-party hosts referenced (scripts/iframes/images/JS): a.com b.com' '' '' SAFE)"
check "followed cred page re-arms hotlink floor"  SUSPICIOUS "$(cv true com '' '' 'https://x.com' "$HL" '' '' SAFE)"
check "followed cred page + real smell -> DANGEROUS" DANGEROUS "$(cv true com '' '' 'https://x.com' 'Urgency language detected' '' '' SAFE)"
check "clean followed cred page stays SAFE"       SAFE       "$(cv true com '' '' 'https://x.com' '' '' '' SAFE)"

# A fetch that produced no assessable page must never read SAFE. healthlynotes.com returned
# HTTP 500 "Database Error" with an empty DOM and scored SAFE; cdn.filestackcontent.com returned
# 200 with zero of everything. Operator attach (status 0, real DOM) must stay assessable.
echo "== is_blank_page <status> <element_count> =="
expect "HTTP 500 is blank"                 yes is_blank_page 500 0
expect "HTTP 404 is blank even with a DOM" yes is_blank_page 404 42
expect "200 with an empty DOM is blank"    yes is_blank_page 200 0
expect "200 with a real DOM is not blank"  no  is_blank_page 200 12
expect "attach (status 0) + DOM not blank" no  is_blank_page 0 12
expect "unknown status + DOM not blank"    no  is_blank_page '' 12
# A registrar parking page is a healthy 200 with a full DOM that belongs to the REGISTRAR.
# sportycast.com (a LUCA alert) landed on Spaceship's "Parking Page" and escaped SAFE only because
# it happened to be served over plain HTTP.
PARK='Domain placeholder page - no real site here (registrar parking / host default: "parking page")'
expect "placeholder page is not assessable" yes is_blank_page 200 12 "$PARK"
expect "no placeholder smell = assessable"  no  is_blank_page 200 12 'Urgency language detected'
check "placeholder is not a red flag"       0 "$(count_red_flags com '' '' "$PARK" '' '')"
check "placeholder does not mask a real smell" 1 "$(count_red_flags com '' '' "$PARK
Urgency language detected" '' '')"
# It must not manufacture severity either: parked domains are overwhelmingly ordinary (an expired
# business, a speculator's inventory), so the floor stays out of it and the domain facts decide.
check "placeholder alone imposes no floor"  ""         "$(cv false com 400 '' 'https://x.com/' "$PARK" '' '' '')"
check "placeholder + young domain -> SUSPICIOUS" SUSPICIOUS "$(cv false com 3 '' 'https://x.com/' "$PARK" '' '' '')"
check "placeholder never downgrades the LLM" DANGEROUS "$(cv false com 400 '' 'https://x.com/' "$PARK" '' '' DANGEROUS)"
# The one claim an unjudgeable page still earns: what it is. A bare UNCLEAR is a shrug, where
# "UNCLEAR (parked)" is the whole answer -- so this is the exception to the no-category rule.
check "placeholder named even on UNCLEAR"   parked     "$(category_of UNCLEAR false 'https://x.com/' "$PARK" '')"
check "placeholder named on a bad verdict"  parked     "$(category_of SUSPICIOUS false 'https://x.com/' "$PARK" '')"
check "credential form outranks placeholder" phishing  "$(category_of DANGEROUS true 'https://x.com/' "$PARK" '')"
check "parked is in the vocabulary"         yes        "$(is_category parked && echo yes)"

# Multi-vendor VirusTotal consensus is stronger than any local heuristic and needs no credential
# form: trencraft.com (11 vendors, scam storefront, no login) capped at SUSPICIOUS before this.
VT11='3-hop redirect chain, VirusTotal flagged malicious (11 vendors)'
check "VT quorum (no login) -> DANGEROUS"   DANGEROUS  "$(cv false com 294 '' 'https://trencraft.com/x/' "$VT11" '' '' SAFE)"
check "VT below quorum stays SUSPICIOUS"    SUSPICIOUS "$(cv false com '' '' 'https://x.com' 'VirusTotal flagged malicious (2 vendors)' '' '' SAFE)"
check "VT quorum never downgrades an LLM DANGEROUS" DANGEROUS "$(cv false com '' '' 'https://x.com' "$VT11" '' '' DANGEROUS)"
check "clean page, no VT line -> SAFE kept"  SAFE      "$(cv false com '' '' 'https://x.com' '' '' '' SAFE)"

# Prior-judgement rollup: url-analyze.sh appends this smell when the ledger holds an INSPECTED
# DANGEROUS for another url on the same host (feedback-report.sh --host). It rides the ordinary
# red-flag counter, so the cap is structural: one flag -> SUSPICIOUS alone, DANGEROUS with a
# credential form. A compromised legitimate host still serves real pages on its other paths.
PRIOR='Confirmed phishing previously inspected on this host (https://h.com/login)'
PRIORD='Confirmed phishing previously inspected on this domain (https://sib.h.com/login)'
check "sibling-host wording counts too"     1          "$(count_red_flags com '' '' "$PRIORD" '' '')"
# A settled SUSPICIOUS sibling is capped: it floors to SUSPICIOUS and, unlike a DANGEROUS one,
# never combines with a login form to reach DANGEROUS -- it says the domain hosted something bad,
# not that this page is harvesting.
PRIORS='A sibling url was previously inspected as suspicious on this domain (https://sib.h.com/x)'
check "prior suspicious is not a red flag" 0          "$(count_red_flags com '' '' "$PRIORS" '' '')"
check "prior suspicious -> SUSPICIOUS"     SUSPICIOUS "$(cv false com '' '' 'https://h.com/y' "$PRIORS" '' '' SAFE)"
check "prior suspicious + login stays SUSPICIOUS" SUSPICIOUS "$(cv true com '' '' 'https://h.com/y' "$PRIORS" '' '' SAFE)"
check "prior suspicious never downgrades"  DANGEROUS  "$(cv false com '' '' 'https://h.com/y' "$PRIORS" '' '' DANGEROUS)"

# The campaign smells reuse the two shapes above, so only the wording is new here.
CAMPS='A url under the same campaign tag s1=upg12 was previously inspected as suspicious (https://a.b/x)'
check "campaign suspicious is capped too"  SUSPICIOUS "$(cv true com '' '' 'https://h.com/y' "$CAMPS" '' '' SAFE)"
CAMPD='Confirmed phishing previously inspected under the same campaign tag s1=upg12 (https://a.b/x)'
check "campaign dangerous + login -> DANGEROUS" DANGEROUS "$(cv true com '' '' 'https://h.com/y' "$CAMPD" '' '' SAFE)"

echo "== cloak gate + confirmed phishing (the gate is why there is no form) =="
# ps092.soakblast.com/?s1=snm3: cloak gate, atob() redirect, fast-flux TTL, and s1=snm3 already
# settled as phishing on another domain -- and it read SUSPICIOUS, because no credential form was
# visible. The gate is precisely WHY it was not visible, so the kit's own cloak was protecting it.
GATE='Unrecognized bot/cloak challenge - real page gated from the scraper'
GATECF='Cloudflare Turnstile challenge - real page gated from the scraper'
check "gate + confirmed campaign -> DANGEROUS"  DANGEROUS  "$(cv false com '' '' 'https://ps092.soakblast.com/?s1=snm3' "$GATE, $CAMPD" '' '' SAFE)"
check "gate + confirmed host -> DANGEROUS"      DANGEROUS  "$(cv false com '' '' 'https://h.com/y' "$GATECF, $PRIOR" '' '' SAFE)"
check "gate + confirmed domain -> DANGEROUS"    DANGEROUS  "$(cv false com '' '' 'https://h.com/y' "$GATE, $PRIORD" '' '' SAFE)"
# Each half alone must NOT reach DANGEROUS. A gate on its own fronts plenty of legitimate sites,
# and a confirmed sibling on its own says the domain hosted something bad, not that this page does.
check "gate alone stays SUSPICIOUS"             SUSPICIOUS "$(cv false com '' '' 'https://real.com/' "$GATECF" '' '' SAFE)"
check "confirmed sibling alone stays SUSPICIOUS" SUSPICIOUS "$(cv false com '' '' 'https://h.com/y' "$PRIOR" '' '' SAFE)"
# A merely-suspicious sibling is not a confirmation, so the pair must not fire on it either.
check "gate + suspicious sibling stays SUSPICIOUS" SUSPICIOUS "$(cv false com '' '' 'https://h.com/y' "$GATE, $PRIORS" '' '' SAFE)"
# With a credential form the existing login rule already reaches DANGEROUS; this must not be the
# thing carrying it, and it must not change the answer either.
check "gate + confirmed + login -> DANGEROUS"   DANGEROUS  "$(cv true com '' '' 'https://h.com/y' "$GATE, $PRIOR" '' '' SAFE)"
# The floor only ever escalates: an LLM that already said DANGEROUS is not downgraded, and the
# floor is never applied to a page carrying neither half.
check "clean gated page keeps LLM SAFE"         SAFE       "$(cv false com 3000 '' 'https://real.com/' '' '' '' SAFE)"

echo "== kit signatures (naming the build, not the brand) =="
# Deliberately an ORDINARY red flag rather than a VirusTotal-style standalone DANGEROUS: the
# tokens are strong (build hashes, invented field names, paired filenames) but they are OUR
# string table, with no second opinion behind them. A kit page with no credential form is
# usually a redirector stage, and SUSPICIOUS covers it.
KIT='Known phishing kit: Kratos (build artifact "barr.svg")'
check "kit signature counts once"        1          "$(count_red_flags com '' '' "$KIT" '' '')"
check "kit signature -> SUSPICIOUS"      SUSPICIOUS "$(cv false com '' '' 'https://x.com/' "$KIT" '' '' SAFE)"
check "kit signature + login -> DANGEROUS" DANGEROUS "$(cv true com '' '' 'https://x.com/' "$KIT" '' '' SAFE)"

SITEKEY='Bot-gate sitekey: 0x4AAAAAAABkMYinukE8nzYS'
echo "== bot-gate sitekey (attribution, not evidence of theft) =="
# Who deployed the gate, not that the page steals -- so it must never score. A kit reuses one
# sitekey across campaigns, which is what makes it worth extracting at all.
check "sitekey is not a red flag"        0          "$(count_red_flags com '' '' "$SITEKEY" '' '')"
check "sitekey alone imposes no floor"   SAFE       "$(cv false com '' '' 'https://x.com/' "$SITEKEY" '' '' SAFE)"
check "sitekey + login imposes no floor" SAFE       "$(cv true com '' '' 'https://x.com/' "$SITEKEY" '' '' SAFE)"
check "sitekey does not mask a real smell" 1        "$(count_red_flags com '' '' "Urgency language detected, $SITEKEY" '' '')"

echo "== browser-in-the-middle (the page relays instead of submitting) =="
# A BitM kit never submits: socket.io streams the victim's input to a backend browser and patches
# the DOM back, so off-domain form action / exfil host / obfuscated call all see nothing. The
# socket is the handle that survives the kit renaming its scripts -- but some legitimate SPAs open
# one on a signed-out page, so it is capped like the signals above. The kit signature is a counted
# flag and is what reaches DANGEROUS.
WS='Credential page holds a WebSocket to its own origin (evil.test) - input is relayed live rather than submitted (Browser-in-the-Middle)'
BITMKIT='Known phishing kit: BitM relay (Socket.IO + DOM diffing) (build artifact "socket.io")'
check "websocket is not a red flag"      0          "$(count_red_flags com '' '' "$WS" '' '')"
check "websocket -> SUSPICIOUS"          SUSPICIOUS "$(cv false com '' '' 'https://x.com/' "$WS" '' '' SAFE)"
check "websocket + login stays SUSPICIOUS" SUSPICIOUS "$(cv true com '' '' 'https://x.com/' "$WS" '' '' SAFE)"
check "websocket never downgrades"       DANGEROUS  "$(cv false com '' '' 'https://x.com/' "$WS" '' '' DANGEROUS)"
# The full BitM page: kit signature (counted) + socket + credential form.
check "bitm kit counts once"             1          "$(count_red_flags com '' '' "$BITMKIT, $WS" '' '')"
check "bitm kit + login -> DANGEROUS"    DANGEROUS  "$(cv true com '' '' 'https://x.com/' "$BITMKIT, $WS" '' '' SAFE)"

echo "== anti-analysis javascript (the kit checking whether it is talking to us) =="
# Capped like the other "this is bad company, not proof of theft" signals: SUSPICIOUS, excluded
# from the red-flag count, so commercial bot protection on a real login page cannot reach DANGEROUS.
AA='anti-analysis: probes for 6 browser-automation artifacts'
check "anti-analysis is not a red flag"   0          "$(count_red_flags com '' '' '' '' "$AA")"
check "anti-analysis -> SUSPICIOUS"       SUSPICIOUS "$(cv false com '' '' 'https://x.com/' '' '' "$AA" SAFE)"
check "anti-analysis + login stays SUSPICIOUS" SUSPICIOUS "$(cv true com '' '' 'https://x.com/' '' '' "$AA" SAFE)"
check "anti-analysis never downgrades"    DANGEROUS  "$(cv false com '' '' 'https://x.com/' '' '' "$AA" DANGEROUS)"
# but the deob signals that ARE proof still behave as before
check "exfil still outranks it" DANGEROUS "$(cv false com '' '' 'https://x.com/' '' '' "off-domain URL: https://e.vil/c, $AA" SAFE)"

echo "== registry hold (why the domain is dead) =="
# Capped for the same reason as the signals above: an RDAP clientHold/serverHold is where an abuse
# takedown ends, but it is also where an unpaid renewal on a legitimate domain ends, and RDAP
# cannot tell them apart. SUSPICIOUS, never combining with a login form to reach DANGEROUS.
HOLD='domain suspended at the registry (RDAP hold)'
check "registry hold is not a red flag"   0          "$(count_red_flags com '' '' "$HOLD" '' '')"
check "registry hold -> SUSPICIOUS"       SUSPICIOUS "$(cv false com '' '' 'https://x.com/' "$HOLD" '' '' SAFE)"
check "registry hold + login stays SUSPICIOUS" SUSPICIOUS "$(cv true com '' '' 'https://x.com/' "$HOLD" '' '' SAFE)"
check "registry hold never downgrades"    DANGEROUS  "$(cv false com '' '' 'https://x.com/' "$HOLD" '' '' DANGEROUS)"
# and it must not mask a real flag sitting beside it
check "hold + a real smell still counts the smell" 1 "$(count_red_flags com '' '' "$HOLD, Login form submits off-domain" '' '')"

echo "== open-redirect abuse (the phish that hosts nothing) =="
# The real thing, trimmed: a genuine accounts.google.com authorize url whose redirect_uri is
# percent-encoded character by character to hide the attacker host.
OA='https://accounts.google.com/o/oauth2/v2/auth?client_id=904424875402-73hnjvjhcilptli7r7cpf7bvig8fcbp6.apps.googleusercontent.com&redirect_uri=h%74tps:%2f%2fm%2D3%36%35a%36%33c9%2d%61%64o%62%33%39b%37%63%61%62%6C%37jFW%57i%73u%72%6b%73%44%3942%64%579%37v%66Bwc%34%42I%37cN.%72a%64i%6fpanam%65ric%61%6e%61%70an%61ma%2eco%6d&scope=openid+email&prompt=none&response_type=code'
check "redirect target is decoded out" \
      'm-365a63c9-adob39b7cabl7jfwwisurksd942dw97vfbwc4bi7cn.radiopanamericanapanama.com' \
      "$(redirect_target "$OA")"
expect "and its encoding is gratuitous"  yes has_gratuitous_encoding "$(redirect_raw "$OA")"
expect "that host reads machine-generated" yes is_random_label m-365a63c9-adob39b7cabl7jfwwisurksd942dw97vfbwc4bi7cn
# A normal OAuth flow: off-site redirect, no hiding. Nothing here may score.
OK='https://accounts.google.com/o/oauth2/v2/auth?client_id=1234.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Fapp.slack.com%2Fauth&scope=openid+email&response_type=code'
check "ordinary oauth still resolves"    'app.slack.com' "$(redirect_target "$OK")"
expect "and is not called obfuscated"    no  has_gratuitous_encoding "$(redirect_raw "$OK")"
expect "reserved chars encode normally"  no  has_gratuitous_encoding 'https%3A%2F%2Fx.com%2Fa%3Fb%3Dc'
expect "a slack host is not random"      no  is_random_label app.slack
check "no redirect param -> nothing"     ''  "$(redirect_target 'https://x.com/a?b=c')"
check "param that is not a url"          ''  "$(redirect_target 'https://x.com/a?url=notaurl')"
check "double-encoded still decodes"     'evil.example' "$(redirect_target 'https://x.com/a?next=https%253A%252F%252Fevil.example%252Fp')"
# redirect_url gives the WHOLE destination, not just the host: an interstitial hands the browser a
# url with a path, and fetching the bare host would land on a homepage the link never opened.
GEN='https://help_genderise_biz-dot-mmemails.appspot.com/em_1atsOJAfqJEKyrGRwosi?url=https://www.linkedin.com/company/genderise-rising-as-equals/'
check "full destination incl. path" 'https://www.linkedin.com/company/genderise-rising-as-equals/' "$(redirect_url "$GEN")"
check "host-only view is unchanged"  'www.linkedin.com' "$(redirect_target "$GEN")"
check "encoded destination decodes whole" 'https://evil.example/p' "$(redirect_url 'https://x.com/a?next=https%253A%252F%252Fevil.example%252Fp')"
check "no redirect param -> no url"  ''  "$(redirect_url 'https://x.com/a?b=c')"
check "non-url param -> no url"      ''  "$(redirect_url 'https://x.com/a?url=notaurl')"
# A javascript:/data: payload in the parameter must never come back as something to fetch.
check "non-http scheme is refused"   ''  "$(redirect_url 'https://x.com/a?url=javascript%3Aalert(1)')"

OBF='redirect target hidden by gratuitous percent-encoding (evil.example)'
check "obfuscated redirect is a red flag" 1 "$(count_red_flags com '' '' "$OBF" '' '')"
check "obfuscated redirect + login -> DANGEROUS" DANGEROUS "$(cv true com '' '' 'https://accounts.google.com/o' "$OBF" '' '' SAFE)"

echo "== campaign_key (what survives a domain rotation) =="
check "affiliate tag"          's1=upg12'  "$(campaign_key 'https://ul590.getmypair.space/?s1=upg12')"
check "same tag, other domain" 's1=upg12'  "$(campaign_key 'https://lxu438.getnew.space/?s1=upg12')"
check "different sub-campaign" 's1=snm3'   "$(campaign_key 'https://mg64.victorypuck.com/?s1=snm3')"
check "no query -> nothing"    ''          "$(campaign_key 'https://x.com/a/b')"
check "word value -> nothing"  ''          "$(campaign_key 'https://news.lawncots.co/?p=unsubscribe')"
check "utm is legit sharing"   ''          "$(campaign_key 'https://x.com/?utm_campaign=aug26')"
check "recipient email"        ''          "$(campaign_key 'https://x.com/?e=neil@example.co.za')"
check "long token"             ''          "$(campaign_key 'https://x.com/?token=cec793b0657b4035ab14d14a0e832939')"
check "digits only"            ''          "$(campaign_key 'https://x.com/?page=1234')"
# Per-victim tokens can only be grouped by the shape of the generator that made them. Both hops of
# the Google-OAuth chain carried this one, with different values.
check "token shape, hop 1" 'shape:state=alnum-digits' "$(campaign_key 'https://accounts.google.com/o/oauth2/v2/auth?scope=openid&state=p1KZOObfm27wFyTC1ju0T4ppj-14153490313725112891132624')"
check "token shape, hop 2" 'shape:state=alnum-digits' "$(campaign_key 'https://m-365a63c9-x.radiopanamericanapanama.com?state=hztgXDzNtHx7AgVxKr8clA5Zp-14332323313229262624419027112417262314192517911326913811')"
check "an ordinary token has no shape" '' "$(campaign_key 'https://x.com/?state=abc-123')"
# The subdomain label repeated as the path: one campaign, two unrelated registered domains.
check "label echo, domain 1" 'shape:label=u5xb' "$(campaign_key 'https://u5xb.eaotocephalic.digital/u5xb')"
check "label echo, domain 2" 'shape:label=u5xb' "$(campaign_key 'https://u5xb.iaoerheartwounding.digital/u5xb')"
# ... but docs.example.com/docs and blog.foo.com/blog are ordinary site structure
check "a word label is not a token" '' "$(campaign_key 'https://docs.example.com/docs')"
check "and neither is blog/blog"     '' "$(campaign_key 'https://blog.foo.com/blog')"
# The carrier must NOT group on its own: /ls/click with no tracking blob is every mailshot on the
# platform, and grouping there would put every legitimate sender behind one bad inspection.
check "sendgrid click link is not a campaign" '' "$(campaign_key 'http://url7037.comaround.com/ls/click?upn=u001.bmj3YK0AQCI1')"
# The blob's leading run IS the generator. Same operator, three unrelated customer domains, three
# per-recipient payloads -- and the 4-char chunk before the separator may itself contain '_'.
_sg='shape:sendgrid=RlEke38337DE9NoRp6M9QNtL5lwdCzbH'
check "sendgrid blob, domain 1" "$_sg" "$(campaign_key 'http://url7037.comaround.com/ls/click?upn=u001.bmj3YK0AQCI1-2BKgyVtOcfi-3D-3Da9um_RlEke38337DE9NoRp6M9QNtL5lwdCzbHiNt5hhDTsIyfD9zR2T-3D-3D')"
check "sendgrid blob, domain 2" "$_sg" "$(campaign_key 'http://url3695.gebesa.com/ls/click?upn=u001.SWp9zHIs4lB6d7ZV7uya-3D-3DbGUB_RlEke38337DE9NoRp6M9QNtL5lwdCzbHiNt5hhDTsIy1eavD2P-3D-3D')"
check "separator chunk holding _" "$_sg" "$(campaign_key 'http://url8083.calvis.com/ls/click?upn=u001.-2B8lUgkdiKuq91Fx-3D-3D83_G_RlEke38337DE9NoRp6M9QNtL5lwdCzbHiNt5hhDTsIwehMNSjP-3D-3D')"
# An unrelated legitimate sender has a different blob, so it must land in its own group, not ours
check "another sender, own group" 'shape:sendgrid=GVdTVisepyi0Aw01b0BRD4YM8I6Z2lIO' "$(campaign_key 'https://u16090459.ct.sendgrid.net/ls/click?upn=u001.fQA8MPQ1Ll0Ew-2FFTw7jM-3Dyd6E_GVdTVisepyi0Aw01b0BRD4YM8I6Z2lIOzarEEC-2BA8Jk-3D-3D')"
# Too short to be the constant run, or broken by an escaped +// inside it: no key beats a weak one
check "short blob -> nothing" '' "$(campaign_key 'https://x.ct.sendgrid.net/ls/click?upn=u001.abc-3D-3Dyd6E_RlEke38337DE9')"
check "escape inside the run" '' "$(campaign_key 'https://x.ct.sendgrid.net/ls/click?upn=u001.abc-3D-3Dyd6E_RlEke-2BFke38337DE9NoRp6M9QNtL5lwdCzbH')"
check "letters only"           ''          "$(campaign_key 'https://x.com/?lang=engb')"

echo "== is_tenant_suffix (where an apex means nothing) =="
expect "awsapprunner.com is shared"   yes is_tenant_suffix awsapprunner.com
expect "pages.dev is shared"          yes is_tenant_suffix pages.dev
expect "getnew.space is one owner"    no  is_tenant_suffix getnew.space
expect "zumbocloud.com is one owner"  no  is_tenant_suffix zumbocloud.com

echo "== is_tenant_infra (whose DNS is this?) =="
# The FP: an S3 endpoint's 8 A records and 297s TTL are the load balancer, not fast-flux.
expect "regional s3 endpoint is infra"  yes is_tenant_infra s3.us-east-1.amazonaws.com
expect "bare amazonaws.com is infra"    yes is_tenant_infra amazonaws.com
expect "cloudfront is infra"            yes is_tenant_infra cloudfront.net
expect "co.uk is a registry, not infra" no  is_tenant_infra co.uk
expect "space is a registry, not infra" no  is_tenant_infra space
# Tail match must not swallow a lookalike: notamazonaws.com is somebody else's domain.
expect "suffix must end on a boundary"  no  is_tenant_infra notamazonaws.com
# The vanity list is a SUBSET, and is_tenant_suffix is the union -- so a rollup stops at blogspot
# too, which it did not when the two lists were maintained separately.
expect "blogspot is shared for rollup" yes is_tenant_suffix blogspot.com
expect "appspot is shared for rollup"  yes is_tenant_suffix appspot.com

echo "== is_vanity_suffix (where the subdomain LABEL is a human choice) =="
expect "appspot hands out labels"     yes is_vanity_suffix appspot.com
expect "github.io hands out labels"   yes is_vanity_suffix github.io
expect "blogspot hands out labels"    yes is_vanity_suffix blogspot.com
# Kept OUT on purpose: an S3 bucket or CloudFront distribution named after its own owner is
# ordinary, so the brand-lookalike rule must not read "acmecorp-assets.s3.amazonaws.com" titled
# "Acme Corp" as impersonation. Still tenant suffixes above -- just not vanity ones.
expect "s3 buckets are not vanity"    no  is_vanity_suffix amazonaws.com
expect "cloudfront is not vanity"     no  is_vanity_suffix cloudfront.net
expect "esp infra is not vanity"      no  is_vanity_suffix maillist-manage.in
expect "a normal apex is not vanity"  no  is_vanity_suffix linkedin.com
check "prior host phishing counts once"     1          "$(count_red_flags com '' '' "$PRIOR" '' '')"
check "prior host phishing -> SUSPICIOUS"   SUSPICIOUS "$(cv false com '' '' 'https://h.com/other' "$PRIOR" '' '' SAFE)"
check "prior host phishing + login -> DANGEROUS" DANGEROUS "$(cv true com '' '' 'https://h.com/other' "$PRIOR" '' '' SAFE)"
check "prior host phishing never downgrades" DANGEROUS "$(cv false com '' '' 'https://h.com/x' "$PRIOR" '' '' DANGEROUS)"

echo "== category_of (what it is, independent of how bad) =="
# category_of <verdict> <has_login> <url> <smells> <deobfus> [title]
co() { category_of "$@"; }
check "login form -> phishing"        phishing      "$(co DANGEROUS true 'https://x.cfd/' '' '')"
check "exfil without a form -> phishing" phishing   "$(co DANGEROUS false 'https://x.cfd/' 'Off-domain exfil detected' '')"
check "unsub + bad -> email-harvest"  email-harvest "$(co SUSPICIOUS false 'https://x.com/unsubscribe?id=1' '' '')"
check "unsub + safe -> unsubscribe"   unsubscribe   "$(co SAFE false 'https://x.com/unsubscribe?id=1' '' '')"
check "wallet -> scam"                scam          "$(co DANGEROUS false 'https://x.com/' '' 'crypto wallet BTC revealed')"
check "VT hit -> scam"                scam          "$(co DANGEROUS false 'https://x.com/' 'VirusTotal flagged malicious (7 vendors)' '')"
check "nothing recognisable -> other" other         "$(co SUSPICIOUS false 'https://x.com/' '' '')"
check "safe login page -> login"      login         "$(co SAFE true 'https://x.com/signin' '' '')"
check "survey -> questionnaire"       questionnaire "$(co SAFE false 'https://x.com/s/abc' '' '' 'Customer Survey 2026')"
check "poll -> poll"                  poll          "$(co SAFE false 'https://x.com/vote/12' '' '')"
check "nps -> rating"                 rating        "$(co SAFE false 'https://x.com/r/9' '' '' 'Rate your experience')"
check "utm link -> marketing"         marketing     "$(co SAFE false 'https://x.com/p?utm_source=mail' '' '')"
check "plain page -> content"         content       "$(co SAFE false 'https://x.com/about' '' '')"
check "every guess is in the vocabulary" yes "$(is_category "$(co SAFE false 'https://x.com/about' '' '')" && echo yes)"
check "vision sees porn -> adult"     adult         "$(co SUSPICIOUS false 'https://xk51.efast.space/Qz' '' '' 'No swiping. No ghosting.' 'BRAND: none. PASSWORD: no. ADULT: yes')"
check "adult on a safe page too"      adult         "$(co SAFE false 'https://x.com/about' '' '' '' 'ADULT: yes')"
check "credential form outranks adult" phishing     "$(co DANGEROUS true 'https://x.cfd/' '' '' '' 'ADULT: yes')"
check "ADULT: no changes nothing"     other         "$(co SUSPICIOUS false 'https://x.com/' '' '' '' 'BRAND: none. PASSWORD: no. ADULT: no')"
check "UNCLEAR gets no category"      ""            "$(co UNCLEAR false 'https://x.com/survey' '' '')"
check "empty verdict gets no category" ""           "$(co '' false 'https://x.com/survey' '' '')"

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
