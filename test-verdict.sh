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
# A carrier shape must NOT group: every legitimate mailshot on the platform would join the phish
check "sendgrid click link is not a campaign" '' "$(campaign_key 'http://url7037.comaround.com/ls/click?upn=u001.bmj3YK0AQCI1')"
check "letters only"           ''          "$(campaign_key 'https://x.com/?lang=engb')"

echo "== is_tenant_suffix (where an apex means nothing) =="
expect "awsapprunner.com is shared"   yes is_tenant_suffix awsapprunner.com
expect "pages.dev is shared"          yes is_tenant_suffix pages.dev
expect "getnew.space is one owner"    no  is_tenant_suffix getnew.space
expect "zumbocloud.com is one owner"  no  is_tenant_suffix zumbocloud.com
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
check "UNCLEAR gets no category"      ""            "$(co UNCLEAR false 'https://x.com/survey' '' '')"
check "empty verdict gets no category" ""           "$(co '' false 'https://x.com/survey' '' '')"

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
