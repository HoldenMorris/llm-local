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
check "prior host phishing counts once"     1          "$(count_red_flags com '' '' "$PRIOR" '' '')"
check "prior host phishing -> SUSPICIOUS"   SUSPICIOUS "$(cv false com '' '' 'https://h.com/other' "$PRIOR" '' '' SAFE)"
check "prior host phishing + login -> DANGEROUS" DANGEROUS "$(cv true com '' '' 'https://h.com/other' "$PRIOR" '' '' SAFE)"
check "prior host phishing never downgrades" DANGEROUS "$(cv false com '' '' 'https://h.com/x' "$PRIOR" '' '' DANGEROUS)"

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
