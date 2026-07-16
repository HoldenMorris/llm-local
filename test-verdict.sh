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

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
