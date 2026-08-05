#!/bin/bash

# Extract phishing signals from DEOBFUSCATED JavaScript. Safe: it only greps text, it never
# executes the code. Source this file, then call js_signals.
#
# js_signals [file]   (reads stdin if no file) -> one-line, comma-joined summary on stdout
#                     (empty if nothing notable). Set LANDED_DOMAIN to mark off-domain URLs
#                     as exfil endpoints. Set ORIG_JS=<file> to the PRE-deobfuscation source so
#                     only genuinely hidden URLs count as exfil (see below).

js_signals() {
    local js; js=$(cat "${1:-/dev/stdin}" 2>/dev/null)
    [ -z "$js" ] && return 0
    # Zero-width characters are sprinkled through kit source purely to break string matching
    # (Cephas does it by design; "eva​l(" matches no rule anyone wrote). Strip them before
    # anything below looks at the text -- every pattern here is a string match.
    local zw; zw=$(printf '%s' "$js" | grep -oP '[\x{200B}-\x{200D}\x{2060}-\x{2064}\x{FEFF}\x{00AD}]' 2>/dev/null | wc -l)
    js=$(printf '%s' "$js" | perl -CSD -pe 's/[\x{200B}-\x{200D}\x{2060}-\x{2064}\x{FEFF}\x{00AD}]//g' 2>/dev/null || printf '%s' "$js")
    local dom="${LANDED_DOMAIN:-}" out=""
    # The pre-deobfuscation source, when the caller supplies it. A URL already sitting verbatim in
    # it was never hidden -- webcrack just prettified a minified bundle -- and a plain readable
    # host is auditable, overwhelmingly CDN/analytics/first-party infra (youtube.com's own bundle
    # names accounts.google.com), NOT covert theft. Only URLs deobfuscation actually REVEALED
    # (in the cleartext, absent from the source) are exfil. Same rule page-fetch.sh already applies.
    local orig=""
    [ -n "${ORIG_JS:-}" ] && [ -f "${ORIG_JS:-}" ] && orig=$(cat "$ORIG_JS" 2>/dev/null)
    _add() { out+="${out:+, }$1"; }

    # URLs referenced in code (fetch/xhr/form-action/redirect targets). Dedup, cap 5.
    local u h
    while IFS= read -r u; do
        [ -z "$u" ] && continue
        h=$(printf '%s' "$u" | sed -E 's|https?://([^/]+).*|\1|')
        # Compare the HOST, not the whole URL: minifiers escape query strings (& for &), which
        # deobfuscation decodes, so a verbatim URL match spuriously fails. The host is also what
        # exfil actually turns on -- where data could go.
        if [ -n "$dom" ] && ! printf '%s' "$h" | grep -qiF "$dom" \
           && ! { [ -n "$orig" ] && printf '%s' "$orig" | grep -qiF "$h"; }; then
            _add "off-domain URL: $u"
        else
            _add "URL: $u"
        fi
    done < <(printf '%s' "$js" | grep -oiE "https?://[a-z0-9.-]+[^\"' )>]*" | sort -u | head -5)

    # Data-exfil sinks
    printf '%s' "$js" | grep -qE 'document\.cookie'                                    && _add "reads document.cookie"
    printf '%s' "$js" | grep -qiE 'fetch\s*\(|XMLHttpRequest|\.send\s*\(|sendBeacon'   && _add "network send (fetch/xhr/beacon)"
    printf '%s' "$js" | grep -qiE 'localStorage|sessionStorage'                        && _add "web storage access"
    # Redirects
    printf '%s' "$js" | grep -qiE 'location\.(href|replace|assign)|window\.location\s*=' && _add "JS redirect"
    # Dynamic-exec sinks still present in the cleartext
    printf '%s' "$js" | grep -qE 'eval\s*\('                                           && _add "eval()"
    printf '%s' "$js" | grep -qE 'atob\s*\('                                           && _add "atob()"
    # Crypto wallet addresses. Boundary-guarded, exactly like page-fetch.js: unanchored,
    # "T[A-Za-z1-9]{33}" matches INSIDE any long minified identifier, so every minified bundle
    # reported a phantom wallet.
    printf '%s' "$js" | grep -qE '(^|[^a-zA-Z0-9])(bc1[a-z0-9]{39,59}|0x[a-fA-F0-9]{40}|T[A-Za-z1-9]{33})([^a-zA-Z0-9]|$)' && _add "crypto wallet address"

    # Anti-analysis code. This is the kit checking whether it is talking to US -- headless Chrome,
    # on Linux, from a datacentre IP -- and it is worth more than most content signals, because a
    # page that probes for automation before showing itself has something to hide.
    #
    # The probe list is the discriminator, not any single name. Legitimate bot-protection scripts
    # test navigator.webdriver, and analytics libraries test one or two more; the kits enumerate
    # the whole family in a fixed order (Datadog found the identical sequence across every 1Phish
    # V2+ sample). So the threshold is FOUR distinct names -- below that it is context, not a claim.
    local _names; _names=$(printf '%s' "$js" \
        | grep -oE 'webdriver|__nightmare|_Selenium_IDE_Recorder|_selenium|callPhantom|_phantom|__firefoxDriver|__stopAllTimers|__driver_evaluate|__webdriver_script_fn|domAutomation' \
        | sort -u | wc -l)
    [ "${_names:-0}" -ge 4 ] && _add "anti-analysis: probes for $_names browser-automation artifacts"
    # A debugger statement inside a timer is not debugging, it is a trap: it freezes devtools every
    # 100ms so nobody can read the page. Same for blocking F12 / Ctrl-Shift-I.
    # [^;] and not [^)]: the trap is normally set(Interval)(function(){debugger},100), so the
    # parenthesis class stopped at the arrow/function's own parens and never reached the keyword.
    printf '%s' "$js" | grep -qzE 'set(Interval|Timeout)[^;]{0,120}debugger' && _add "anti-analysis: debugger trap in a timer"
    printf '%s' "$js" | grep -qE 'keyCode\s*===?\s*123|["'"'"']F12["'"'"']' \
        && printf '%s' "$js" | grep -qiE 'shiftKey|ctrlKey' && _add "anti-analysis: devtools keys blocked"
    # Kits query an IP-reputation API and refuse cloud/scanner ranges. ipapi.is is the one the
    # current AiTM families use; the generic ip-echo services are already a page-fetch smell.
    printf '%s' "$js" | grep -qiE 'ipapi\.is|ip-?api\.com/json|ipwho\.is' \
        && printf '%s' "$js" | grep -qiE 'hosting|datacent|is_?proxy|is_?vpn|asn' \
        && _add "anti-analysis: datacentre/VPN IP filtering"
    # The script deleting itself once it has run, so a DOM dump shows nothing.
    printf '%s' "$js" | grep -qE 'currentScript[^;]{0,40}\.remove\(|removeChild\s*\(\s*document\.currentScript' \
        && _add "anti-analysis: script removes itself from the DOM"
    [ "${zw:-0}" -gt 20 ] && _add "anti-signature: $zw invisible characters padded into the source"

    printf '%s' "$out"
}
