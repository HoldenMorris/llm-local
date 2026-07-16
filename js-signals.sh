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

    printf '%s' "$out"
}
