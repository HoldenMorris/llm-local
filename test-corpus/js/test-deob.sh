#!/bin/bash
# Golden test for js-deobfuscate.sh: webcrack must reveal the exfil URL that
# obfuscator.io hid inside obf-exfil.js. Fails if deobfuscation regresses.
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"

# Sanity: the fixture must actually be obfuscated (URL not in cleartext).
if grep -q 'evil.example' "$DIR/obf-exfil.js"; then
    echo "FAIL: fixture is not obfuscated (exfil URL visible in cleartext)"; exit 1
fi

OUT=$("$ROOT/js-deobfuscate.sh" "$DIR/obf-exfil.js")
if echo "$OUT" | grep -q 'evil\.example/steal'; then
    echo "PASS: deobfuscation revealed the hidden exfil URL evil.example/steal"
else
    echo "FAIL: exfil URL not revealed. Output was:"; echo "$OUT"; exit 1
fi
