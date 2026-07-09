# Research: JS deobfuscation tool choice

**Question:** Is JStillery the best tool to detect/deobfuscate obfuscated page JS
inside `url-analyze.sh`? (User was unsure.)

**Answer: No. Use `webcrack` as primary, `REstringer` as optional escalation. Reject JStillery.**

## The security constraint that decides it

`url-analyze.sh` ingests **live phishing pages**. The deobfuscator runs on attacker-
controlled JS. So the single most important property is: *does the tool execute the
obfuscated code to deobfuscate it?*

| Tool | Method | Executes attacker JS? | Maintained | obfuscator.io | Install |
|------|--------|----------------------|-----------|---------------|---------|
| **webcrack** (j4k0xb) | Static AST (Babel), scope-aware | **No** (default) | Yes, v2.16 (active) | Yes (native target) + unminify/unpack | `npx webcrack` (Node 22/24) |
| **REstringer** (HumanSecurity) | Hybrid: safe AST + "unsafe" dynamic | Only unsafe modules, **sandboxed** (`isolated-vm`) | Yes, v2.1.0 Nov 2025 | Yes (dedicated processor) | `npm i -g restringer` (Node 20+) |
| **synchrony** (relative) | Static AST | No | Moderate | Yes | `npx deobfuscator` |
| **JStillery** (mindedsecurity) | **Partial evaluation = runs the code** | **Yes** | Stale (~2018) | Generic | Node CLI/web/REST |

## Why webcrack over JStillery

1. **Safety.** webcrack transforms the AST statically — it never runs the malware. JStillery
   *must* execute it (that's how partial evaluation works), so it needs the same hard sandbox
   we already give Puppeteer, and even then it's the riskiest option.
2. **Fit.** The dominant obfuscator in phishing kits is `javascript-obfuscator` (obfuscator.io):
   string-array rotation/shuffle, control-flow flattening, dead-code, self-defending. webcrack
   targets exactly this and auto-detects it (no config).
3. **Maintenance.** webcrack is active; JStillery is effectively abandoned and dependency-stale.
4. **Ops.** `npx webcrack` drops into a small Node container next to the existing Puppeteer one.

## Why keep REstringer in reserve

Some phishing JS uses custom/rolled obfuscation webcrack won't fully resolve. REstringer's
sandboxed dynamic modules (`isolated-vm`) can crack those *without* running code on the host.
Add it as a second-pass escalation only if webcrack output still looks obfuscated. YAGNI until seen.

## Decision

- **Primary:** `webcrack` (static, safe, maintained, obfuscator.io).
- **Escalation (optional, later):** `REstringer`, sandboxed.
- **Rejected:** `JStillery` (executes attacker JS, unmaintained).
- **Non-negotiable:** whichever tool runs, it runs in a locked-down, `--network none` container.
  Never deobfuscate on the host.

## Sources
- webcrack — https://github.com/j4k0xb/webcrack , https://www.npmjs.com/package/webcrack
- REstringer — https://github.com/HumanSecurity/restringer
- JStillery — https://github.com/mindedsecurity/JStillery
- synchrony — https://deobfuscate.relative.im/
- javascript-obfuscator — https://github.com/javascript-obfuscator/javascript-obfuscator
