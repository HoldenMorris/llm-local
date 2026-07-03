# Determinism Plan — "Goodbye Slop, Welcome to Determinism"

Applying David Khourshid's (XState) talk to this phishing-detection toolkit.
Source transcript: `docs/state-machine.txt`.

## 1. The talk, distilled

**Core thesis:** *Non-determinism at the edges, determinism at the core.* Write
**programs that call LLMs**, not **LLMs that call programs** ("deterministic
core, agentic shell" — the mirror of "functional core, imperative shell").

- **Determinism** = same input → same output. LLMs are non-deterministic (not
  random — a fixed set of choices). Statecharts exist to *contain* complexity
  and make it visual.
- **The root cause of slop is "unstructured delegation"** — throwing judgment,
  structure, and control flow over the wall to an agent. Slop predates AI; it's
  *"code without a reliable model"*: can't fully explain it, unsure edge cases
  are covered, invariants implicit, behavior scattered, no safe way to change.
- **LLMs weren't trained on good code — they were trained on *all* code.** They
  repeat and amplify your existing patterns, including bad assumptions.
- **The missing layer is an explicit *model*** — a structured representation of
  how the system should behave, between noisy markdown-intent and noisy code
  (~90% of code is boilerplate unrelated to behavioral intent).
- **Named anti-patterns:** one-shotting; **prose control flow** ("you MUST /
  never / only when…" in a prompt = control flow in natural language, *hoping*
  the model obeys); "more agents fixes it"; entangled concerns; "bigger context
  window fixes it" (more context ≠ more structure).
- **The fix isn't necessarily state machines — it's *structure*.** Only model
  the *confusing* parts ("modeling is not ceremony when it replaces confusion").
  Start rough, iterate. AI is good at helping you build the model.
- **Demo:** an email agent as an XState machine
  (`requirements → draft → iterate → send`) where deterministic transitions
  enforce invariants (can't send without an approved draft) and the LLM only
  does fuzzy work (is anything missing? write the draft).

## 2. Where this project already gets it right

- **`url-analyze.sh` is already a program that calls an LLM** — the inversion
  Khourshid preaches. Phases 1–3 (static URL, domain info, page fetch) are fully
  deterministic; only Phase 4 is the non-deterministic edge.
- **The "deterministic safety floor"** (`url-analyze.sh:328-359`) is *literally*
  the thesis in action: it re-asserts a deterministic core over the LLM's fuzzy
  verdict, escalating but never downgrading.

We're not starting from slop — we're one refactor away from the clean version.

## 3. Where it's still slop-shaped (the gaps)

1. **Prose control flow in `SYSTEM_PROMPT` (`url-analyze.sh:278-308`).** The
   `RULE 1 (MANDATORY)… RULE 2… RULE 3… RULE 4`, *"you must NOT downgrade,"*
   *"follow this decision procedure EXACTLY"* — the exact anti-pattern the talk
   names. It already **proved it fails**: the deterministic floor exists
   precisely because the prompt couldn't be trusted to do boolean AND-logic. The
   verdict decision procedure doesn't belong in a prompt at all.
2. **The verdict logic is duplicated and can drift:**
   - Red-flag definitions live in *both* the prompt (lines 282-291) *and* the
     bash floor (lines 333-344).
   - Two different risky-TLD lists (`url-analyze.sh:49` and `:333`) that will
     silently diverge.
3. **The model is implicit** — the verdict logic (the genuinely confusing part)
   is smeared across a prompt + a bash `if/elif` block. No single place says
   "these signals → this verdict."
4. **The core is unverifiable.** `benchmark.sh` tests the *email* classifier;
   there are **zero tests for `url-analyze.sh` verdicts.**

## 4. What model system actually fits (state machines etc.)

- **A state machine (XState) is the wrong tool here.** The pipeline is *linear*
  (phase 1→2→3→4 with early exits) — that's not where the confusion is, and
  XState is a JS/TS library that means a large dependency + rewrite of a bash
  toolkit. Violates both Ponytail and the talk's "don't add ceremony" rule.
- **The confusing part is the *verdict decision*, and its right model is a
  decision table** — a single, deterministic, data-driven `classify()` taking
  extracted signals → `SAFE | SUSPICIOUS | DANGEROUS`. Bash-native, zero deps,
  one source of truth.
- **The LLM gets demoted to a true edge role:** return a structured signal
  assessment / rationale, *not* the verdict.
- **A visual statechart earns its place only as documentation** — a Mermaid
  diagram in `docs/` of the pipeline + the decision table. The "blueprint for
  future-you and your agents" the talk closes on.

## 5. GSD plan

Three small, independently-shippable increments. Each ends committed and working.

### Phase 1 — Single-source the model (deterministic core)
- Extract the verdict logic into one pure function `classify_verdict()` (a
  decision table over the already-extracted signals), in a sourced `verdict.sh`
  — same pattern as `ollama-up.sh`.
- Dedupe: one `RISKY_TLDS`, one red-flag definition, consumed by both Phase 1
  display and the classifier.
- **Done when:** `url-analyze.sh` computes the verdict via `classify_verdict`;
  the floor logic is subsumed and the risky-TLD list exists once.

### Phase 2 — Demote the LLM to the edge
- Rewrite `SYSTEM_PROMPT` to drop `RULE 1-4`. The LLM returns a *signal
  assessment + short rationale* (fuzzy judgment on ambiguous signals — brand
  impersonation nuance, urgency tone), not a verdict.
- Deterministic `classify_verdict()` produces the final verdict; the LLM's
  rationale becomes explanatory context.
- **Done when:** the verdict is deterministic given fixed signals; the LLM can't
  override the core, only inform it.

### Phase 3 — Lock the core with golden tests
- A tiny harness (mirroring `benchmark.sh`'s shape) feeding fixed signal sets →
  asserting expected verdicts. No LLM, no network — pure core.
- Seed cases: login+risky-TLD→DANGEROUS, established-domain login→SAFE,
  unsubscribe-on-young-domain→SUSPICIOUS.
- **Done when:** `./test-verdict.sh` passes and pins the decision table.

### Optional Phase 4 — The blueprint
- Mermaid statechart of the pipeline + the decision table in `docs/`, linked
  from CLAUDE.md.
- **Done when:** a new reader (or agent) can see the model without reading 380
  lines of bash.

### Explicitly NOT doing (Ponytail / anti-ceremony)
No XState, no new runtime dependency, no rewrite out of bash, no formal spec
language. The "model" here is a decision table + a diagram, nothing heavier.
