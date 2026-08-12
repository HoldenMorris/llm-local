# Plan: follow-up from the 2026-08-12 scan review

Context and evidence: [CONTEXT.md](CONTEXT.md).

**Goal (what must be TRUE):** every signal we print has a known precision, the vision model's new
claim is measured rather than assumed, and a settled ledger row cannot quietly contradict itself.

Cheapest first. Each task ships independently and commits on its own. Every one of these is
answerable from artifacts already on disk — 293 cache entries, ~290 screenshots and 147 labelled
URLs — so none of them needs a new scan of live infrastructure.

---

## 1. Measure signal precision from the ledger  ← START HERE

**Why:** the FP cost a human triage while the verdict was right the whole time. We rank signals by
nothing today. The ledger already holds 147 settled URLs with true labels.

**Build:** `feedback-report.sh --signals` (or a small script). For each distinct signal string in
the cached `page.json` / scan output of every **settled** URL, print: times seen on settled-bad,
times on settled-SAFE, and the ratio.

**Done when:** the output ranks every signal we emit, and the ones that appear as often on SAFE
pages as on bad ones are named. Expect the third-party-hosts note and the low-TTL line to look
poor; the point is to find out rather than to guess.

**Then:** demote or drop the worst — but a signal excluded from `count_red_flags` is still LLM
context and still analyst attention, so "demote" means *stop printing it*, not just stop counting
it. Re-run the 147-URL replay to confirm no verdict moves.

## 2. Validate the VLM's ADULT answer on the cached screenshot corpus

**Why:** shipped on six pages. ~290 screenshots are already on disk, and the call needs no network.

**Build:** a throwaway loop putting the current vision prompt over every `page.jpg` in `.cache/`,
recording the `ADULT` line against the URL's settled category.

**Done when:** we know the false-positive rate on non-adult pages, and specifically whether the
lingerie/swimwear/dating-photo carve-out holds outside the one sibling that tested it.

**Watch for:** the same unreliability that produced `PASSWORD: yes` on a page with no form. If
ADULT proves as loose, cap it further — a wrong `adult` category on a real business page is a
slur, not a mis-scored flag.

## 3. Audit the ledger for rows that contradict themselves

**Why:** a `SUSPICIOUS/phishing` row whose note says "this is a legitimate service" drove
`--settled` to auto-confirm and poisoned the replay corpus. It is the ledger's own integrity, and
the ledger is the thing every other measurement here depends on.

**Build:** `feedback-report.sh --audit` — deterministic checks only, no LLM:
- category `phishing` on a URL whose cached `page.json` never showed a credential form or exfil
- settled bad with a note containing an explicit negation ("legit", "real service", "not a phish")
- settled rows whose URL no longer appears in any cache directory

**Done when:** it flags the `wfse` row shape, and running it over today's ledger produces a list
short enough to work through by hand.

**Not doing:** blocking the write. A human disagreeing with the machine is exactly what the ledger
is for, and refusing their input would be worse than an occasional bad row. Audit after, never gate.

## 4. Random tenant label as its own signal

**Why:** on shared infrastructure the tenant label is the only part the registrant chose, so
`b6596g` carries the same meaning `lxu438` does on a registrable domain — but it is 6 characters
and `is_random_label` needs >8.

**Build:** when `is_tenant_infra(suffix_of(host))`, judge `head_of(host)` with a threshold suited
to a label rather than a hostname.

**Validate BEFORE shipping** against the 20 tenant-infra hosts in the corpus. The legitimate ones
there — `accelo-us-west-2-attachments`, `lalitmaurya`, `danselem`, `supreviewinfo` — are the FP
test. If a shorter threshold flags any of them, the idea is wrong at that threshold.

**Cap:** one red flag at most, and SUSPICIOUS without a credential form. A random bucket name is
how half of legitimate cloud storage is named.

## 5. Decide the severity of unsolicited adult delivery

**Not code — a decision, and it is Holden's.** Currently `adult` is category-only and never floors.
The question: does explicit imagery delivered to a *named recipient* by mail link earn a floor on
its own, independent of what the domain scores?

Consider before answering: the category exists so the ledger can be mined by kind, and severity
and category were deliberately made independent. A floor here starts re-coupling them.

---

## Explicitly not in this phase

- **Vision on every page.** Trigger 3 exists because ~50s per scan is the constraint; making the
  VLM unconditional trades every scan's latency for one category.
- **Fixing the VLM's `PASSWORD` unreliability at source.** It is a 4-bit quantised model doing what
  those do. The cap already contains it. Revisit only if a better small VLM appears
  (`model-scout.sh`).
- **urlscan on gated pages.** Separate decision, already written up in
  `../anti-bot-rendering/RESEARCH-2026-08.md`.
