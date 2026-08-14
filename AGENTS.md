# AGENTS.md

Agent-facing brief. **[`CLAUDE.md`](CLAUDE.md) is the source of truth** for what this toolkit
detects and why each detection is capped where it is — read it before changing detection code.
This file only covers how to work in the repo.

## What this is

A URL/page phishing detection toolkit. `./url-analyze.sh <url>` renders the page in a sandbox and
prints `SAFE | SUSPICIOUS | DANGEROUS` plus a category and the signals behind both. Two layers:

- **Deterministic core** — `verdict.sh` (`classify_verdict`, `category_of`, `campaign_key`,
  `redirect_url`). Pure: no network, no LLM. It sets a safety **floor** that escalates over the
  LLM and never downgrades. Pinned by `test-verdict.sh` (188 golden cases).
- **Agentic shell** — `url-analyze.sh` orchestrates the phases and calls the LLM last, for a
  rationale on top of the floor. See [`docs/determinism-plan.md`](docs/determinism-plan.md).

The email-spam benchmark (`benchmark.sh`, `test-corpus/`, `prompts/`) is the original tool and
still works, but it is not where the work is.

## Rules that are not negotiable

1. **A detection fix ratchets BOTH paths forward.** Deterministic floor *and* LLM prompt, never one
   traded against the other. A one-sided patch just moves the false result around. Full reasoning:
   CLAUDE.md → "Detection changes drive forward".
2. **Pin every fix with a golden case** in `test-verdict.sh`, and confirm a known-good page does not
   regress.
3. **Cap each new floor at the severity the signal earns.** A login page plus one off-CDN host is
   SUSPICIOUS, not DANGEROUS.
4. **A factless scan degrades to UNCLEAR, never SAFE.** "Saw nothing, called it clean" is the
   recurring bug class in this repo.
5. **Never commit scan artifacts.** `.cache/` and `url-corpus-live.txt` are gitignored because live
   phishing URLs carry recipient email addresses and reset tokens. Grep before you add a fixture.
6. **Ponytail mode** — see the ladder at the top of CLAUDE.md. Shortest working diff, reuse before
   writing, mark deliberate shortcuts with a `ponytail:` comment.

## Before you commit

```bash
./test-verdict.sh          # 188 golden cases, pure
./feedback-report.sh --self-test
./next-alert.sh --self-test
./brand-verify.sh --self-test
./psl.sh && ./inspect.sh   # self-checks
bash -n page-fetch.sh      # and node --check the embedded JS if you touched it
```

None of these touch the network or a live site.

## Where new detection ideas come from

`./intel-feed.sh` prints what is new in the threat-intel feed, each item tagged with the detections
we already have — or `NO MATCHING DETECTION`, which is the line worth an hour. Read the post for the
**mechanism**, then ask what deterministic artifact survives a kit rebuild. That is the only part
worth a signature.

The other source is the ledger: `./feedback-report.sh -f` lists the scans an analyst flagged as
wrong and nobody has triaged yet.

## Publishing

`./sync-to-luca.sh` exports this repo's **HEAD** into `luca-ecosystem/tools/local-llm` on a fresh
branch and prints a PR link. This repo stays the source of truth; never hand-edit the copy there.
It refuses to run on a dirty tree, and it exports tracked files only, so `.env` and `.cache/` can
never leak. The script itself is `export-ignore`d, so if you are reading this **inside**
`luca-ecosystem` you are looking at a point-in-time snapshot: the changes go in the source repo,
and a re-sync brings them here.
