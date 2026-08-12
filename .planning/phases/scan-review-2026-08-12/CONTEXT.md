# Context: what two scans on 2026-08-12 exposed

Both scans shipped fixes the same day (`353f825`, `7ed5f1a`, `622e68a`, `b492f00`). This is the
review of what they exposed *beyond* those fixes — the parts still open.

Neither URL is reproduced in full here: the live one carries a recipient's email address in its
redirect target. Host and shape only.

## Scan 1 — `xk51.efast.space/…` : an adult gateway that nothing could name

**What it is:** a full-page grid of explicit images with an `Enter` link. Zero forms. Title:
"No swiping. No ghosting. Just something that clicks." Reached from a mail link carrying a
per-recipient address and an `?s1=upg12` campaign tag.

**What the scan did:** `SUSPICIOUS (other)` — correct severity from the 0-day domain, fast-flux
TTL and `atob()` redirect, but `other` is the category we emit when we have nothing to say.

**Why:** the page is *entirely pictures*. Scraped text says nothing, and zero forms disarms every
login-gated escalation — so the vision model, our only instrument that could see it, never ran.

**Fixed:** a third vision trigger (formless page carrying a red flag) plus an `ADULT` line in the
VLM prompt, feeding `category_of`. Now reads `SUSPICIOUS (adult)`.

**Still open:**

1. **The ADULT answer is validated on six pages.** One true positive, five true negatives —
   including the same operator's clothed dating-lure sibling, which correctly answered no. Six is
   an anecdote. There are ~290 cached screenshots sitting on disk that could answer this properly.
2. **A clean-looking adult page still gets no look.** Trigger 3 requires a red flag. An adult
   gateway on an aged domain with a valid cert and no risky JS scores zero, so vision never runs
   and the category stays `content`. We caught this one because its *domain* was hostile, not
   because of what it was.
3. **The VLM lies about credential fields, and we found that by accident.** `PASSWORD: yes` on a
   formless `github.io` newsletter set `HAS_LOGIN` and floored it DANGEROUS (phishing). The cap
   (trigger 3 is category-only) fixes the blast radius, not the underlying unreliability —
   triggers 1 and 2 still trust that answer, on pages that at least have a form.
4. **Severity is undecided.** Unsolicited explicit imagery delivered to a named recipient by mail
   link is capped at whatever the domain earns. Deliberate — porn is not phishing — but nobody has
   actually decided whether that is the right answer for *unsolicited* delivery.

## Scan 2 — `wfse.s3.us-east-1.amazonaws.com/2608SCE.html` : five signals, all false

**What it is:** the S3-hosted "view this e-statement in your browser" page for a genuine
Woolworths Financial Services mailing, sent through Constellation/Bidvest over Amazon SES.

**What the scan did:** verdict `SAFE` — and then five signals: amazon typosquat, 5-level
subdomains, random domain `wfses3useast1amazonaws`, 8 A records, 297s TTL.

**Why:** every one of those checks read the **public suffix** as if the registrant had chosen it.
`s3` and `us-east-1` even supplied the two digits `is_random_label` requires. `psl.sh` knew the
suffix and simply did not expose it.

**Fixed:** `suffix_of` / `head_of` in `psl.sh`; typosquat, subdomain depth and entropy now judge
the head; fast-flux gated on `is_tenant_infra`. Signals 5 → 0. A 147-URL replay moved **no
verdict** and held all seven DANGEROUS tenant-infra rows.

**Still open:**

1. **The verdict was never wrong — and it cost a human triage anyway.** This is the finding. A
   signal that changes no verdict is not free; it is what an analyst pays attention with. We have
   no measure of which signals are noise, and 147 labelled URLs sitting in the ledger that could
   produce one.
2. **The triage wrote a self-contradicting row**, and nothing objected: verdict `SUSPICIOUS`,
   category `phishing`, note *"THis is in fact just a 'view email in webpage' link from a real
   service"*. That row then drove `--settled` to exit 2 (auto-confirm as bad) and exported a false
   label into the replay corpus. Corrected by hand on 2026-08-12; the flow that allowed it is
   unchanged.
3. **The replay surfaced a real gap while removing a false one.** `b6596g.s3.us-east-1.amazonaws.com`
   lost its random-domain signal legitimately — the bucket name is 6 characters and the threshold
   is >8. It only ever fired because we were gluing AWS's labels onto it. But on a tenant host that
   label is the *only* thing the registrant chose, and a machine-generated one is meaningful. We
   have no signal for it.
