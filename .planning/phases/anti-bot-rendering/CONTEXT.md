# Context: Turnstile cloaking & bypass landscape (operator brief)

Threat actors increasingly hide phishing landing pages behind **Cloudflare Turnstile** as an
anti-analysis / cloaking layer: it stops lightweight crawlers, signature scanners and bots from
executing the backend phishing script, hiding the kit from automated threat intel. Observed
firsthand on `versmo.z13.web.core.windows.net/mon.html` -> `oxyma.online` -> `zbeem.top/.../login.php`
(Turnstile-gated, CF-fronted, `.top` throwaway).

How TI platforms / scanners drop the veil (operator-provided):

1. **Stealth browser automation** — default headless Selenium/Puppeteer/Playwright leak
   `navigator.webdriver=true` and default fingerprints. Undetected engines (SeleniumBase UC
   mode, Camoufox) patch browser properties at the C++/binary level and *temporarily disconnect
   the automation control connection during Turnstile verification* so the challenge can't detect
   the hook. Behavior simulation: Bezier-curve mouse movement + randomized delays to tick an
   interactive checkbox if Turnstile escalates.
2. **Fingerprint matching & JA4 spoofing** — Cloudflare passively fingerprints before rendering
   a challenge. The TLS **JA4** (cipher suites, extensions, TLS versions) must match the claimed
   UA; WebAPI camouflage matches Canvas/AudioContext/CPU cores/resolution/fonts for a high
   reputation score.
3. **High-reputation residential/mobile proxies** — datacenter IPs (AWS/Azure/DO) are near-
   universally flagged into the hardest interactive loops. Residential/mobile ASNs get evaluated
   under low-risk policies, so Turnstile often passes natively in "Managed (Invisible)" mode with
   no interactive click.
4. **API solvers & pre-clearance harvesting** — when passive bypass fails: extract the public
   Turnstile **sitekey** from the HTML, send sitekey+URL to a solver service, get a token, inject
   it into the form payload or append the resulting **`cf_clearance`** cookie to the session ->
   the uncloaked page is open for DOM extraction, screenshotting, brand-abuse analysis.

**Defensive value:** in isolated sandboxes this lets TI teams pull phishing kits, extract C2
configs, and update gateways before users hit the link.

## Operator-in-the-loop (preferred for THIS tool)
> "we can use browser automation tools as a local agent driven by operator (me) to move past the gate"

For a local, human-run scanner the cleanest path is **assisted**: the operator (residential IP,
real browser, can solve an interactive challenge) passes the gate once; the tool then does the
heavy lifting on the *uncloaked* page. Sidesteps JA4 spoofing / solver services / proxy costs and
their ethical baggage. See PLAN for the concrete shape.
