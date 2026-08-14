#!/bin/bash

# Sandboxed page fetcher + feature extractor
# Uses Puppeteer in a disposable container
# Outputs JSON with page features for LLM analysis

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Leading flags: -m/--mobile (mobile UA vs mobile-only cloakers), -p <tor|none> egress proxy,
# -g <cc> Tor exit country (ISO code). See .planning/phases/ip-routing.
UA_MODE="desktop"; PROXY="none"; EXIT_CC=""
while [[ "${1:-}" == -* ]]; do
  case "$1" in
    -m|--mobile) UA_MODE="mobile"; shift ;;
    -p) PROXY="$2"; shift 2 ;;
    -g) EXIT_CC="$2"; shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
URL="${1:?Usage: $0 [-m|--mobile] [-p tor|none] [-g <cc>] <url>}"

# ponytail: PAGE_SHOT=<host .png/.jpg> also saves a viewport screenshot there, for
# the vision-model escalation step. Unset = no screenshot, no output change.
SHOT="${PAGE_SHOT:-}"

# ponytail: PAGE_SCRIPTS_DIR=<host dir> dumps FULL inline script bodies there, but only
# when obfuscation markers fire, for the JS-deobfuscation escalation. Unset = no dump.
SCRIPTS_DIR="${PAGE_SCRIPTS_DIR:-}"

# Config: brand-impersonation match mode. strict (default) = title/form-action only;
# body = also match body-text mentions (noisier). Passed into the container below.
BRAND_MATCH="${BRAND_MATCH:-strict}"

CONTAINER_NAME="llm-page-fetch-$$"
IMAGE="ghcr.io/puppeteer/puppeteer:latest"
# Per-process, like the container name above. It used to be a fixed /tmp/page-fetch.js, which made
# two concurrent fetches destroy each other: the first one to finish rm'd the file, and the other's
# `docker run -v` then found no source path -- so Docker CREATED ONE, as a root-owned directory.
# Every fetch after that died on "cat: /tmp/page-fetch.js: Is a directory", and page-fetch.sh exits
# 1 with an empty stdout, which every caller reads as a page that would not load. A whole parallel
# corpus sweep came back "dead host" that way.
JS_TMP="/tmp/page-fetch-$$.js"
# A wall-clock cap on the whole fetch. Puppeteer's own timeouts bound individual steps (goto 60s,
# readyState 10s) and NOT the fetch as a whole: one live page held a 220-url corpus replay for five
# minutes, and this script is the step an alert pipeline would sit behind, where five minutes is a
# stalled queue rather than a slow scan. On expiry the caller sees an empty stdout and a non-zero
# exit -- which is already how it reads a fetch that failed, so a timed-out scan degrades to
# UNCLEAR the same way a dead host does, and never to SAFE.
# The container is killed explicitly: --rm only fires when the client exits normally, so a killed
# client would otherwise leave a container (and a docker-held /out mount) behind.
PAGE_TIMEOUT="${PAGE_TIMEOUT:-180}"
trap 'rm -f "$JS_TMP"; docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1' EXIT INT TERM

cat << 'SCRIPT' > "$JS_TMP"
const puppeteer = require('puppeteer');
const { URL } = require('url');
const tls = require('tls');

// Does the host answer a TLS handshake on :443? Distinguishes an http-only kit (no HTTPS at all)
// from a real site that serves https but doesn't force-redirect http->https. Cert validity is
// irrelevant here -- we only ask "is TLS offered", so rejectUnauthorized:false.
const httpsAvailable = (host, timeout = 5000) => new Promise((res) => {
  const s = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout }, () => { s.destroy(); res(true); });
  s.on('error', () => res(false));
  s.on('timeout', () => { s.destroy(); res(false); });
});

(async () => {
  const targetUrl = process.argv[2];
  const parsed = new URL(targetUrl);
  // Registrable domain. ponytail: no PSL dependency -- just treat a known second-level suffix
  // ("co" in paypal.co.uk) as part of the TLD, else apexOf('paypal.co.uk') is 'co.uk' and every
  // legit ccTLD brand site (barclays.co.uk, amazon.co.jp) reads as brand impersonation.
  // ponytail: covers the ccTLD shapes we see; swap in the real PSL if an edge case bites.
  const SLD_SUFFIX = /^(co|com|net|org|ac|gov|edu|ne|or|in)$/;
  // The real Public Suffix List, mounted read-only by page-fetch.sh (same cached file psl.sh
  // maintains, so the bash and JS halves can never disagree about who owns a domain). Absent
  // list -> fall back to the heuristic above, which is wrong for multi-label suffixes in exactly
  // the way it always was: losing the file must change nothing else. See psl.sh for the why.
  let PSL = null;
  try {
    PSL = new Set(require('fs').readFileSync('/home/pptruser/psl.dat', 'utf8')
      .split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('//')));
  } catch {}
  const apexOf = h => {
    const host = (h || '').toLowerCase().replace(/\.$/, '');
    if (!host) return '';
    if (PSL) {
      let rest = host, suffix = '';
      while (rest) {                                    // longest rule wins -> longest-first walk
        const up = rest.includes('.') ? rest.slice(rest.indexOf('.') + 1) : '';
        if (PSL.has('!' + rest)) { suffix = up; break; }             // exception rule
        if (PSL.has(rest) || (up && PSL.has('*.' + up))) { suffix = rest; break; }
        rest = up;
      }
      if (!suffix) suffix = host.slice(host.lastIndexOf('.') + 1);   // implicit "*" rule
      if (suffix === host) return host;                 // host IS a suffix: no registrable domain
      const head = host.slice(0, host.length - suffix.length - 1);
      return head.slice(head.lastIndexOf('.') + 1) + '.' + suffix;
    }
    const p = host.split('.');
    return p.slice(p.length >= 3 && SLD_SUFFIX.test(p[p.length - 2]) ? -3 : -2).join('.');
  };
  // let: re-anchored to the LANDED host after redirects so analysis isn't judged against the entry shortener
  let domain = parsed.hostname;
  let apexDomain = apexOf(domain);
  // The apex we STARTED on, kept across the re-anchor above. An SSO hop leaves the tenant apex
  // (cogtanw.eu.qlikcloud.com -> login.qlik.com), after which the OAuth redirect_uri host -- the
  // origin's own apex -- read as off-domain exfil and floored genuine Qlik/Auth0 SSO to DANGEROUS.
  // ponytail: an entry shortener also gets its apex exempted; an exfil endpoint hosted on the
  // shortener's own apex is not a shape we've seen. Tighten if one shows up.
  const originApex = apexDomain;
  const sameSite = h => { const a = apexOf(h); return a === apexDomain || a === originApex; };

  // Operator attach mode (PAGE_ATTACH=<CDP browserURL>): connect to the analyst's OWN browser,
  // which already walked past the bot gate on a residential IP. No launch, no navigation, no
  // stealth -- we just read the live, uncloaked DOM the human is looking at. See url-analyze.sh
  // and .planning/phases/anti-bot-rendering.
  const attach = process.env.PAGE_ATTACH || '';
  const proxy = process.env.PAGE_PROXY || '';   // e.g. socks5://llm-tor:9050 (Tor egress)
  const uaMode = process.argv[3] || 'desktop';
  let browser, page;
  if (attach) {
    browser = await puppeteer.connect({ browserURL: attach, defaultViewport: null });
    const tabs = await browser.pages();
    // The tab the operator left on the real page: last non-blank, non-devtools tab.
    page = tabs.filter(p => { const u = p.url(); return u && u !== 'about:blank' && !u.startsWith('devtools://'); }).at(-1) || tabs.at(-1);
    if (!page) { console.log(JSON.stringify({ error: 'attach: no open tab found' })); await browser.disconnect(); process.exit(0); }
  } else {
    browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-first-run',
        '--disable-blink-features=AutomationControlled',  // one more automation tell CF checks
        // keep an http:// URL on http; else http-only kits die on Chrome's silent https upgrade
        '--disable-features=HttpsUpgrades,HttpsFirstBalancedMode,HttpsFirstModeV2',
        // Egress proxy (Tor). Chrome SOCKS5 resolves target DNS remotely -> no DNS leak.
        ...(proxy ? [`--proxy-server=${proxy}`] : []),
      ]
    });

    page = await browser.newPage();

    // Stealth: some SPAs (and anti-bot layers) refuse to render for headless Chrome, checking
    // navigator.webdriver / missing chrome object / empty plugins. Mask those before any
    // navigation so client-rendered login pages (e.g. Securemail) actually mount.
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
      Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
      Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
      window.chrome = window.chrome || { runtime: {} };
      const origQuery = window.navigator.permissions && window.navigator.permissions.query;
      if (origQuery) window.navigator.permissions.query = (p) =>
        p && p.name === 'notifications' ? Promise.resolve({ state: Notification.permission }) : origQuery(p);
    });

    // ponytail: mobile UA when requested  many phishing cloakers only forward mobile victims
    const UAS = {
      desktop: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
      mobile: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    };
    await page.setUserAgent(UAS[uaMode] || UAS.desktop);
    if (uaMode === 'mobile') await page.setViewport({ width: 390, height: 844, isMobile: true, hasTouch: true });
    else await page.setViewport({ width: 1920, height: 1080 });

    // ponytail: realistic headers  cloakers 403 bare (curl-style) requests missing these
    await page.setExtraHTTPHeaders({
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    });
  }
  // Attach: don't tear down the operator's browser at the end (the shell owns its PID); headless:
  // close the disposable one.
  const shutdown = () => attach ? browser.disconnect() : browser.close();

  // Track every main-frame navigation (captures JS/meta/cookie redirects, not just HTTP 3xx)
  const hops = [];
  page.on('framenavigated', (frame) => {
    const u = frame.url();
    if (frame === page.mainFrame() && u && u !== 'about:blank' && hops.at(-1) !== u) hops.push(u);
  });

  // Capture page console output + JS errors. Useful as a signal (skimmers/exfil kits log
  // debug lines) and to see WHY a client-rendered page failed to mount (blank SPA).
  const consoleLogs = [];
  const pushLog = (type, text) => { if (consoleLogs.length < 40 && text) consoleLogs.push({ type, text: String(text).slice(0, 300) }); };
  const isNoise = (u) => /\/favicon\.ico(\?|$)/i.test(u || '');   // benign, every site 404s it
  page.on('console', m => {
    const u = (m.location && m.location().url) || '';
    if (isNoise(u)) return;
    // include the resource URL -- a bare "Failed to load resource: 404" is useless without it
    pushLog(m.type(), u ? `${m.text()} (${u})` : m.text());
  });
  page.on('pageerror', e => pushLog('pageerror', e && e.message ? e.message : e));
  page.on('requestfailed', r => { if (!isNoise(r.url())) pushLog('requestfailed', r.url() + ' ' + (r.failure() && r.failure().errorText)); });

  // Track all requests
  const requests = [];
  await page.setRequestInterception(true);
  page.on('request', (req) => {
    try {
      const u = new URL(req.url());
      requests.push({
        url: req.url(),
        type: req.resourceType(),
        domain: u.hostname,
        isThirdParty: u.hostname !== domain
      });
    } catch {}
    req.continue();
  });

  // WebSocket connections. page.on('request') never fires for the WSS upgrade, so ask CDP
  // directly. This is the one handle on a Browser-in-the-Middle kit: the page is a thin client
  // for a browser the attacker drives, so it never submits anything. Every check that looks for
  // theft -- off-domain form action, exfil host, obfuscated network call -- sees nothing, because
  // input is relayed over the socket and the DOM is patched back. A renamed script file defeats
  // the kit signature below; the socket is the part it cannot do without.
  // ponytail: attach mode connects to an ALREADY-loaded tab, so a socket opened before we got
  // there raises no event and this reads empty. Re-navigate that tab if you need it.
  const webSockets = [];
  try {
    const cdp = await page.createCDPSession();
    await cdp.send('Network.enable');
    cdp.on('Network.webSocketCreated', e => {
      if (webSockets.length < 20 && e && e.url) webSockets.push(String(e.url).slice(0, 300));
    });
  } catch {}

  // Capture HTTP "Refresh:" headers on document hops -- a silent redirect that never
  // appears as a 3xx Location, used by cloakers. Collected across every hop, since the
  // intermediate gate (not the landed page) is usually what carries it.
  const refreshHeaders = [];
  page.on('response', (r) => {
    try {
      if (r.request().resourceType() === 'document') {
        const rh = r.headers()['refresh'];
        if (rh) refreshHeaders.push(rh);
      }
    } catch {}
  });

  let resp = null;
  let metaRefreshSeen = '';
  const cfChallenge = () => requests.some(r => /challenges\.cloudflare\.com|__cf_chl|cdn-cgi\/challenge/i.test(r.url));

  if (attach) {
    // The operator already cleared the gate and landed on the real page. Don't navigate --
    // just let any late-mounted forms/scripts settle before we read the uncloaked DOM.
    await page.waitForNetworkIdle({ idleTime: 1000, timeout: 8000 }).catch(() => {});
  } else {
    // Initial navigation  tolerate mid-flight JS redirects that destroy the JS context
    resp = await page.goto(targetUrl, {
      waitUntil: 'domcontentloaded',
      timeout: 30000
    }).catch(() => null);

    // Grab any <meta refresh> on the FIRST document before we follow it away -- an auto-
    // refresh navigates and the tag is gone from the landed DOM. Best-effort (racy for 0-sec).
    metaRefreshSeen = await page.evaluate(() => {
      const m = Array.from(document.querySelectorAll('meta'))
        .find(x => (x.getAttribute('http-equiv') || '').toLowerCase() === 'refresh');
      return m ? (m.getAttribute('content') || '') : '';
    }).catch(() => '');

    // Follow JS/meta/cookie redirects (cloaker gates) until the URL stops changing
    let prevUrl = null;
    for (let i = 0; i < 6 && page.url() !== prevUrl; i++) {
      prevUrl = page.url();
      const nav = await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 8000 }).catch(() => null);
      if (nav) resp = nav;
    }

    // Let the landing page settle so dynamically-injected forms/scripts are captured
    await page.waitForNetworkIdle({ idleTime: 1500, timeout: 15000 }).catch(() => {});

    // Cloudflare Turnstile / interstitial: managed challenges often auto-pass in a few seconds
    // for a clean-looking browser. If one is present, wait it out and re-settle, then keep
    // following any redirect it releases us to. Best-effort -- hard challenges won't pass.
    if (cfChallenge()) {
      for (let i = 0; i < 3; i++) {
        await new Promise(r => setTimeout(r, 5000));
        const nav = await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 6000 }).catch(() => null);
        if (nav) resp = nav;
        if (!/challenge|just a moment|checking your browser/i.test((await page.title().catch(() => '')))) break;
      }
      await page.waitForNetworkIdle({ idleTime: 1500, timeout: 10000 }).catch(() => {});
    }
  }

  // The follow loop above chases every onward hop, and the LAST hop is allowed to fail -- a kit
  // redirects to a destination that is dead, blocked, or resolves to nothing, and Chrome parks the
  // tab on chrome-error://. The check below then throws away the whole fetch as "unreachable",
  // including the page we successfully loaded and could read a moment earlier. That is how
  // tequiero.com.co/rr/tt/ -- an Outlook credential page that answers HTTP 200 -- produced zero
  // signals and no redirect chain at all: not a redirect-detection failure, a fetch that discarded
  // its own evidence.
  // So: if we landed nowhere but the FIRST navigation worked, go back to it and analyse what we
  // could actually see. One extra navigation, only on the failure path.
  if (!attach && !/^https?:/i.test(page.url()) && resp) {
    // Scripts OFF for the retry. The page's own redirect is what broke the tab the first time, so
    // re-running it just breaks it again -- with JS disabled the served HTML stays put and we read
    // the credential form, the title and the inline scripts as delivered. Re-enabled immediately
    // after load: page.evaluate() needs script execution, and the page's own scripts were already
    // skipped at parse time, so nothing of theirs runs.
    // This is a last resort on a fetch that already failed, so a JS-built page showing less than
    // it would have is still strictly more than the nothing we had.
    await page.setJavaScriptEnabled(false).catch(() => {});
    const back = await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => null);
    await page.setJavaScriptEnabled(true).catch(() => {});
    if (back) resp = back;
  }

  const landedUrl = page.url();
  // A failed navigation lands on about:blank or a chrome-error:// interstitial (blocked,
  // timeout, cert/upgrade failure). Both are empty non-pages: scoring them yields a phantom
  // "clean" verdict, so treat any non-http(s) landed scheme as an unreachable fetch.
  // EXCEPT an explicit data: target, which legitimately stays on data: -- rejecting it as
  // "unreachable" silently zeroed every signal (password field, obfuscated JS, exfil) and
  // scored the corpus's only DANGEROUS fixture as SAFE.
  const dataTarget = /^data:/i.test(targetUrl) && /^data:/i.test(landedUrl);
  if (!landedUrl || (!/^https?:/i.test(landedUrl) && !dataTarget)) {
    // Even with no renderable page we usually know the HTTP status, and "the server answered 404"
    // is a different fact from "we could not reach it": one says the kit is gone, the other says
    // nothing at all. Report it so the caller can tell them apart.
    const st = resp ? resp.status() : 0;
    console.log(JSON.stringify({ error: 'timeout or unreachable', status: st, url: targetUrl }));
    await shutdown();
    process.exit(0);
  }

  const status = resp ? resp.status() : 0;

  // Re-anchor host to where we actually landed (redirects may cross domains)
  domain = new URL(landedUrl).hostname;
  apexDomain = apexOf(domain);

  // Full hop chain (HTTP + JS/meta/cookie redirects), consecutive-deduped
  const redirects = hops.map(u => ({ url: u, status: null }));
  if (!redirects.length) redirects.push({ url: targetUrl, status });
  if (redirects.at(-1).url !== landedUrl) redirects.push({ url: landedUrl, status });
  redirects.at(-1).status = status;

  // Vue/React SPAs (e.g. Securemail) mount AFTER network idle and render the login form
  // late, into SHADOW DOM that a plain querySelector can't see. Poll (bounded ~10s, breaks
  // early) for a shadow-piercing password field or real body text before scraping.
  for (let i = 0; i < 12; i++) {
    let ready = false;
    for (const frame of page.frames()) {
      try {
        ready = await frame.evaluate(() => {
          const deepPw = (root, d = 0) => {
            if (d > 8 || !root.querySelectorAll) return false;
            if (root.querySelector('input[type="password"]')) return true;
            for (const el of root.querySelectorAll('*')) if (el.shadowRoot && deepPw(el.shadowRoot, d + 1)) return true;
            return false;
          };
          return deepPw(document) || (!!document.body && document.body.innerText.trim().length > 30);
        });
      } catch {}
      if (ready) break;
    }
    if (ready) break;
    await new Promise(r => setTimeout(r, 800));
  }

  const features = await page.evaluate(() => {
    // Shadow-DOM-piercing helpers: Vue/web-component apps (e.g. Securemail) render forms,
    // inputs and text INTO shadow roots that a plain document.querySelector can't reach.
    const deepAll = (sel) => {
      const out = [], stack = [document];
      while (stack.length) {
        const n = stack.pop();
        if (!n.querySelectorAll) continue;
        out.push(...n.querySelectorAll(sel));
        for (const el of n.querySelectorAll('*')) if (el.shadowRoot) stack.push(el.shadowRoot);
      }
      return out;
    };
    const deepText = () => {
      let t = document.body ? document.body.innerText : '', stack = [document];
      while (stack.length) {
        const n = stack.pop();
        if (!n.querySelectorAll) continue;
        for (const el of n.querySelectorAll('*')) if (el.shadowRoot) { t += '\n' + (el.shadowRoot.textContent || ''); stack.push(el.shadowRoot); }
      }
      return t;
    };

    // Credential detection must not hang on <input type="password">. A page built on a no-code
    // site builder (Framer, Wix, Google Forms) CANNOT emit one, so a kit deployed there collects
    // the password in a plain type="text" box: witty-run-128215.framer.app labelled one
    // "Password" while its name attribute was literally "Email", and hasLoginForm read false, so
    // every login-gated floor AND all three vision triggers stayed disarmed on a live cPanel
    // Webmail clone that the screenshot showed plainly.
    // Attribute names are the kit's to choose. The visible LABEL is not -- the victim has to be
    // told which box is the password -- so read that instead. Zero-width padding is stripped
    // first, same evasion class as the brand matching further down.
    // Short labels only, and scoped to the input's OWN <label>: "Password" is a label, a
    // paragraph or a "forgot your password?" link is not.
    const _ZW = /[​-‍⁠-⁤﻿­͏]/g;
    const PWD_LABEL = /pass\s?word|passwort|contrase|mot de passe|senha|wachtwoord/i;
    const pwdLabelled = (i) => {
      const root = i.getRootNode();
      const l = i.closest('label')
        || (i.id && root.querySelector ? root.querySelector(`label[for="${CSS.escape(i.id)}"]`) : null);
      const t = ((l && (l.innerText || l.textContent)) || '').replace(_ZW, '').trim();
      return t.length <= 40 && PWD_LABEL.test(t);
    };
    const isPwdInput = (i) => i.type === 'password' || (i.type === 'text' && pwdLabelled(i));

    // Compare APEX domains, not hostnames -- otherwise a site's own subdomains
    // (en.wikipedia.org vs www.wikipedia.org) count as "external" and skew the profile.
    const apex = h => (h || '').split('.').slice(-2).join('.');
    const links = deepAll('a[href]').map(a => ({
      href: a.href, text: (a.textContent||'').trim().slice(0,80),
      isExternal: !!a.hostname && apex(a.hostname) !== apex(location.hostname)
    }));

    // In-body <meta http-equiv="refresh" content="0;url=..."> -- another silent redirect.
    const _mr = Array.from(document.querySelectorAll('meta'))
      .find(m => (m.getAttribute('http-equiv') || '').toLowerCase() === 'refresh');
    const metaRefresh = _mr ? (_mr.getAttribute('content') || '') : '';

    const forms = deepAll('form').map(f => ({
      action: f.action, method: f.method,
      hasPassword: Array.from(f.querySelectorAll('input')).some(isPwdInput),
      inputs: Array.from(f.querySelectorAll('input')).map(i => ({ type: i.type, name: i.name, placeholder: i.placeholder }))
    }));

    const scripts = Array.from(document.querySelectorAll('script')).map(s => ({
      src: s.src || 'inline',
      text: (s.textContent || '').slice(0, 1000)
    }));

    const iframes = Array.from(document.querySelectorAll('iframe')).map(f => f.src);
    const images = Array.from(document.querySelectorAll('img')).map(i => i.src).slice(0,30);

    const meta = {};
    document.querySelectorAll('meta').forEach(m => {
      const k = m.getAttribute('name') || m.getAttribute('property') || '';
      if (k) meta[k] = m.getAttribute('content') || '';
    });

    // Full, untruncated inline script bodies -- used only for obfuscation detection and the
    // deobfuscation dump below; kept OUT of the stdout JSON so output stays small.
    const inlineScripts = Array.from(document.querySelectorAll('script'))
      .filter(s => !s.src).map(s => s.textContent || '');

    // Raw markup for kit-signature matching (see kitSignatures below). Kept OUT of the stdout
    // JSON like inlineScripts -- it is only a haystack. Class names, hidden input names, asset
    // filenames and inline script bodies all live in here, which is exactly the set of things a
    // kit cannot rename without rebuilding itself.
    const rawHtml = (document.documentElement.outerHTML || '').slice(0, 400000);

    return {
      title: document.title,
      text: deepText().slice(0, 4000),
      links, forms, scripts, inlineScripts, rawHtml, iframes, images, meta, metaRefresh,
      hasLoginForm: deepAll('input').some(isPwdInput),
      // The password box is not a password box: it goes in as visible cleartext, no browser or
      // password manager treats it as a secret. Reported separately because it is a finding in
      // its own right, not just the reason hasLoginForm is true.
      cleartextPassword: deepAll('input').some(i => i.type === 'text' && pwdLabelled(i)),
    };
  });

  // SPAs / webmail (e.g. Securemail, Zimbra) render the login form INSIDE an iframe, invisible
  // to a main-frame-only DOM query. Puppeteer can evaluate in child frames, so merge their
  // forms + password fields + text/title so login detection and brand/urgency checks work.
  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;
    try {
      const sub = await frame.evaluate(() => {
        // Same label-based credential test as the main frame above -- duplicated because an
        // evaluate() body crosses into the page and takes no closures with it. Keep in sync.
        const _ZW = /[​-‍⁠-⁤﻿­͏]/g;
        const PWD_LABEL = /pass\s?word|passwort|contrase|mot de passe|senha|wachtwoord/i;
        const pwdLabelled = (i) => {
          const l = i.closest('label') || (i.id ? document.querySelector(`label[for="${CSS.escape(i.id)}"]`) : null);
          const t = ((l && (l.innerText || l.textContent)) || '').replace(_ZW, '').trim();
          return t.length <= 40 && PWD_LABEL.test(t);
        };
        const isPwdInput = (i) => i.type === 'password' || (i.type === 'text' && pwdLabelled(i));
        const inputs = Array.from(document.querySelectorAll('input'));
        return {
          forms: Array.from(document.forms).map(f => ({
            action: f.action, method: f.method,
            hasPassword: Array.from(f.querySelectorAll('input')).some(isPwdInput),
            inputs: Array.from(f.querySelectorAll('input')).map(i => ({ type: i.type, name: i.name, placeholder: i.placeholder })),
          })),
          hasPassword: inputs.some(isPwdInput),
          cleartextPassword: inputs.some(i => i.type === 'text' && pwdLabelled(i)),
          text: (document.body ? document.body.innerText : '').slice(0, 4000),
          title: document.title,
        };
      });
      if (sub.forms.length) features.forms.push(...sub.forms);
      if (sub.hasPassword) features.hasLoginForm = true;
      if (sub.cleartextPassword) features.cleartextPassword = true;
      if (!features.text && sub.text) features.text = sub.text;    // main frame had no body text
      if (!features.title && sub.title) features.title = sub.title;
    } catch {}
  }

  // --- Analysis ---

  const smells = [];

  // External resources summary (moved up for brand check)
  const thirdParty = requests.filter(r => r.domain && r.domain !== domain);
  const thirdPartyDomains = [...new Set(thirdParty.map(r => r.domain))].slice(0,15);

  // Brand mismatch - but whitelist OAuth/payment integrations
  const brands = [
    // Tech
    'google','facebook','microsoft','apple','amazon','paypal','netflix','instagram','linkedin','twitter','github','dropbox','adobe','zoom','slack','wix',
    // Crypto
    'coinbase','binance','metamask','tronlink','trustwallet','kraken','ledger','blockchain',
    // US Banks
    'chase','wellsfargo','bankofamerica','citibank','usbank','capitalone','tdbank','truist','schwab','fidelity','americanexpress','amex','visa','mastercard',
    // UK Banks
    'barclays','hsbc','lloyds','natwest','santander','halifax','monzo','revolut',
    // EU Banks
    'ing','bnp','deutsche','commerzbank','rabobank','unicredit','creditsuisse','ubs',
    // African Banks
    'nedbank','standardbank','fnb','absa','capitec','investec','firstrand','oldmutual',
    // APAC Banks
    'dbs','ocbc','maybank','icici','hdfc','commonwealth','anz','westpac'
  ];
  // ponytail: OAuth/payment providers whose presence explains brand mentions
  const oauthPaymentDomains = ['accounts.google.com','apis.google.com','facebook.com','login.microsoftonline.com',
    'appleid.apple.com','amazon.com','paypal.com','stripe.com','js.stripe.com','m.stripe.com','github.com',
    'login.live.com','auth0.com','okta.com','supabase.co'];
  // Match on dot-delimited labels, never substrings (see the brandExplainedByOAuth note below).
  const onDomain = (d, o) => d === o || d.endsWith(`.${o}`);
  // Where a brand must appear to count as impersonation. Config knob: BRAND_MATCH env.
  //   'strict' (default): page TITLE or a FORM ACTION -- the strong signals a phishing clone
  //            emits (titles itself "PayPal Login", posts creds to a paypal-named URL).
  //   'body': also count body-text mentions -- noisier; legit content sites merely NAME brands
  //           (wikipedia -> "google, apple"), so this over-flags. Kept for future tuning.
  const brandMatch = (process.env.BRAND_MATCH || 'strict').toLowerCase();
  // Invisible characters exist in a phishing page for exactly one reason: to break the string
  // matching that every scanner (and every YARA rule) does. Cephas pads its source with random
  // zero-width characters; Sneaky2FA breaks up UI labels with invisible tags. "Micro<zwsp>soft"
  // renders identically and matches nothing. Strip them before ANY text comparison -- one regex
  // removes the whole evasion class. See .planning/phases/kit-fingerprinting/RESEARCH.md.
  const ZW = /[​-‍⁠-⁤﻿­͏]/g;
  const dezw = s => (s || '').replace(ZW, '');
  const zwCount = ((features.title || '') + (features.text || '')).match(ZW);
  const title = dezw(features.title).toLowerCase();
  const formActions = features.forms.map(f => dezw(f.action).toLowerCase()).join(' ');
  const body = dezw(features.text).toLowerCase();

  // The link promised a site; what we fetched is a registrar parking page, a for-sale lander, a
  // web-server default page or a suspension notice. NOTHING on it belongs to the link's target,
  // so scoring it is the phantom-SAFE shape (is_blank_page in verdict.sh): the scanner saw no
  // site, which is not the same as seeing a safe one. sportycast.com came in as a LUCA alert,
  // landed on Spaceship's "Parking Page", and escaped SAFE only because it happened to be served
  // over plain HTTP. Which way it reads then is up to the DOMAIN facts (age, TLD, ledger priors)
  // and to the web archive -- was there ever a site here? -- not to this page.
  // Strong phrases only, and no commas in the smell text (count_red_flags splits on those).
  // ponytail: deliberately NOT here: bare "coming soon" and "under construction" as standalone
  // words, which real trading sites say. The parking NETWORKS are matched by request host
  // instead, which is the artifact a re-skinned lander cannot rename.
  const parkRe = /parking page|parked (free of charge|domain|by|at)|domain( name)?( \S{1,40})? (is|may be) (for sale|available)|domain parking|(buy|get) this domain|is this your domain|registered (at|with) (spaceship|namecheap|godaddy|porkbun|dynadot|hostinger)|future home of something quite cool|welcome to nginx|apache\d? \S{0,12} ?default page|iis windows server|default web ?site page|this (site|page) is under construction|account has been suspended/i;
  const parkHostRe = /(sedoparking|parkingcrew|bodis|afternic|hugedomains|undeveloped|parklogic|cashparking|dan\.com|above\.com|sav\.com)/i;
  const parkHit = (title + ' ' + body).match(parkRe) || thirdPartyDomains.join(' ').match(parkHostRe);
  if (parkHit)
    smells.push(`Domain placeholder page - no real site here (registrar parking / host default: "${parkHit[0].replace(/,/g, ' ').slice(0, 60)}")`);

  const brandHaystack = brandMatch === 'body'
    ? [title, formActions, body].join(' ')
    : [title, formActions].join(' ');
  // Word-boundary match so short brands (e.g. "ing") don't hit inside "tracking"/"information"
  const matched = brands.filter(b => new RegExp(`\\b${b}\\b`, 'i').test(brandHaystack));
  if (matched.length) {
    // Only the registrable apex proves ownership. A brand in the SUBDOMAIN is attacker-controlled
    // (userswix-com-signin.pit-phone.com) -- that IS the typosquat, so it must never excuse the
    // impersonation smell the way testing the full hostname did.
    // Per brand, never `.some()`. A brand is excused only by ITS OWN apex, so one
    // legitimately-present brand must not cancel the others: an Adobe credential form on
    // bayon-jakes.github.io matches BOTH "adobe" and "github" -- github really is in the apex, so
    // .some() returned true and the adobe claim vanished. And the page did not even have to
    // mention GitHub: brandHaystack includes the form actions, so a same-origin form on any
    // *.github.io page put "github" in `matched` by itself. That silently disarmed brand
    // impersonation on every github.io kit, and on every host whose name contains a brand token.
    const unexplained = matched.filter(b => !apexDomain.includes(b.replace(/\s/g,'')));
    // Check if brand is explained by legitimate OAuth/payment integration.
    // Match on dot-delimited labels, never substrings: "m.stripe.com" first-label was "m", and
    // d.includes("m") is true for every .com domain -- which silently explained away every brand
    // hit on any page loading a single third-party resource.
    const brandExplainedByOAuth = unexplained.length > 0 && unexplained.every(b =>
      thirdPartyDomains.some(d =>
        new RegExp(`(^|\\.)${b.replace(/\s/g,'')}\\.`, 'i').test(d) ||
        oauthPaymentDomains.some(o => onDomain(d, o)))
    );
    // Name the UNEXPLAINED brands, not every match -- listing "github" as impersonated on a
    // github.io page is exactly the confusion this fix is about.
    if (unexplained.length && !brandExplainedByOAuth)
      smells.push(`Brand impersonation: "${unexplained.slice(0,3).join(', ')}" in title/form but domain is "${domain}"`);
  }

  // ponytail: Hotlinked brand artwork -- the page DISPLAYS an <img> served from a BRAND's own
  // domain while the page itself is not that brand. Kits are cloned wholesale from the real login
  // page, so the logo <img src> still points at the victim brand's CDN. The asset's HOST is the
  // attribution, so this needs no logo database, no perceptual hashing and no model: the cheapest
  // rung of the visual-impersonation ladder.
  // Legit pages embed brand artwork too (payment buttons, partner/dealer logos), so this is CONTEXT
  // and never a red flag on its own -- verdict.sh floors it to SUSPICIOUS only when the page also
  // asks for credentials, and count_red_flags excludes it. ponytail: upgrade path if recall is too
  // low is favicon hashing, then a logo hash set; a self-hosted copied logo is invisible here.
  const noHotlink = new Set(['google','facebook','amazon','microsoft','apple','github','instagram','twitter','linkedin']);
  // <5 chars ('ing','fnb','visa') matches inside ordinary words; the set above is embedded on
  // legit pages constantly (social buttons, maps, affiliate images) so it has near-zero precision.
  const hotlinkBrands = brands.filter(b => b.length >= 5 && !noHotlink.has(b));
  const hotlinked = [...new Set(features.images.map(u => {
    try { return new URL(u).hostname.toLowerCase(); } catch { return ''; }
  }))].flatMap(h => {
    const sld = apexOf(h).split('.')[0];   // 'paypalobjects' for www.paypalobjects.com
    const b = hotlinkBrands.find(x => sld === x || sld.startsWith(x));
    return b && !apexDomain.includes(b) && !oauthPaymentDomains.some(o => onDomain(h, o)) ? [[b, h]] : [];
  });
  if (hotlinked.length)  // space-joined (no commas): verdict.sh splits SMELLS on commas
    smells.push(`Hotlinked brand image: "${[...new Set(hotlinked.map(x => x[0]))].join(' ')}" `
      + `artwork served from its own domain (${[...new Set(hotlinked.map(x => x[1]))].slice(0,3).join(' ')}) `
      + `but page is "${domain}"`);

  // Links
  const extLinks = features.links.filter(l => l.isExternal);
  const intLinks = features.links.filter(l => !l.isExternal);
  if (extLinks.length > intLinks.length * 2 && extLinks.length > 3)
    smells.push(`Skewed link profile: ${extLinks.length} external vs ${intLinks.length} internal`);

  // The page asks for a password in a box that is not a password box. Nobody who set out to
  // collect passwords ends up here by accident: the browser will not mask it, a password manager
  // will not fill it, and the value sits in the DOM in the clear. It is what a credential kit on
  // a no-code builder looks like -- Framer, Wix, Google Forms -- because those platforms have no
  // password field to offer. Counted as an ordinary red flag (verdict.sh has no exclusion for
  // it), so together with the login form it just armed, it carries the DANGEROUS floor.
  // No commas: verdict.sh counts red flags by splitting SMELLS on them.
  if (features.cleartextPassword)
    smells.push('Password collected in a cleartext input - no <input type=password> on the page (the shape of a kit built on a no-code site builder)');

  // Login form to external
  for (const f of features.forms) {
    if (f.hasPassword && f.action) {
      try {
        if (new URL(f.action).hostname !== domain)
          smells.push(`Login form submits to "${new URL(f.action).hostname}" (off-domain)`);
      } catch {}
    }
  }

  // === Kit signatures ===
  // Attackers do not write pages, they deploy kits, and a kit leaks its BUILD. Brand imagery
  // changes per campaign; the scraped design-system class, the hard-coded asset filename and the
  // POST endpoint do not, because changing them means rebuilding the kit.
  // Every entry needs a token that is distinctive on its own -- a build hash, an invented field
  // name, a pair of filenames -- never a generic path like "login.php". `not` is the domain that
  // legitimately owns the artifact: 1Password's real site carries its own design-system classes,
  // and the whole point is that this page is NOT that site.
  // See .planning/phases/kit-fingerprinting/RESEARCH.md for provenance of each token.
  const kitHay = dezw(features.rawHtml || '').toLowerCase();
  const kitSignatures = [
    { name: '1Phish (1Password clone)', not: '1password.com',
      any: ['knox-provider_ltr__kddqqu0', 'reset_base__1e6d9s10', 'validated_user_1pass', 'hideclick:ignore'] },
    { name: 'Tycoon2FA', any: ['/web6socket/', 'cllascio.php', 'bltdref', 'bltdua', 'bltddata'] },
    // Kratos ships these two svgs together on its login page. Either one alone is too weak, and
    // next.php/save.php alone is a path half the PHP web could use.
    { name: 'Kratos', all: ['barr.svg', 'lg.svg'] },
    // Browser-in-the-Middle: socket.io relays the victim's keystrokes to a backend browser and
    // domdiffer (from fiduswriter/diffDOM) patches the returned DOM back into the page. Same
    // reasoning as Kratos above -- neither token is a kit token on its own, since chat apps ship
    // socket.io and the real fiduswriter ships diffDOM, so it has to be BOTH on one page.
    { name: 'BitM relay (Socket.IO + DOM diffing)', all: ['socket.io', 'domdiffer'] },
  ];
  for (const kit of kitSignatures) {
    if (kit.not && (apexDomain === kit.not || domain.endsWith('.' + kit.not))) continue;
    const hit = kit.all ? kit.all.every(t => kitHay.includes(t))
                        : kit.any.filter(t => kitHay.includes(t));
    const matched = kit.all ? (hit ? kit.all : []) : hit;
    if (matched.length)
      smells.push(`Known phishing kit: ${kit.name} (build artifact "${matched[0]}")`);
  }

  // A credential page holding a socket to its OWN origin does not submit -- it streams. That is
  // the Browser-in-the-Middle shape, and it survives the kit renaming every script file above.
  // Only same-origin counts: a third-party socket is a chat widget (Intercom, Zendesk, Crisp) on
  // a page that happens to have a login, which is ordinary. Even so it is capped at SUSPICIOUS in
  // verdict.sh, because some legitimate SPAs open one; the kit signature is what reaches
  // DANGEROUS. Host only, no commas -- verdict.sh splits this list on commas to count flags.
  const wsSameOrigin = [...new Set(webSockets
    .map(u => { try { return new URL(u).host.toLowerCase(); } catch { return ''; } })
    .filter(h => h && sameSite(h.split(':')[0])))];
  if (features.hasLoginForm && wsSameOrigin.length)
    smells.push(`Credential page holds a WebSocket to its own origin (${wsSameOrigin[0]}) - input is relayed live rather than submitted (Browser-in-the-Middle)`);

  // The padding itself is a signal, not just an obstacle. A handful of zero-width characters is
  // ordinary (emoji joiners, CJK line-break hints, a stray BOM), so only bulk padding counts --
  // that is the deliberate anti-signature technique, and it is why the threshold sits well above
  // anything a legitimate page produces by accident.
  if (zwCount && zwCount.length > 20)
    smells.push(`${zwCount.length} invisible characters padded into the page text - anti-signature obfuscation`);

  // Iframes
  if (features.iframes.length > 2)
    smells.push(`${features.iframes.length} iframes - possible clickjacking`);

  // Redirects -- count only real cross-URL hops, not SPA hash-route changes within one
  // page load (viewer/ -> viewer/#/ -> viewer/#/auth/login is Angular/Vue routing, not a
  // redirect chain). Two URLs identical except for the #fragment are the same hop.
  const realHops = [...new Set(redirects.map(r => r.url.split('#')[0]))];
  if (realHops.length > 2)
    smells.push(`${realHops.length}-hop redirect chain`);

  // Bot / human-verification gates cloaking the real page from the scraper. Detect the major
  // providers by the scripts they load. On a redirect-chain phish this is deliberate cloaking; it
  // also explains a "dead" (404/empty) land. Each smell ends with "gated from the scraper" so
  // url-analyze's operator-attach trigger can match any provider with one test.
  //
  // A provider script is NOT a gate. PayPal, Google and much of the legit web load INVISIBLE
  // reCAPTCHA/Turnstile for fraud scoring while the real page renders fine -- this fired on
  // paypal.com over a page we fetched perfectly (title "...| PayPal ZA", 200), claiming "real page
  // gated from the scraper", which scored a red flag AND offered to open Brave for paypal.com.
  // So only claim a gate when we actually failed to reach the real page: a challenge interstitial
  // (its title or URL), or a gate script on a page with no content AND no form -- a challenge has
  // neither, while a bare login page has the form.
  // ponytail: title/URL markers cover the mainstream gates; add DOM widget detection if a kit
  // ships a gate with a custom title and real body text.
  const challengeTitle = /just a moment|checking your browser|attention required|verify you are (a )?human|are you a robot|security check|access denied|enable javascript and cookies/i;
  const reallyGated = challengeTitle.test(title)
    || /__cf_chl|cdn-cgi\/challenge/i.test(landedUrl)
    || (body.trim().length < 200 && !features.hasLoginForm);
  const gateProviders = [
    { re: /challenges\.cloudflare\.com|__cf_chl|cdn-cgi\/challenge/i, name: 'Cloudflare Turnstile' },
    { re: /\bhcaptcha\.com|newassets\.hcaptcha\.com/i, name: 'hCaptcha' },
    { re: /google\.com\/recaptcha|gstatic\.com\/recaptcha|recaptcha\/api\.js/i, name: 'reCAPTCHA' },
  ];
  let gateMatched = false;
  if (reallyGated)
    for (const g of gateProviders)
      if (requests.some(r => g.re.test(r.url))) {
        smells.push(`${g.name} challenge - real page gated from the scraper`);
        gateMatched = true;
      }
  // Custom/unrecognized cloak: a page that renders blank with no form and NO known provider script
  // -- a homebrew JS challenge (ft_chall/gsauth counters, console.clear anti-debug) hid the real
  // page. Without this the scraper knows it was blocked yet stays silent, so a cloaked phish reads
  // phantom-SAFE. Corroborated by either a redirect (normal scan) or attach mode: in attach there is
  // no navigation (we read the operator's already-loaded tab, realHops==1), so a blank land means the
  // operator did NOT clear the gate -- the kit still denied them ("Unauthorized access"). Flagging it
  // also stops that deny page from overwriting the cache as phantom-SAFE. A cleared gate has real
  // body/a form -> reallyGated false -> no fire. Ends in "gated from the scraper" -> floor + attach.
  if (reallyGated && !gateMatched && (realHops.length > 1 || attach))
    smells.push(`Unrecognized bot/cloak challenge - real page gated from the scraper`);

  // The one identifier a gate MUST expose to work: its sitekey. A kit-embedded Turnstile /
  // hCaptcha / reCAPTCHA widget carries it as data-sitekey in the markup, or as ?k= / render= on
  // the provider request. A sitekey belongs to an ACCOUNT and a kit reuses it across campaigns, so
  // it is the same class of evidence as the SendGrid tracking blob in campaign_key: the last thing
  // to change when the domains rotate. We were fetching the page and throwing it away.
  // Ceiling: Cloudflare's OWN managed challenge (cdn-cgi/challenge-platform) is CF-hosted and
  // exposes no customer sitekey -- this reads kit-deployed widgets only.
  // Context, never a floor: a sitekey says who deployed the gate, not that the page steals.
  const siteKeys = [...new Set([
    ...(dezw(features.rawHtml || '').match(/data-sitekey\s*=\s*["']([^"']{8,64})["']/gi) || [])
      .map(m => (m.match(/["']([^"']{8,64})["']/) || [])[1]),
    ...requests.filter(r => /challenges\.cloudflare\.com|hcaptcha\.com|recaptcha/i.test(r.url))
      .map(r => { try { const q = new URL(r.url).searchParams; return q.get('k') || q.get('sitekey') || q.get('render') || ''; } catch { return ''; } }),
  ].map(k => (k || '').trim()).filter(k => /^[A-Za-z0-9_-]{8,64}$/.test(k) && k !== 'explicit'))];
  if (siteKeys.length)
    smells.push(`Bot-gate sitekey: ${siteKeys.slice(0, 3).join(' ')}`);

  // ponytail: silent Refresh redirects (HTTP "Refresh:" header or <meta refresh>) -- cloaker
  // gates that bounce victims without a visible 3xx Location. Flag when a url= target exists.
  const refreshHit = refreshHeaders.find(rh => /url=/i.test(rh));
  if (refreshHit)
    smells.push(`HTTP Refresh header redirect: ${refreshHit.slice(0,120)}`);
  const metaRefreshFound = metaRefreshSeen || features.metaRefresh;
  if (metaRefreshFound && /url=/i.test(metaRefreshFound))
    smells.push(`Meta-refresh redirect: ${metaRefreshFound.slice(0,120)}`);

  // HTTPS -- judge the landed URL, not the typed one (HTTP->HTTPS redirect is secure). Flag "no TLS"
  // only when the host offers no HTTPS at all: Chrome's https auto-upgrade is disabled (so http-only
  // kits load), which would otherwise false-flag every real site that serves https but doesn't force
  // a redirect. Under a proxy, skip the probe (a direct connect would bypass Tor/leak) and flag as before.
  if ((redirects.at(-1)?.url || targetUrl).startsWith('http:')) {
    const noTls = proxy ? true : !(await httpsAvailable(new URL(landedUrl).hostname));
    if (noTls) smells.push('Served over HTTP (no TLS)');
  }

  // Suspicious JS -- scan FULL inline bodies, not the 1000-char preview
  const allJs = features.inlineScripts.join('\n');
  const jsSmells = [];
  if (/eval\s*\(/.test(allJs)) jsSmells.push('eval()');
  // \batob\b (not atob\() so aliasing is caught: kits do `tt = atob; tt('base64')`
  if (/\batob\b/.test(allJs)) jsSmells.push('atob()');
  if (/document\.write/.test(allJs)) jsSmells.push('document.write()');
  if (/(?:\\x[0-9a-f]{2}){3,}/i.test(allJs)) jsSmells.push('hex-encoded strings');
  if (/window\.location\s*=/.test(allJs)) jsSmells.push('location redirect');
  // obfuscator.io hallmarks (the obfuscator most phishing kits use, and what webcrack cracks):
  // hex-named identifiers like _0x4c8c82 in quantity, and String.fromCharCode string-building.
  if ((allJs.match(/_0x[0-9a-f]{4,}/gi) || []).length >= 5) jsSmells.push('obfuscated identifiers (_0x)');
  if (/String\.fromCharCode\s*\(/.test(allJs)) jsSmells.push('String.fromCharCode');

  // Obfuscated network exfil: JS that decodes strings (atob) AND fires a request. Legit pages
  // almost never atob() a fetch URL -- this is the classic credential-harvest handler
  // (e.g. #signin click -> fetch(atob(...)+input.value)). The endpoint stays hidden because
  // it only fires on submit (never a page resource) and is base64-encoded (no plain URL).
  if (/\batob\b/.test(allJs) && /\bfetch\s*\(|XMLHttpRequest|\.open\s*\(|sendBeacon/.test(allJs))
    smells.push('Obfuscated network call: JS atob-decodes then makes a request (likely credential exfil)');

  // Decode base64 string literals -- try BOTH raw and with '+' removed, since a common
  // evasion inserts a '+' the kit strips at runtime (`atob('aa+bb').replace('+','')`).
  const b64parts = [];
  for (const s of (allJs.match(/[A-Za-z0-9+/]{12,}={0,2}/g) || [])) {
    for (const v of [s, s.replace(/\+/g, '')]) {
      try { const d = Buffer.from(v, 'base64').toString('utf8');
            if (/^[\x09\x0A\x0D\x20-\x7E]{4,}$/.test(d)) b64parts.push(d); } catch {}
    }
  }
  const b64decoded = b64parts.join(' ');

  // Off-apex domains the page could send data to: form actions + hosts in plain JS + hosts
  // in base64-decoded JS. Excludes CDNs/analytics. Listed for the verdict and for triage.
  const hostsIn = (t) => [...String(t).matchAll(/https?:\/\/([a-z0-9.-]+)/gi)].map(m => m[1].toLowerCase());
  // auth0.com: the identity provider behind a large share of legitimate SSO logins -- its SDK/CDN
  // host is not a third party in any meaningful sense. zohocdn/zohowebstatic: Zoho's own asset
  // hosts, which sit on a different apex from its product domains (maillist-manage.in).
  // lr-ingest: LogRocket session replay, which false-positived the real Wasabi console.
  // ponytail: this is a hand-maintained allowlist and every entry is a patch, not a fix -- three
  // separate false positives this session were just vendors missing from it. The real answer is a
  // reputation/prevalence check on the host, not a longer regex. Revisit when it grows again.
  const cdnRe = /(googleapis|gstatic|cloudflare|jsdelivr|unpkg|cdnjs|jquery|bootstrapcdn|google-analytics|googletagmanager|fontawesome|recaptcha|hcaptcha|gravatar|auth0\.com|zohocdn|zohowebstatic|lr-ingest|w3\.org|schema\.org)/i;
  // Only covert exfil vectors count: an off-domain FORM ACTION (posts data cross-domain) or a
  // host HIDDEN in an obfuscated/base64 blob. A host sitting in plain, readable JS is auditable
  // and overwhelmingly analytics/RUM/CDN -- not covert theft -- so it is NOT treated as exfil.
  const exfilDomains = [...new Set([
    ...features.forms.map(f => { try { return new URL(f.action).hostname.toLowerCase(); } catch { return ''; } }),
    ...hostsIn(b64decoded),
  ])].filter(h => h && !sameSite(h) && !cdnRe.test(h));
  if (exfilDomains.length)
    smells.push(`Off-domain exfil endpoint(s) in page code: ${exfilDomains.slice(0,4).join(', ')}`);

  // Off-domain hosts the page pulls resources from (scripts, iframes, images) or names in plain
  // JS. NOT exfil on its own -- context for triage: a hotlinked brand logo, a tracking pixel, a
  // sketchy third party. Surfaced to the operator + LLM; excluded from the deterministic red-flag
  // count (verdict.sh) so it can't floor the verdict by itself -- the LLM judges whether it smells.
  const thirdPartyHosts = [...new Set([
    ...features.scripts.map(s => s.src), ...features.iframes, ...features.images,
  ].map(u => { try { return new URL(u).hostname.toLowerCase(); } catch { return ''; } })
   .concat(hostsIn(allJs)))]
    .filter(h => h && !sameSite(h) && !cdnRe.test(h) && !exfilDomains.includes(h));
  if (thirdPartyHosts.length)  // space-joined (no commas) so verdict.sh's comma-split count excludes it whole
    smells.push(`Third-party hosts referenced (scripts/iframes/images/JS): ${thirdPartyHosts.slice(0,6).join(' ')}`);

  // ponytail: IP fingerprinting services used to track victims (also seen base64-encoded in JS)
  const ipFingerprinters = ['api.ipify.org','ipinfo.io','ip-api.com','ipapi.co','checkip.amazonaws.com',
    'ifconfig.me','icanhazip.com','wtfismyip.com','ipecho.net','myexternalip.com','myips.cc'];
  const fingerprintHits = [...new Set([...thirdPartyDomains, ...(b64decoded.match(/[a-z0-9.-]+\.[a-z]{2,}/gi) || [])])]
    .filter(d => ipFingerprinters.some(f => String(d).includes(f)));
  if (fingerprintHits.length)
    smells.push(`IP fingerprinting: ${fingerprintHits.join(', ')}`);

  // ponytail: Redirect to compromised WordPress (wp-include/wp-content with random paths, not plugins/themes/uploads)
  const finalUrl = redirects.at(-1)?.url || targetUrl;
  const wpSuspicious = /\/wp-(includes?|content)\/(?!(plugins|themes|uploads)\/)[a-z0-9]{3,}\//i;
  if (finalUrl !== targetUrl && wpSuspicious.test(finalUrl))
    smells.push(`Redirect to compromised WordPress: ${new URL(finalUrl).hostname}`);

  // Random URL path (kit paths like /kz51odwn/, /43uu6p0/). This said "high entropy" but computed
  // none -- it flagged ANY alphanumeric segment >4 chars outside a 6-word whitelist, so /uploads/,
  // /content/, /support/ (most of the web) read as random. Shannon entropy does not separate these
  // either: short distinct-char words score as high as random ones ("uploads" 2.81 vs "kz51odwn" 3.0).
  // What actually separates them is a digit INSIDE the word: real words have none (uploads, content)
  // and technical paths only carry a trailing version digit (oauth2, base64, html5, sha256).
  // ponytail: misses all-alphabetic random paths (/xkcdqwrt/); add a bigram check if kits move there.
  const pathParts = new URL(landedUrl).pathname.split('/').filter(p => p.length > 4);
  const randomPath = pathParts.find(p => /^[a-z0-9]{5,}$/i.test(p) && /\d/.test(p.replace(/\d+$/, '')));
  if (randomPath)
    smells.push(`Random URL path: /${randomPath}/`);

  // ponytail: Urgency keywords in page text
  const urgencyPatterns = /(suspend|terminat|verify.{0,10}(now|immediate)|expire|unauthorized|unusual.{0,10}activity|confirm.{0,10}identity|update.{0,10}(payment|billing)|within.{0,10}24.{0,10}hour)/i;
  if (urgencyPatterns.test(body))
    smells.push('Urgency language detected');

  // ponytail: Hidden form fields (potential data exfil)
  const hiddenInputs = features.forms.flatMap(f => f.inputs.filter(i => i.type === 'hidden' && i.name));
  if (hiddenInputs.length > 3)
    smells.push(`${hiddenInputs.length} hidden form fields`);

  // ponytail: Sensitive field names
  const sensitiveFields = /(ssn|social.?sec|credit.?card|cvv|cvc|routing|account.?num|pin|passport)/i;
  const sensitiveInputs = features.forms.flatMap(f => f.inputs.filter(i => sensitiveFields.test(i.name || i.placeholder || '')));
  if (sensitiveInputs.length)
    smells.push(`Sensitive data fields: ${sensitiveInputs.map(i => i.name || i.placeholder).join(', ')}`);

  // ponytail: Clipboard hijacking
  if (/oncopy|oncut|onpaste|clipboard/i.test(allJs))
    smells.push('Clipboard access detected');

  // ponytail: Right-click/context menu disabled. Order-independent: the modern idiom is
  // addEventListener('contextmenu', e => e.preventDefault()), which puts contextmenu FIRST and
  // slipped past a regex that only matched preventDefault-before-contextmenu.
  if (/contextmenu/i.test(allJs) && /preventDefault|return\s*false/i.test(allJs))
    smells.push('Right-click disabled');

  // ponytail: Crypto wallet addresses
  const cryptoPatterns = /(^|[^a-z0-9])(bc1[a-z0-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|T[A-Za-z1-9]{33})([^a-z0-9]|$)/;
  if (cryptoPatterns.test(body))
    smells.push('Crypto wallet address found');

  // ponytail: Where the credentials actually live. A marketing landing page or SPA shell often
  // carries NO form at all -- the login sits one click away behind a "Login" / "Member Portal"
  // link. Every login-dependent floor (off-CDN third-party host, hotlinked brand artwork,
  // brand-lookalike subdomain) is a no-op until a password field is seen, so a kit with a clean
  // front page and the harvester at /login scores SAFE. Real case: icamis.icam.mw came back SAFE
  // on a page with zero forms while the credential form sat at /login.
  // Only SURFACE the candidates here -- url-analyze.sh decides whether to spend a second fetch.
  // Same registrable domain only: legit sites SSO off-domain (login.microsoftonline.com) and
  // following that would import the identity provider's signals as if they were this site's.
  const loginStrong = /(^|[^a-z])(log[-_ ]?in|sign[-_ ]?in|signon|logon)([^a-z]|$)/i;
  const loginWeak   = /(^|[^a-z])(member[-_ ]?portal|my[-_ ]?account|portal|account|auth)([^a-z]|$)/i;
  const loginLinks = features.hasLoginForm ? [] : [...new Set(features.links.flatMap(a => {
    let u; try { u = new URL(a.href); } catch { return []; }
    if (!/^https?:$/.test(u.protocol) || apexOf(u.hostname) !== apexDomain) return [];
    const hay = `${a.text} ${u.pathname}`;         // link TEXT matters: "Member Portal" -> /portal
    if (loginStrong.test(hay)) return [[0, u.href]];
    if (loginWeak.test(hay))   return [[1, u.href]];
    return [];
  }).sort((x, y) => x[0] - y[0]).map(x => x[1]))].slice(0, 3);   // strong candidates first

  const result = {
    url: targetUrl,
    finalUrl: redirects.at(-1)?.url || targetUrl,
    status,
    redirects,
    domain, apexDomain,
    title: features.title,
    hasLoginForm: features.hasLoginForm,
    counts: {
      links: features.links.length,
      externalLinks: extLinks.length,
      internalLinks: intLinks.length,
      forms: features.forms.length,
      loginForms: features.forms.filter(f => f.hasPassword).length,
      scripts: features.scripts.length,
      iframes: features.iframes.length,
      images: features.images.length,
      thirdPartyDomains: thirdPartyDomains.length,
    },
    thirdPartyDomains,
    exfilDomains,
    webSockets,
    siteKeys,
    loginLinks,
    suspiciousJs: jsSmells,
    phishingSmells: smells,
    console: consoleLogs,
  };

  // A page that renders blank/empty but logged JS errors -- common with SPAs that fail to
  // mount headless, and worth flagging (the screenshot/vision won't see anything either).
  const consoleErrs = consoleLogs.filter(l => l.type === 'error' || l.type === 'pageerror');
  // Not on a 4xx/5xx: there the empty body IS the error page and the only console error is the
  // document's own failed load, so "an SPA that failed to mount" is a story about a page that was
  // never served. It read that way on every dead SendGrid click link, and a wrong explanation in
  // the LLM's context is worse than none -- the status is the finding, and the redirector rule
  // in url-analyze.sh reads it.
  if (features.text.trim().length < 20 && consoleErrs.length && !(status >= 400))
    smells.push(`Page did not render (${consoleErrs.length} JS error(s); likely an SPA that failed to mount headless)`);

  // ponytail: optional viewport screenshot for the vision-model escalation (argv[4] = container path)
  const shotPath = process.argv[4];
  if (shotPath) {
    // A template preloader hides itself on window 'load', and network idle does NOT imply that.
    // stl-hk.net had two Google font files still in flight ("Slow network is detected" in the
    // console), so load never fired and the shot was a spinner on white -- while the DOM behind it
    // was complete (15 links, 3 images, the real title). The DOM signals were fine; what was lost
    // is the vision phase and the human read, which is exactly the evidence a "cloak or just slow?"
    // call needs. So wait for the condition the preloader is actually waiting on, not for silence.
    await page.waitForFunction(() => document.readyState === 'complete', { timeout: 10000 }).catch(() => {});
    // Still covered? Then load is not coming. Hide the overlay rather than photograph it -- the
    // page underneath is already rendered, so this recovers a usable screenshot instead of
    // spending the ~1min vision call on a spinner. Named preloaders ONLY, and only while one
    // actually covers the viewport, so a real full-screen element (a login modal, a cloak gate --
    // the thing we most want to see) is never touched.
    // ponytail: the id/class naming IS the whole test. An unnamed overlay still gets photographed;
    // upgrade path is comparing two shots a second apart and only then removing what did not move.
    await page.evaluate(() => {
      const viewport = innerWidth * innerHeight;
      const named = '[id*="load" i],[class*="load" i],[id*="preload" i],[class*="preload" i],[id*="spin" i],[class*="spin" i]';
      for (const el of document.querySelectorAll(named)) {
        const s = getComputedStyle(el), r = el.getBoundingClientRect();
        if (s.display === 'none' || s.visibility === 'hidden' || parseFloat(s.opacity) === 0) continue;
        if ((s.position === 'fixed' || s.position === 'absolute') && r.width * r.height > viewport * 0.6)
          el.style.display = 'none';
      }
    }).catch(() => {});
    const isJpeg = /\.jpe?g$/i.test(shotPath);
    await page.screenshot({ path: shotPath, ...(isJpeg ? { quality: 70 } : {}) }).catch(() => {});
  }

  // ponytail: dump full inline scripts for the deobfuscation escalation (argv[5] = container dir),
  // but ONLY when obfuscation markers fired -- clean pages don't spill script files.
  const scriptsDir = process.argv[5];
  if (scriptsDir && jsSmells.length) {
    const fs = require('fs');
    features.inlineScripts.forEach((body, i) => {
      if (body.trim()) fs.writeFileSync(`${scriptsDir}/${String(i).padStart(2,'0')}.js`, body);
    });
  }

  console.log(JSON.stringify(result));
  await shutdown();
})();
SCRIPT

echo "Fetching page in sandboxed container..."

if ! docker image inspect "$IMAGE" &>/dev/null; then
  echo "Pulling puppeteer image (first run)..."
  docker pull "$IMAGE" >/dev/null
fi

# Mount a writable dir + pass a container path only when a screenshot was requested
SHOT_MOUNT=() SHOT_ARG=""
if [ -n "$SHOT" ]; then
  mkdir -p "$(dirname "$SHOT")" && chmod 777 "$(dirname "$SHOT")"  # ponytail: pptruser (uid!=host) must write the mount
  SHOT_MOUNT=(-v "$(dirname "$SHOT")":/out)
  SHOT_ARG="/out/$(basename "$SHOT")"
fi

# Same pattern for the inline-script dump (only when PAGE_SCRIPTS_DIR is set)
SCRIPTS_MOUNT=() SCRIPTS_ARG=""
if [ -n "$SCRIPTS_DIR" ]; then
  mkdir -p "$SCRIPTS_DIR" && chmod 777 "$SCRIPTS_DIR"
  SCRIPTS_MOUNT=(-v "$SCRIPTS_DIR":/scripts)
  SCRIPTS_ARG="/scripts"
fi

# Operator attach mode: reach the analyst's real browser (CDP on the host's 127.0.0.1) from
# inside the container -- Linux host networking shares the host loopback. Off unless PAGE_ATTACH set.
ATTACH_ARGS=()
[ -n "${PAGE_ATTACH:-}" ] && ATTACH_ARGS=(--network host -e PAGE_ATTACH="$PAGE_ATTACH")

# -p tor: route the scanner's egress through the Tor sidecar (llm-tor on the llm-net docker net)
# for geo-targeting / blacklist-dodging / attribution hygiene. Prints the actual exit IP+geo the
# kit will see (EGRESS line, before the JSON) and fails loud rather than silently going direct.
PROXY_ARGS=()
if [ "$PROXY" = tor ]; then
  "$SCRIPT_DIR/tor-up.sh" ${EXIT_CC:+-g "$EXIT_CC"} >&2 || { echo '{"error":"tor egress unavailable"}'; exit 0; }
  _eg=$(curl -s --max-time 20 --socks5-hostname 127.0.0.1:9050 http://ip-api.com/json 2>/dev/null)
  echo "EGRESS $(echo "$_eg" | jq -r '.query // "?"') $(echo "$_eg" | jq -r '.countryCode // "?"') $(echo "$_eg" | jq -r 'if (.org // "") != "" then .org elif (.isp // "") != "" then .isp else "?" end')"
  PROXY_ARGS=(--network llm-net -e PAGE_PROXY="socks5://llm-tor:9050")
fi

# Public Suffix List for the JS apexOf (see psl.sh). Mounted read-only; if the list is missing the
# script falls back to its old last-two-labels heuristic, so this is best-effort by design.
source "$SCRIPT_DIR/psl.sh"
PSL_MOUNT=()
psl_ensure && PSL_MOUNT=(-v "$PSL_FILE":/home/pptruser/psl.dat:ro)

_rc=0
timeout -k 10 "$PAGE_TIMEOUT" \
docker run --rm --name "$CONTAINER_NAME" \
  --cap-drop ALL \
  --cap-add SYS_ADMIN \
  --security-opt no-new-privileges \
  --security-opt seccomp=unconfined \
  --shm-size=256m \
  --memory 1g \
  --cpus 1 \
  -e BRAND_MATCH="$BRAND_MATCH" \
  "${ATTACH_ARGS[@]}" \
  "${PROXY_ARGS[@]}" \
  -v "$JS_TMP":/home/pptruser/script.js:ro \
  "${PSL_MOUNT[@]}" \
  "${SHOT_MOUNT[@]}" \
  "${SCRIPTS_MOUNT[@]}" \
  "$IMAGE" \
  node /home/pptruser/script.js "$URL" "$UA_MODE" "$SHOT_ARG" "$SCRIPTS_ARG" 2>/dev/null || _rc=$?

# 124 = timeout expired, 137 = it needed the KILL. Name it on stderr: an empty stdout otherwise
# reads as "the page would not load", and a scan that ran out of time is a different fact from a
# page that was never there.
if [ "$_rc" -ge 124 ]; then
  echo "page-fetch: timed out after ${PAGE_TIMEOUT}s (container killed) - $URL" >&2
fi
exit "$_rc"
