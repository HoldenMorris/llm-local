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

cat << 'SCRIPT' > /tmp/page-fetch.js
const puppeteer = require('puppeteer');
const { URL } = require('url');

(async () => {
  const targetUrl = process.argv[2];
  const parsed = new URL(targetUrl);
  // let: re-anchored to the LANDED host after redirects so analysis isn't judged against the entry shortener
  let domain = parsed.hostname;
  let apexDomain = domain.split('.').slice(-2).join('.');

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

  const landedUrl = page.url();
  if (!landedUrl || landedUrl === 'about:blank') {
    console.log(JSON.stringify({ error: 'timeout or unreachable' }));
    await shutdown();
    process.exit(0);
  }

  const status = resp ? resp.status() : 0;

  // Re-anchor host to where we actually landed (redirects may cross domains)
  domain = new URL(landedUrl).hostname;
  apexDomain = domain.split('.').slice(-2).join('.');

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
      hasPassword: !!f.querySelector('input[type="password"]'),
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

    return {
      title: document.title,
      text: deepText().slice(0, 4000),
      links, forms, scripts, inlineScripts, iframes, images, meta, metaRefresh,
      hasLoginForm: deepAll('input[type="password"]').length > 0,
    };
  });

  // SPAs / webmail (e.g. Securemail, Zimbra) render the login form INSIDE an iframe, invisible
  // to a main-frame-only DOM query. Puppeteer can evaluate in child frames, so merge their
  // forms + password fields + text/title so login detection and brand/urgency checks work.
  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;
    try {
      const sub = await frame.evaluate(() => ({
        forms: Array.from(document.forms).map(f => ({
          action: f.action, method: f.method,
          hasPassword: !!f.querySelector('input[type="password"]'),
          inputs: Array.from(f.querySelectorAll('input')).map(i => ({ type: i.type, name: i.name, placeholder: i.placeholder })),
        })),
        hasPassword: !!document.querySelector('input[type="password"]'),
        text: (document.body ? document.body.innerText : '').slice(0, 4000),
        title: document.title,
      }));
      if (sub.forms.length) features.forms.push(...sub.forms);
      if (sub.hasPassword) features.hasLoginForm = true;
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
    'google','facebook','microsoft','apple','amazon','paypal','netflix','instagram','linkedin','twitter','github','dropbox','adobe','zoom','slack',
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
  // Where a brand must appear to count as impersonation. Config knob: BRAND_MATCH env.
  //   'strict' (default): page TITLE or a FORM ACTION -- the strong signals a phishing clone
  //            emits (titles itself "PayPal Login", posts creds to a paypal-named URL).
  //   'body': also count body-text mentions -- noisier; legit content sites merely NAME brands
  //           (wikipedia -> "google, apple"), so this over-flags. Kept for future tuning.
  const brandMatch = (process.env.BRAND_MATCH || 'strict').toLowerCase();
  const title = (features.title || '').toLowerCase();
  const formActions = features.forms.map(f => (f.action || '').toLowerCase()).join(' ');
  const body = features.text.toLowerCase();
  const brandHaystack = brandMatch === 'body'
    ? [title, formActions, body].join(' ')
    : [title, formActions].join(' ');
  // Word-boundary match so short brands (e.g. "ing") don't hit inside "tracking"/"information"
  const matched = brands.filter(b => new RegExp(`\\b${b}\\b`, 'i').test(brandHaystack));
  if (matched.length) {
    const dom = domain.toLowerCase();
    const brandInDomain = matched.some(b => dom.includes(b.replace(/\s/g,'')));
    // Check if brand is explained by legitimate OAuth/payment integration
    const brandExplainedByOAuth = matched.every(b =>
      thirdPartyDomains.some(d => d.includes(b.replace(/\s/g,'')) || oauthPaymentDomains.some(o => d.includes(o.split('.')[0])))
    );
    if (!brandInDomain && !brandExplainedByOAuth)
      smells.push(`Brand impersonation: "${matched.slice(0,3).join(', ')}" in title/form but domain is "${domain}"`);
  }

  // Links
  const extLinks = features.links.filter(l => l.isExternal);
  const intLinks = features.links.filter(l => !l.isExternal);
  if (extLinks.length > intLinks.length * 2 && extLinks.length > 3)
    smells.push(`Skewed link profile: ${extLinks.length} external vs ${intLinks.length} internal`);

  // Login form to external
  for (const f of features.forms) {
    if (f.hasPassword && f.action) {
      try {
        if (new URL(f.action).hostname !== domain)
          smells.push(`Login form submits to "${new URL(f.action).hostname}" (off-domain)`);
      } catch {}
    }
  }

  // Iframes
  if (features.iframes.length > 2)
    smells.push(`${features.iframes.length} iframes - possible clickjacking`);

  // Redirects
  if (redirects.length > 2)
    smells.push(`${redirects.length}-hop redirect chain`);

  // Bot / human-verification gates cloaking the real page from the scraper. Detect the major
  // providers by the scripts they load -- fires whether the challenge is invisible or an
  // interactive click. On a redirect-chain phish this is deliberate cloaking; it also explains a
  // "dead" (404/empty) land. Each smell ends with "gated from the scraper" so url-analyze's
  // operator-attach trigger can match any provider with one test.
  const gateProviders = [
    { re: /challenges\.cloudflare\.com|__cf_chl|cdn-cgi\/challenge/i, name: 'Cloudflare Turnstile' },
    { re: /\bhcaptcha\.com|newassets\.hcaptcha\.com/i, name: 'hCaptcha' },
    { re: /google\.com\/recaptcha|gstatic\.com\/recaptcha|recaptcha\/api\.js/i, name: 'reCAPTCHA' },
  ];
  for (const g of gateProviders)
    if (requests.some(r => g.re.test(r.url)))
      smells.push(`${g.name} challenge - real page gated from the scraper`);

  // ponytail: silent Refresh redirects (HTTP "Refresh:" header or <meta refresh>) -- cloaker
  // gates that bounce victims without a visible 3xx Location. Flag when a url= target exists.
  const refreshHit = refreshHeaders.find(rh => /url=/i.test(rh));
  if (refreshHit)
    smells.push(`HTTP Refresh header redirect: ${refreshHit.slice(0,120)}`);
  const metaRefreshFound = metaRefreshSeen || features.metaRefresh;
  if (metaRefreshFound && /url=/i.test(metaRefreshFound))
    smells.push(`Meta-refresh redirect: ${metaRefreshFound.slice(0,120)}`);

  // HTTPS -- judge the landed URL, not the typed one (HTTP->HTTPS redirect is secure)
  if ((redirects.at(-1)?.url || targetUrl).startsWith('http:'))
    smells.push('Served over HTTP (no TLS)');

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
  const apexOf = h => (h || '').toLowerCase().split('.').slice(-2).join('.');
  const hostsIn = (t) => [...String(t).matchAll(/https?:\/\/([a-z0-9.-]+)/gi)].map(m => m[1].toLowerCase());
  const cdnRe = /(googleapis|gstatic|cloudflare|jsdelivr|unpkg|cdnjs|jquery|bootstrapcdn|google-analytics|googletagmanager|fontawesome|recaptcha|hcaptcha|gravatar|w3\.org|schema\.org)/i;
  // Only covert exfil vectors count: an off-domain FORM ACTION (posts data cross-domain) or a
  // host HIDDEN in an obfuscated/base64 blob. A host sitting in plain, readable JS is auditable
  // and overwhelmingly analytics/RUM/CDN -- not covert theft -- so it is NOT treated as exfil.
  const exfilDomains = [...new Set([
    ...features.forms.map(f => { try { return new URL(f.action).hostname.toLowerCase(); } catch { return ''; } }),
    ...hostsIn(b64decoded),
  ])].filter(h => h && apexOf(h) !== apexDomain && !cdnRe.test(h));
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
    .filter(h => h && apexOf(h) !== apexDomain && !cdnRe.test(h) && !exfilDomains.includes(h));
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

  // ponytail: Random URL path (high entropy paths like /kz51odwn/)
  const pathParts = new URL(landedUrl).pathname.split('/').filter(p => p.length > 4);
  const randomPath = pathParts.find(p => /^[a-z0-9]{5,}$/i.test(p) && !/^(index|login|admin|user|api|auth)$/i.test(p));
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

  // ponytail: Right-click/context menu disabled
  if (/oncontextmenu.*return\s*false|preventDefault.*contextmenu/i.test(allJs))
    smells.push('Right-click disabled');

  // ponytail: Crypto wallet addresses
  const cryptoPatterns = /(^|[^a-z0-9])(bc1[a-z0-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|T[A-Za-z1-9]{33})([^a-z0-9]|$)/;
  if (cryptoPatterns.test(body))
    smells.push('Crypto wallet address found');

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
    suspiciousJs: jsSmells,
    phishingSmells: smells,
    console: consoleLogs,
  };

  // A page that renders blank/empty but logged JS errors -- common with SPAs that fail to
  // mount headless, and worth flagging (the screenshot/vision won't see anything either).
  const consoleErrs = consoleLogs.filter(l => l.type === 'error' || l.type === 'pageerror');
  if (features.text.trim().length < 20 && consoleErrs.length)
    smells.push(`Page did not render (${consoleErrs.length} JS error(s); likely an SPA that failed to mount headless)`);

  // ponytail: optional viewport screenshot for the vision-model escalation (argv[4] = container path)
  const shotPath = process.argv[4];
  if (shotPath) {
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
  -v /tmp/page-fetch.js:/home/pptruser/script.js:ro \
  "${SHOT_MOUNT[@]}" \
  "${SCRIPTS_MOUNT[@]}" \
  "$IMAGE" \
  node /home/pptruser/script.js "$URL" "$UA_MODE" "$SHOT_ARG" "$SCRIPTS_ARG" 2>/dev/null

rm -f /tmp/page-fetch.js
