#!/bin/bash

# Sandboxed page fetcher + feature extractor
# Uses Puppeteer in a disposable container
# Outputs JSON with page features for LLM analysis

set -e

# ponytail: -m/--mobile swaps to a mobile UA to defeat mobile-only cloakers
UA_MODE="desktop"
[[ "$1" == "-m" || "$1" == "--mobile" ]] && { UA_MODE="mobile"; shift; }
URL="${1:?Usage: $0 [-m|--mobile] <url>}"

# ponytail: PAGE_SHOT=<host .png/.jpg> also saves a viewport screenshot there, for
# the vision-model escalation step. Unset = no screenshot, no output change.
SHOT="${PAGE_SHOT:-}"

# ponytail: PAGE_SCRIPTS_DIR=<host dir> dumps FULL inline script bodies there, but only
# when obfuscation markers fire, for the JS-deobfuscation escalation. Unset = no dump.
SCRIPTS_DIR="${PAGE_SCRIPTS_DIR:-}"

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

  const browser = await puppeteer.launch({
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--no-first-run'
    ]
  });

  const page = await browser.newPage();

  // ponytail: mobile UA when requested  many phishing cloakers only forward mobile victims
  const uaMode = process.argv[3] || 'desktop';
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

  // Track every main-frame navigation (captures JS/meta/cookie redirects, not just HTTP 3xx)
  const hops = [];
  page.on('framenavigated', (frame) => {
    const u = frame.url();
    if (frame === page.mainFrame() && u && u !== 'about:blank' && hops.at(-1) !== u) hops.push(u);
  });

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

  // Initial navigation  tolerate mid-flight JS redirects that destroy the JS context
  let resp = await page.goto(targetUrl, {
    waitUntil: 'domcontentloaded',
    timeout: 30000
  }).catch(() => null);

  // Follow JS/meta/cookie redirects (cloaker gates) until the URL stops changing
  let prevUrl = null;
  for (let i = 0; i < 6 && page.url() !== prevUrl; i++) {
    prevUrl = page.url();
    const nav = await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 8000 }).catch(() => null);
    if (nav) resp = nav;
  }

  // Let the landing page settle so dynamically-injected forms/scripts are captured
  await page.waitForNetworkIdle({ idleTime: 1500, timeout: 15000 }).catch(() => {});

  const landedUrl = page.url();
  if (!landedUrl || landedUrl === 'about:blank') {
    console.log(JSON.stringify({ error: 'timeout or unreachable' }));
    await browser.close();
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

  const features = await page.evaluate(() => {
    const links = Array.from(document.querySelectorAll('a[href]')).map(a => ({
      href: a.href, text: (a.textContent||'').trim().slice(0,80),
      isExternal: a.hostname && a.hostname !== location.hostname
    }));

    const forms = Array.from(document.forms).map(f => ({
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
      text: (document.body ? document.body.innerText : '').slice(0, 4000),
      links, forms, scripts, inlineScripts, iframes, images, meta,
      hasLoginForm: !!document.querySelector('input[type="password"]'),
    };
  });

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
  const body = features.text.toLowerCase();
  // Word-boundary match so short brands (e.g. "ing") don't hit inside "tracking"/"information"
  const matched = brands.filter(b => new RegExp(`\\b${b}\\b`, 'i').test(body));
  if (matched.length) {
    const dom = domain.toLowerCase();
    const brandInDomain = matched.some(b => dom.includes(b.replace(/\s/g,'')));
    // Check if brand is explained by legitimate OAuth/payment integration
    const brandExplainedByOAuth = matched.every(b =>
      thirdPartyDomains.some(d => d.includes(b.replace(/\s/g,'')) || oauthPaymentDomains.some(o => d.includes(o.split('.')[0])))
    );
    if (!brandInDomain && !brandExplainedByOAuth)
      smells.push(`Brand impersonation: page mentions "${matched.slice(0,3).join(', ')}" but domain is "${domain}"`);
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

  // HTTPS
  if (targetUrl.startsWith('http:'))
    smells.push('Served over HTTP (no TLS)');

  // Suspicious JS -- scan FULL inline bodies, not the 1000-char preview
  const allJs = features.inlineScripts.join('\n');
  const jsSmells = [];
  if (/eval\s*\(/.test(allJs)) jsSmells.push('eval()');
  if (/atob\s*\(/.test(allJs)) jsSmells.push('atob()');
  if (/document\.write/.test(allJs)) jsSmells.push('document.write()');
  if (/(?:\\x[0-9a-f]{2}){3,}/i.test(allJs)) jsSmells.push('hex-encoded strings');
  if (/window\.location\s*=/.test(allJs)) jsSmells.push('location redirect');
  // obfuscator.io hallmarks (the obfuscator most phishing kits use, and what webcrack cracks):
  // hex-named identifiers like _0x4c8c82 in quantity, and String.fromCharCode string-building.
  if ((allJs.match(/_0x[0-9a-f]{4,}/gi) || []).length >= 5) jsSmells.push('obfuscated identifiers (_0x)');
  if (/String\.fromCharCode\s*\(/.test(allJs)) jsSmells.push('String.fromCharCode');

  // ponytail: IP fingerprinting services used to track victims
  const ipFingerprinters = ['api.ipify.org','ipinfo.io','ip-api.com','ipapi.co','checkip.amazonaws.com',
    'ifconfig.me','icanhazip.com','wtfismyip.com','ipecho.net','myexternalip.com'];
  const fingerprintHits = thirdPartyDomains.filter(d => ipFingerprinters.some(f => d.includes(f)));
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
    suspiciousJs: jsSmells,
    phishingSmells: smells,
  };

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
  await browser.close();
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

docker run --rm --name "$CONTAINER_NAME" \
  --cap-drop ALL \
  --cap-add SYS_ADMIN \
  --security-opt no-new-privileges \
  --security-opt seccomp=unconfined \
  --shm-size=256m \
  --memory 1g \
  --cpus 1 \
  -v /tmp/page-fetch.js:/home/pptruser/script.js:ro \
  "${SHOT_MOUNT[@]}" \
  "${SCRIPTS_MOUNT[@]}" \
  "$IMAGE" \
  node /home/pptruser/script.js "$URL" "$UA_MODE" "$SHOT_ARG" "$SCRIPTS_ARG" 2>/dev/null

rm -f /tmp/page-fetch.js
