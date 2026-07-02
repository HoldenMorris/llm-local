#!/bin/bash

# Sandboxed page fetcher + feature extractor
# Uses Puppeteer in a disposable container
# Outputs JSON with page features for LLM analysis

set -e

URL="${1:?Usage: $0 <url>}"

CONTAINER_NAME="llm-page-fetch-$$"
IMAGE="ghcr.io/puppeteer/puppeteer:latest"

cat << 'SCRIPT' > /tmp/page-fetch.js
const puppeteer = require('puppeteer');
const { URL } = require('url');

(async () => {
  const targetUrl = process.argv[2];
  const parsed = new URL(targetUrl);
  const domain = parsed.hostname;
  const apexDomain = domain.split('.').slice(-2).join('.');

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

  await page.setUserAgent(
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
  );
  await page.setViewport({ width: 1920, height: 1080 });

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

  const resp = await page.goto(targetUrl, {
    waitUntil: 'networkidle0',
    timeout: 15000
  }).catch(() => null);

  if (!resp) {
    console.log(JSON.stringify({ error: 'timeout or unreachable' }));
    await browser.close();
    process.exit(0);
  }

  // Redirect chain
  const redirects = [];
  let r = resp;
  while (r) {
    redirects.push({ url: r.url(), status: r.status() });
    r = r.request().redirectChain().length
      ? r.request().redirectChain().at(-1).response()
      : null;
  }

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

    return {
      title: document.title,
      text: (document.body ? document.body.innerText : '').slice(0, 4000),
      links, forms, scripts, iframes, images, meta,
      hasLoginForm: !!document.querySelector('input[type="password"]'),
    };
  });

  // --- Analysis ---

  const smells = [];

  // External resources summary (moved up for brand check)
  const thirdParty = requests.filter(r => r.isThirdParty);
  const thirdPartyDomains = [...new Set(thirdParty.map(r => r.domain))].slice(0,15);

  // Brand mismatch - but whitelist OAuth/payment integrations
  const brands = ['google','facebook','microsoft','apple','amazon','paypal',
    'netflix','instagram','linkedin','twitter','github','dropbox','adobe',
    'chase','wells fargo','amex','visa','mastercard'];
  // ponytail: OAuth/payment providers whose presence explains brand mentions
  const oauthPaymentDomains = ['accounts.google.com','apis.google.com','facebook.com','login.microsoftonline.com',
    'appleid.apple.com','amazon.com','paypal.com','stripe.com','js.stripe.com','m.stripe.com','github.com',
    'login.live.com','auth0.com','okta.com','supabase.co'];
  const body = features.text.toLowerCase();
  const matched = brands.filter(b => body.includes(b));
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
    smells.push(`${features.iframes.length} iframes — possible clickjacking`);

  // Redirects
  if (redirects.length > 2)
    smells.push(`${redirects.length}-hop redirect chain`);

  // HTTPS
  if (targetUrl.startsWith('http:'))
    smells.push('Served over HTTP (no TLS)');

  // Suspicious JS
  const allJs = features.scripts.filter(s => s.src === 'inline').map(s => s.text).join('\n');
  const jsSmells = [];
  if (/eval\s*\(/.test(allJs)) jsSmells.push('eval()');
  if (/atob\s*\(/.test(allJs)) jsSmells.push('atob()');
  if (/document\.write/.test(allJs)) jsSmells.push('document.write()');
  if (/(?:\\x[0-9a-f]{2}){3,}/i.test(allJs)) jsSmells.push('hex-encoded strings');
  if (/window\.location\s*=/.test(allJs)) jsSmells.push('location redirect');

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
  const pathParts = new URL(targetUrl).pathname.split('/').filter(p => p.length > 4);
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
    status: resp.status(),
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

  console.log(JSON.stringify(result));
  await browser.close();
})();
SCRIPT

echo "Fetching page in sandboxed container..."

if ! docker image inspect "$IMAGE" &>/dev/null; then
  echo "Pulling puppeteer image (first run)..."
  docker pull "$IMAGE" >/dev/null
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
  "$IMAGE" \
  node /home/pptruser/script.js "$URL" 2>/dev/null

rm -f /tmp/page-fetch.js
