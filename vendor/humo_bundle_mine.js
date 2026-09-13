// humo_bundle_mine.js — mine www.humo.be JS bundles for GraphQL, API endpoints, auth patterns.
const http = require('http');
const fs = require('fs');
const path = require('path');

const DIR = path.join(__dirname, '..', 'findings', 'bounties', 'humo-h1');

function getJSON(p) {
  return new Promise((r, j) => {
    http.get({ host: '127.0.0.1', port: 9223, path: p }, c => {
      let d = '';
      c.on('data', x => d += x);
      c.on('end', () => r(JSON.parse(d)));
    }).on('error', j);
  });
}

function cdp(ws, m, p = {}) {
  return new Promise((r, j) => {
    const id = Math.floor(Math.random() * 1e9);
    const t = setTimeout(() => j(new Error('timeout')), 15000);
    const h = evt => {
      const msg = JSON.parse(evt.data);
      if (msg.id === id) { clearTimeout(t); ws.removeEventListener('message', h); msg.error ? j(new Error(JSON.stringify(msg.error))) : r(msg.result); }
    };
    ws.addEventListener('message', h);
    ws.send(JSON.stringify({ id, method: m, params: p }));
  });
}

async function main() {
  const targets = await getJSON('/json');
  let tab = targets.find(t => t.type === 'page');
  const ws = new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise(r => ws.onopen = r);
  await cdp(ws, 'Page.enable');
  await cdp(ws, 'Runtime.enable');
  await cdp(ws, 'Network.enable');
  await cdp(ws, 'Network.setExtraHTTPHeaders', {
    headers: { 'X-Intigriti-Username': 'greenbird122' }
  });

  // Navigate to www.humo.be and let it fully load
  console.log('=== Loading www.humo.be ===');
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be' });
  await new Promise(r => setTimeout(r, 8000));

  const evalJS = async (expr) => {
    const r = await cdp(ws, 'Runtime.evaluate', { expression: expr, returnByValue: true });
    return r.result.value;
  };

  // Get all script URLs
  const scripts = await evalJS(`
    JSON.stringify(Array.from(document.querySelectorAll('script[src]')).map(s => s.src))
  `);
  const scriptUrls = JSON.parse(scripts || '[]');
  console.log(`Found ${scriptUrls.length} script URLs`);

  // Get all API endpoints referenced in inline scripts
  const inlineApis = await evalJS(`
    JSON.stringify(
      (() => {
        const scripts = Array.from(document.querySelectorAll('script:not([src])'));
        const text = scripts.map(s => s.textContent).join('\\n');
        const apis = [];
        // GraphQL
        const gql = text.match(/['"](\\/api[^'"]*graphql[^'"]*|\\/graphql[^'"]*)/gi);
        if (gql) apis.push(...gql.map(u => 'GQL: ' + u));
        // REST endpoints
        const rest = text.match(/['"]\\/api\\/[^'"]+/gi);
        if (rest) apis.push(...rest.map(u => 'API: ' + u));
        // Auth-related
        const auth = text.match(/['"](?:https?:\\/\\/[^'"]*(?:auth|login|account|oauth)[^'"]*)/gi);
        if (auth) apis.push(...auth.map(u => 'AUTH: ' + u));
        return apis;
      })()
    )
  `);
  console.log(`\nInline API references: ${inlineApis}`);

  // Get fetch/XHR patterns
  const fetchPatterns = await evalJS(`
    JSON.stringify(
      (() => {
        const text = document.documentElement.innerHTML;
        const patterns = [];
        // fetch calls
        const fetches = text.match(/fetch\\(['"]([^'"]+)/g);
        if (fetches) patterns.push(...fetches.map(f => 'FETCH: ' + f));
        // XMLHttpRequest
        const xhrs = text.match(/\\.open\\(['"][A-Z]+['"],\\s*['"]([^'"]+)/g);
        if (xhrs) patterns.push(...xhrs.map(x => 'XHR: ' + x));
        // API base URLs
        const bases = text.match(/(?:apiUrl|baseUrl|apiBase|graphqlUrl|endpoint)['":\\s]+['"]([^'"]+)/gi);
        if (bases) patterns.push(...bases.map(b => 'BASE: ' + b));
        return [...new Set(patterns)];
      })()
    )
  `);
  console.log(`\nFetch/XHR patterns: ${fetchPatterns}`);

  // Check for Next.js or similar framework
  const framework = await evalJS(`
    (() => {
      const hints = [];
      if (window.__NEXT_DATA__) hints.push('Next.js');
      if (window.__NUXT__) hints.push('Nuxt.js');
      if (window.__remixContext) hints.push('Remix');
      if (document.querySelector('#__next')) hints.push('Next.js (DOM)');
      if (document.querySelector('#__nuxt')) hints.push('Nuxt.js (DOM)');
      // Check meta generator
      const gen = document.querySelector('meta[name="generator"]');
      if (gen) hints.push('generator: ' + gen.content);
      return hints.length ? hints.join(', ') : 'unknown framework';
    })()
  `);
  console.log(`\nFramework: ${framework}`);

  // Get CSP from response headers
  const cspResult = await evalJS(`
    (() => {
      const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
      return meta ? meta.content : 'no CSP meta tag';
    })()
  `);
  console.log(`\nCSP: ${cspResult.slice(0, 300)}`);

  // Check for any data-* attributes with API info
  const dataAttrs = await evalJS(`
    JSON.stringify(
      Array.from(document.querySelectorAll('[data-api], [data-url], [data-endpoint], [data-graphql]'))
        .map(e => ({ tag: e.tagName, attrs: Object.fromEntries(Array.from(e.attributes).filter(a => a.name.startsWith('data-')).map(a => [a.name, a.value])) }))
    )
  `);
  console.log(`\nData attributes: ${dataAttrs}`);

  // Download the external scripts from humo.be (not third-party)
  const humoScripts = scriptUrls.filter(u => u.includes('humo.be') && !u.includes('google') && !u.includes('facebook'));
  console.log(`\n=== Downloading ${humoScripts.length} Humo scripts ===`);
  for (const url of humoScripts.slice(0, 5)) {
    const label = url.split('/').pop().split('?')[0].replace(/[^a-zA-Z0-9._-]/g, '_');
    console.log(`  Fetching: ${label} (${url.slice(0, 100)})`);
    try {
      const content = await evalJS(`
        (async () => {
          const r = await fetch('${url}');
          return (await r.text()).slice(0, 100000);
        })()
      `);
      fs.writeFileSync(path.join(DIR, `bundle_${label}`), content || '');
      console.log(`    ✓ ${label}: ${(content || '').length} chars`);
    } catch (e) {
      console.log(`    ✗ ${label}: ${e.message}`);
    }
  }

  // Also get any inline script content that mentions API
  const inlineContent = await evalJS(`
    JSON.stringify(
      Array.from(document.querySelectorAll('script:not([src])'))
        .map(s => s.textContent)
        .filter(t => t.includes('api') || t.includes('graphql') || t.includes('endpoint') || t.includes('fetch'))
        .map(t => t.slice(0, 2000))
    )
  `);
  fs.writeFileSync(path.join(DIR, 'inline_scripts.json'), inlineContent || '[]');
  console.log(`\nInline scripts with API references saved`);

  ws.close();
  console.log('\n=== Done ===');
}

main().catch(e => { console.error(e); process.exit(1); });
