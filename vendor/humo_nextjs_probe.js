// humo_nextjs_probe.js — probe Next.js-specific attack surfaces on www.humo.be.
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

  const evalJS = async (expr) => {
    const r = await cdp(ws, 'Runtime.evaluate', { expression: expr, returnByValue: true });
    return r.result.value;
  };

  const evalAsync = async (expr) => {
    const r = await cdp(ws, 'Runtime.evaluate', {
      expression: `(async () => { ${expr} })()`,
      awaitPromise: true,
      returnByValue: true
    });
    return r.result.value;
  };

  // Make sure we're on the main site
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be' });
  await new Promise(r => setTimeout(r, 6000));

  // Test 1: __NEXT_DATA__
  console.log('=== Test 1: __NEXT_DATA__ ===');
  const nextData = await evalJS(`
    (() => {
      const el = document.getElementById('__NEXT_DATA__');
      if (el) return el.textContent.slice(0, 5000);
      if (window.__NEXT_DATA__) return JSON.stringify(window.__NEXT_DATA__).slice(0, 5000);
      return 'not found';
    })()
  `);
  console.log(nextData.slice(0, 2000));
  fs.writeFileSync(path.join(DIR, 'next_data.json'), nextData || 'not found');

  // Test 2: _next/data/ RSC endpoint
  console.log('\n=== Test 2: _next/data (RSC) ===');
  const rsc = await evalAsync(`
    const r = await fetch('https://www.humo.be/_next/data/fcfb6998eb14/index.json', {
      headers: { 'RSC': '1', 'Next-Router-State-Tree': '%5B%22%22%5D' }
    });
    return r.status + ' | ' + (await r.text()).slice(0, 1000);
  `);
  console.log(rsc);

  // Test 3: /api/ routes discovery
  console.log('\n=== Test 3: Common Next.js API routes ===');
  const apiPaths = ['/api', '/api/health', '/api/auth', '/api/user', '/api/graphql',
    '/api/v1', '/api/config', '/api/status', '/api/debug'];
  for (const p of apiPaths) {
    const r = await evalAsync(`
      const r = await fetch('https://www.humo.be${p}');
      return r.status + ' ' + r.headers.get('content-type');
    `);
    console.log(`  ${p}: ${r}`);
    await new Promise(r => setTimeout(r, 1500));
  }

  // Test 4: /_next/ internal routes
  console.log('\n=== Test 4: _next internal ===');
  const nextPaths = ['/_next/static/chunks/webpack manifest', '/_buildManifest.js', '/_ssgManifest.js',
    '/_next/static/fcfb6998eb14/_buildManifest.js', '/_next/static/fcfb6998eb14/_ssgManifest.js',
    '/sitemap.xml', '/robots.txt'];
  for (const p of nextPaths) {
    const r = await evalAsync(`
      const r = await fetch('https://www.humo.be${p}');
      return r.status + ' | ' + (await r.text()).slice(0, 200);
    `);
    console.log(`  ${p}: ${(r || '').slice(0, 150)}`);
    await new Promise(r => setTimeout(r, 1500));
  }

  // Test 5: View-source the __NEXT_DATA__ for server-side props leakage
  console.log('\n=== Test 5: Check for sensitive data in __NEXT_DATA__ ===');
  const sensitiveCheck = await evalJS(`
    (() => {
      const el = document.getElementById('__NEXT_DATA__');
      if (!el) return 'no __NEXT_DATA__';
      const data = el.textContent;
      const findings = [];
      // Check for API keys, tokens, secrets
      if (data.includes('apiKey') || data.includes('api_key')) findings.push('API key found');
      if (data.includes('token') && !data.includes('csrf')) findings.push('token found');
      if (data.includes('password') || data.includes('secret')) findings.push('password/secret found');
      if (data.includes('internal') || data.includes('debug')) findings.push('internal/debug found');
      if (data.includes('admin')) findings.push('admin reference found');
      // Check for user data
      const emailMatch = data.match(/[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\\.[a-zA-Z]+/g);
      if (emailMatch) findings.push('email found: ' + emailMatch[0]);
      // Check props structure
      if (data.includes('serverProps') || data.includes('pageProps')) findings.push('has page/server props');
      if (data.includes('buildId')) findings.push('buildId exposed');
      return findings.length ? findings.join('; ') : 'clean';
    })()
  `);
  console.log(`  ${sensitiveCheck}`);

  ws.close();
  console.log('\n=== Done ===');
}

main().catch(e => { console.error(e); process.exit(1); });
