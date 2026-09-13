// humo_api_probe.js — probe the internal API endpoints from the build manifest.
// Tests: credentialed-content, bookmarks, recommendations, error, liveblog.
// All via browser context (WAF-safe), identified, paced.
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

  const evalAsync = async (expr) => {
    const r = await cdp(ws, 'Runtime.evaluate', {
      expression: `(async () => { ${expr} })()`,
      awaitPromise: true,
      returnByValue: true
    });
    return r.result.value;
  };

  // Make sure we're on humo.be
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be' });
  await new Promise(r => setTimeout(r, 5000));

  // Test 1: /api/credentialed-content (unauthenticated)
  console.log('=== Test 1: /api/credentialed-content ===');
  const t1 = await evalAsync(`
    const r = await fetch('https://www.humo.be/api/credentialed-content');
    return r.status + ' | ct=' + r.headers.get('content-type') + ' | ' + (await r.text()).slice(0, 500);
  `);
  console.log(t1);

  // Test 2: /api/_next-api/bookmarks (unauthenticated)
  console.log('\n=== Test 2: /api/_next-api/bookmarks ===');
  const t2 = await evalAsync(`
    const r = await fetch('https://www.humo.be/api/_next-api/bookmarks');
    return r.status + ' | ' + (await r.text()).slice(0, 500);
  `);
  console.log(t2);

  // Test 3: /api/_next-api/v1/recommendations (unauthenticated)
  console.log('\n=== Test 3: /api/_next-api/v1/recommendations ===');
  const t3 = await evalAsync(`
    const r = await fetch('https://www.humo.be/api/_next-api/v1/recommendations');
    return r.status + ' | ' + (await r.text()).slice(0, 500);
  `);
  console.log(t3);

  // Test 4: /api/_next-api/v1/error (unauthenticated)
  console.log('\n=== Test 4: /api/_next-api/v1/error ===');
  const t4 = await evalAsync(`
    const r = await fetch('https://www.humo.be/api/_next-api/v1/error');
    return r.status + ' | ' + (await r.text()).slice(0, 500);
  `);
  console.log(t4);

  // Test 5: /api/_next-api/v1/liveblog/moments (unauthenticated)
  console.log('\n=== Test 5: /api/_next-api/v1/liveblog/moments ===');
  const t5 = await evalAsync(`
    const r = await fetch('https://www.humo.be/api/_next-api/v1/liveblog/moments');
    return r.status + ' | ' + (await r.text()).slice(0, 500);
  `);
  console.log(t5);

  // Test 6: /api/_next-api/v1/liveblog/poll (unauthenticated)
  console.log('\n=== Test 6: /api/_next-api/v1/liveblog/poll ===');
  const t6 = await evalAsync(`
    const r = await fetch('https://www.humo.be/api/_next-api/v1/liveblog/poll');
    return r.status + ' | ' + (await r.text()).slice(0, 500);
  `);
  console.log(t6);

  // Test 7: /monitor/error (unauthenticated)
  console.log('\n=== Test 7: /monitor/error ===');
  const t7 = await evalAsync(`
    const r = await fetch('https://www.humo.be/monitor/error');
    return r.status + ' | ' + (await r.text()).slice(0, 500);
  `);
  console.log(t7);

  // Test 8: /web/urlpatterns (disallowed in robots.txt)
  console.log('\n=== Test 8: /web/urlpatterns ===');
  const t8 = await evalAsync(`
    const r = await fetch('https://www.humo.be/web/urlpatterns');
    return r.status + ' | ct=' + r.headers.get('content-type') + ' | ' + (await r.text()).slice(0, 500);
  `);
  console.log(t8);

  // Test 9: /api/_next-api/v1/auth/refresh (unauthenticated)
  console.log('\n=== Test 9: /api/_next-api/v1/auth/refresh ===');
  const t9 = await evalAsync(`
    const r = await fetch('https://www.humo.be/api/_next-api/v1/auth/refresh', { method: 'POST' });
    return r.status + ' | ' + (await r.text()).slice(0, 500);
  `);
  console.log(t9);

  // Test 10: /api/service-worker
  console.log('\n=== Test 10: /api/service-worker ===');
  const t10 = await evalAsync(`
    const r = await fetch('https://www.humo.be/api/service-worker');
    return r.status + ' | ct=' + r.headers.get('content-type') + ' | ' + (await r.text()).slice(0, 500);
  `);
  console.log(t10);

  ws.close();
  console.log('\n=== Done ===');
}

main().catch(e => { console.error(e); process.exit(1); });
