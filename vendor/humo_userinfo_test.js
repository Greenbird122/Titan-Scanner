// humo_userinfo_test.js — test userinfo endpoint auth requirements
const http = require('http');

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

  const evalAsync = async (expr) => {
    const r = await cdp(ws, 'Runtime.evaluate', {
      expression: `(async () => { ${expr} })()`,
      awaitPromise: true,
      returnByValue: true
    });
    return r.result.value;
  };

  // Test 1: no token
  console.log('=== /userinfo (no token) ===');
  const t1 = await evalAsync(`
    const r = await fetch('https://login.dpgmedia.be/userinfo');
    return r.status + ' | ct=' + r.headers.get('content-type') + ' | ' + (await r.text()).slice(0, 300);
  `);
  console.log(t1);

  // Test 2: fake bearer
  console.log('\n=== /userinfo (fake bearer) ===');
  const t2 = await evalAsync(`
    const r = await fetch('https://login.dpgmedia.be/userinfo', {
      headers: { 'Authorization': 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.fake' } // pragma: allowlist secret
    });
    return r.status + ' | ' + (await r.text()).slice(0, 300);
  `);
  console.log(t2);

  // Test 3: empty bearer
  console.log('\n=== /userinfo (empty bearer) ===');
  const t3 = await evalAsync(`
    const r = await fetch('https://login.dpgmedia.be/userinfo', {
      headers: { 'Authorization': 'Bearer ' }
    });
    return r.status + ' | ' + (await r.text()).slice(0, 300);
  `);
  console.log(t3);

  // Test 4: Basic auth header
  console.log('\n=== /userinfo (basic auth) ===');
  const t4 = await evalAsync(`
    const r = await fetch('https://login.dpgmedia.be/userinfo', {
      headers: { 'Authorization': 'Basic dGVzdDp0ZXN0' }
    });
    return r.status + ' | ' + (await r.text()).slice(0, 300);
  `);
  console.log(t4);

  // Test 5: device code endpoint
  console.log('\n=== /device/code ===');
  const t5 = await evalAsync(`
    const r = await fetch('https://login.dpgmedia.be/device/code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'client_id=humo-selectives-web&scope=openid'
    });
    return r.status + ' | ' + (await r.text()).slice(0, 500);
  `);
  console.log(t5);

  // Test 6: introspection endpoint
  console.log('\n=== /introspect ===');
  const t6 = await evalAsync(`
    const r = await fetch('https://login.dpgmedia.be/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'token=fake_token&client_id=humo-selectives-web'
    });
    return r.status + ' | ' + (await r.text()).slice(0, 300);
  `);
  console.log(t6);

  // Test 7: revocation endpoint
  console.log('\n=== /revoke ===');
  const t7 = await evalAsync(`
    const r = await fetch('https://login.dpgmedia.be/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'token=fake_token&client_id=humo-selectives-web'
    });
    return r.status + ' | ' + (await r.text()).slice(0, 300);
  `);
  console.log(t7);

  ws.close();
}

main().catch(e => { console.error(e); process.exit(1); });
