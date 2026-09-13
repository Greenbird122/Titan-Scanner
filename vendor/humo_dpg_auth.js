// humo_dpg_auth.js — probe login.dpgmedia.be: password reset, subscription lookup,
// OIDC endpoints. All identified, all in-scope via the *.humo.be wildcard (auth backend).
const http = require('http');
const fs = require('fs');
const path = require('path');

const DIR = path.join(__dirname, '..', 'findings', 'bounties', 'humo-h1');

function getJSON(urlPath) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: 9223, path: urlPath }, (r) => {
      let d = '';
      r.on('data', (c) => (d += c));
      r.on('end', () => resolve(JSON.parse(d)));
    }).on('error', reject);
  });
}

function cdp(ws, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 1e9);
    const timeout = setTimeout(() => reject(new Error('cdp timeout')), 12000);
    const handler = (evt) => {
      const msg = JSON.parse(evt.data);
      if (msg.id === id) {
        clearTimeout(timeout);
        ws.removeEventListener('message', handler);
        if (msg.error) reject(new Error(JSON.stringify(msg.error)));
        else resolve(msg.result);
      }
    };
    ws.addEventListener('message', handler);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function main() {
  const targets = await getJSON('/json');
  let tab = targets.find(t => t.type === 'page');
  if (!tab) tab = await getJSON('/json/new?about:blank');

  const ws = new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });

  await cdp(ws, 'Page.enable');
  await cdp(ws, 'Network.enable');
  await cdp(ws, 'Runtime.enable');
  await cdp(ws, 'Network.setExtraHTTPHeaders', {
    headers: { 'X-Intigriti-Username': 'greenbird122' }
  });

  const evalJS = async (expr) => {
    const r = await cdp(ws, 'Runtime.evaluate', { expression: expr, returnByValue: true });
    return r.result.value;
  };

  // Test 1: Password reset page
  console.log('=== Test 1: Password reset ===');
  await cdp(ws, 'Page.navigate', {
    url: 'https://login.dpgmedia.be/password/reset?client_id=humo-selectives-web'
  });
  await new Promise(r => setTimeout(r, 5000));
  const resetUrl = await evalJS('window.location.href');
  const resetTitle = await evalJS('document.title');
  const resetBody = await evalJS('document.body ? document.body.innerText.slice(0, 2000) : ""');
  console.log(`  URL: ${resetUrl}`);
  console.log(`  title: ${resetTitle}`);
  console.log(`  body:\n${resetBody.slice(0, 800)}`);

  const resetForms = await evalJS(`
    JSON.stringify(Array.from(document.querySelectorAll('form')).map(f => ({
      action: f.action, method: f.method,
      inputs: Array.from(f.querySelectorAll('input')).map(i => ({
        name: i.name, type: i.type, placeholder: i.placeholder
      }))
    })))
  `);
  console.log(`  forms: ${resetForms}`);

  // Save HTML
  const resetHtml = await evalJS('document.documentElement.outerHTML');
  fs.writeFileSync(path.join(DIR, 'dpg_password_reset.html'), resetHtml || '');
  console.log('  ✓ saved');

  // Test 2: Subscription lookup
  console.log('\n=== Test 2: Subscription lookup ===');
  await cdp(ws, 'Page.navigate', {
    url: 'https://login.dpgmedia.be/subscription/lookup?client_id=humo-selectives-web&origin=IDENTIFY'
  });
  await new Promise(r => setTimeout(r, 5000));
  const lookUrl = await evalJS('window.location.href');
  const lookTitle = await evalJS('document.title');
  const lookBody = await evalJS('document.body ? document.body.innerText.slice(0, 2000) : ""');
  console.log(`  URL: ${lookUrl}`);
  console.log(`  title: ${lookTitle}`);
  console.log(`  body:\n${lookBody.slice(0, 800)}`);

  const lookForms = await evalJS(`
    JSON.stringify(Array.from(document.querySelectorAll('form')).map(f => ({
      action: f.action, method: f.method,
      inputs: Array.from(f.querySelectorAll('input')).map(i => ({
        name: i.name, type: i.type, placeholder: i.placeholder
      }))
    })))
  `);
  console.log(`  forms: ${lookForms}`);

  const lookHtml = await evalJS('document.documentElement.outerHTML');
  fs.writeFileSync(path.join(DIR, 'dpg_subscription_lookup.html'), lookHtml || '');
  console.log('  ✓ saved');

  // Test 3: Check if client_id parameter is validated (try a different brand)
  console.log('\n=== Test 3: client_id = parool-selectives-web (cross-brand) ===');
  await cdp(ws, 'Page.navigate', {
    url: 'https://login.dpgmedia.be/identify?client_id=parool-selectives-web'
  });
  await new Promise(r => setTimeout(r, 5000));
  const crossUrl = await evalJS('window.location.href');
  const crossTitle = await evalJS('document.title');
  const crossBody = await evalJS('document.body ? document.body.innerText.slice(0, 1000) : ""');
  console.log(`  URL: ${crossUrl}`);
  console.log(`  title: ${crossTitle}`);
  console.log(`  body preview: ${crossBody.slice(0, 300)}`);

  // Test 4: Check OIDC well-known endpoint
  console.log('\n=== Test 4: OIDC well-known ===');
  await cdp(ws, 'Page.navigate', {
    url: 'https://login.dpgmedia.be/.well-known/openid-configuration'
  });
  await new Promise(r => setTimeout(r, 5000));
  const oidcUrl = await evalJS('window.location.href');
  const oidcBody = await evalJS('document.body ? document.body.innerText.slice(0, 3000) : ""');
  console.log(`  URL: ${oidcUrl}`);
  console.log(`  body:\n${oidcBody.slice(0, 1500)}`);

  // Save OIDC config
  fs.writeFileSync(path.join(DIR, 'dpg_oidc_config.txt'), oidcBody || '');
  console.log('  ✓ saved');

  // Test 5: Check pipOidcHelper.js for secrets/config
  console.log('\n=== Test 5: pipOidcHelper.js ===');
  await cdp(ws, 'Page.navigate', {
    url: 'https://login-static.dpgmedia.net/resources/scripts/pipOidcHelper.js?version=c1c35b131a6ef90c8dadbfd7244d7f99'
  });
  await new Promise(r => setTimeout(r, 5000));
  const jsBody = await evalJS('document.body ? document.body.innerText.slice(0, 5000) : ""');
  console.log(`  body length: ${(jsBody || '').length}`);
  console.log(`  body preview:\n${(jsBody || '').slice(0, 2000)}`);
  fs.writeFileSync(path.join(DIR, 'dpg_oidc_helper.js'), jsBody || '');
  console.log('  ✓ saved');

  // Summary
  const summary = {
    passwordReset: { url: resetUrl, title: resetTitle },
    subscriptionLookup: { url: lookUrl, title: lookTitle },
    crossBrand: { url: crossUrl, title: crossTitle },
    oidcConfig: { url: oidcUrl },
    timestamp: new Date().toISOString()
  };
  fs.writeFileSync(path.join(DIR, 'dpg_auth_probe.json'), JSON.stringify(summary, null, 2));
  console.log('\n=== Summary saved to dpg_auth_probe.json ===');

  ws.close();
}

main().catch(e => { console.error(e); process.exit(1); });
