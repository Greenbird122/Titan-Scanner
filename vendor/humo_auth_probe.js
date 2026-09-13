// humo_auth_probe.js — probe account.humo.be: callback_url validation,
// registration form, OAuth buttons, CSP. Uses Node 24 native WebSocket.
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

  // Test 1: The normal auth page
  console.log('=== Test 1: account.humo.be/login (normal) ===');
  await cdp(ws, 'Page.navigate', {
    url: 'https://account.humo.be/login?callback_url=https://mijnomgeving.humo.be/'
  });
  await new Promise(r => setTimeout(r, 5000));
  const normalUrl = await evalJS('window.location.href');
  const normalTitle = await evalJS('document.title');
  const normalBody = await evalJS('document.body ? document.body.innerText.slice(0, 2000) : ""');
  console.log(`  final URL: ${normalUrl}`);
  console.log(`  title: ${normalTitle}`);
  console.log(`  body preview:\n${normalBody.slice(0, 500)}`);

  // Get all forms and links
  const normalForms = await evalJS(`
    JSON.stringify(Array.from(document.querySelectorAll('form')).map(f => ({
      action: f.action, method: f.method,
      inputs: Array.from(f.querySelectorAll('input')).map(i => ({
        name: i.name, type: i.type, placeholder: i.placeholder, value: i.value
      }))
    })))
  `);
  console.log(`  forms: ${normalForms}`);

  const normalLinks = await evalJS(`
    JSON.stringify(Array.from(document.querySelectorAll('a')).map(a => ({
      text: a.textContent.trim().slice(0,60), href: a.href
    })).filter(a => a.href.includes('account') || a.href.includes('oauth') || a.href.includes('register') || a.href.includes('signup') || a.href.includes('google') || a.href.includes('microsoft')))
  `);
  console.log(`  auth links: ${normalLinks}`);

  // Save the auth page
  const normalHtml = await evalJS('document.documentElement.outerHTML');
  fs.writeFileSync(path.join(DIR, 'account_humo_normal.html'), normalHtml || '');
  console.log('  ✓ saved account_humo_normal.html');

  // Test 2: callback_url with external marker (open redirect detection)
  console.log('\n=== Test 2: callback_url = https://example.com (marker) ===');
  await cdp(ws, 'Page.navigate', {
    url: 'https://account.humo.be/login?callback_url=https://example.com'
  });
  await new Promise(r => setTimeout(r, 5000));
  const extUrl = await evalJS('window.location.href');
  console.log(`  final URL: ${extUrl}`);
  const extRedirected = extUrl.includes('example.com');
  console.log(`  redirected to external: ${extRedirected}`);

  // Test 3: callback_url with protocol-relative
  console.log('\n=== Test 3: callback_url = //evil.com ===');
  await cdp(ws, 'Page.navigate', {
    url: 'https://account.humo.be/login?callback_url=//evil.com'
  });
  await new Promise(r => setTimeout(r, 5000));
  const protUrl = await evalJS('window.location.href');
  console.log(`  final URL: ${protUrl}`);

  // Test 4: callback_url with backslash
  console.log('\n=== Test 4: callback_url = https://mijnomgeving.humo.be%0d%0aLocation:%20https://evil.com ===');
  await cdp(ws, 'Page.navigate', {
    url: 'https://account.humo.be/login?callback_url=https://mijnomgeving.humo.be%0d%0aLocation:%20https://evil.com'
  });
  await new Promise(r => setTimeout(r, 5000));
  const crlfUrl = await evalJS('window.location.href');
  console.log(`  final URL: ${crlfUrl}`);

  // Test 5: Check if account.humo.be has its own CSP
  console.log('\n=== Test 5: CSP on account.humo.be ===');
  // Re-navigate to the normal page first
  await cdp(ws, 'Page.navigate', {
    url: 'https://account.humo.be/login?callback_url=https://mijnomgeving.humo.be/'
  });
  await new Promise(r => setTimeout(r, 5000));
  const csp = await evalJS(`
    (() => {
      const m = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
      return m ? m.content : null;
    })()
  `);
  console.log(`  CSP meta: ${csp}`);

  // Get CSP from response headers via Network
  // We already have Network enabled, let's capture headers from a fresh navigation
  const headers = {};
  const headerHandler = (evt) => {
    const msg = JSON.parse(evt.data);
    if (msg.method === 'Network.responseReceived') {
      const hdrs = msg.params.response.headers;
      if (hdrs['content-security-policy']) {
        headers['csp'] = hdrs['content-security-policy'];
      }
      if (hdrs['set-cookie']) {
        headers['set-cookie'] = hdrs['set-cookie'];
      }
    }
  };
  ws.addEventListener('message', headerHandler);
  await cdp(ws, 'Page.navigate', {
    url: 'https://account.humo.be/login?callback_url=https://mijnomgeving.humo.be/'
  });
  await new Promise(r => setTimeout(r, 5000));
  ws.removeEventListener('message', headerHandler);
  console.log(`  response CSP: ${headers['csp'] || 'none'}`);
  console.log(`  set-cookie: ${headers['set-cookie'] || 'none'}`);

  // Test 6: Check registration path — does account.humo.be have a register endpoint?
  console.log('\n=== Test 6: account.humo.be/register ===');
  await cdp(ws, 'Page.navigate', {
    url: 'https://account.humo.be/register?callback_url=https://mijnomgeving.humo.be/'
  });
  await new Promise(r => setTimeout(r, 5000));
  const regUrl = await evalJS('window.location.href');
  const regTitle = await evalJS('document.title');
  const regBody = await evalJS('document.body ? document.body.innerText.slice(0, 1500) : ""');
  console.log(`  final URL: ${regUrl}`);
  console.log(`  title: ${regTitle}`);
  console.log(`  body preview:\n${regBody.slice(0, 500)}`);

  const regForms = await evalJS(`
    JSON.stringify(Array.from(document.querySelectorAll('form')).map(f => ({
      action: f.action, method: f.method,
      inputs: Array.from(f.querySelectorAll('input')).map(i => ({
        name: i.name, type: i.type, placeholder: i.placeholder
      }))
    })))
  `);
  console.log(`  forms: ${regForms}`);

  const regHtml = await evalJS('document.documentElement.outerHTML');
  fs.writeFileSync(path.join(DIR, 'account_humo_register.html'), regHtml || '');
  console.log('  ✓ saved account_humo_register.html');

  // Save summary
  const summary = {
    normalAuth: { finalUrl: normalUrl, title: normalTitle },
    callbackRedirect: { finalUrl: extUrl, redirectedToExternal: extRedirected },
    protocolRelative: { finalUrl: protUrl },
    crlf: { finalUrl: crlfUrl },
    csp: csp,
    responseHeaders: headers,
    register: { finalUrl: regUrl, title: regTitle },
    timestamp: new Date().toISOString()
  };
  fs.writeFileSync(path.join(DIR, 'auth_probe.json'), JSON.stringify(summary, null, 2));
  console.log('\n=== Summary saved to auth_probe.json ===');

  ws.close();
}

main().catch(e => { console.error(e); process.exit(1); });
