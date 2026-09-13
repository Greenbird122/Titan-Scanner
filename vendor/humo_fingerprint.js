// humo_fingerprint.js — fingerprint all in-scope Humo endpoints via CDP (port 9223).
// Uses Node 24 native WebSocket. One navigation per host, captures: final URL,
// title, CSP, forms, OAuth buttons, scripts, cookies, GraphQL hints.
const http = require('http');
const fs = require('fs');
const path = require('path');

const DIR = path.join(__dirname, '..', 'findings', 'bounties', 'humo-h1');
fs.mkdirSync(DIR, { recursive: true });

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
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });

  await cdp(ws, 'Page.enable');
  await cdp(ws, 'Network.enable');
  await cdp(ws, 'Runtime.enable');
  await cdp(ws, 'Network.setExtraHTTPHeaders', {
    headers: { 'X-Intigriti-Username': 'greenbird122' }
  });

  const hosts = [
    'https://www.humo.be',
    'https://humo.be/registreren',
    'https://myaccount.humo.be',
    'https://mijnomgeving.humo.be',
    'https://accounts.humo.be',
    'https://shop.humo.be',
  ];

  const results = {};

  for (const url of hosts) {
    const label = url.replace('https://', '').replace(/[^a-zA-Z0-9]/g, '_');
    console.log(`\n=== Probing: ${url} ===`);

    try {
      await cdp(ws, 'Page.navigate', { url });

      // Wait for load event (or timeout)
      await new Promise((resolve) => {
        const handler = (evt) => {
          const msg = JSON.parse(evt.data);
          if (msg.method === 'Page.loadEventFired') {
            ws.removeEventListener('message', handler);
            resolve();
          }
        };
        ws.addEventListener('message', handler);
        setTimeout(() => { ws.removeEventListener('message', handler); resolve(); }, 12000);
      });

      await new Promise(r => setTimeout(r, 2000));

      const evalJS = async (expr) => {
        const r = await cdp(ws, 'Runtime.evaluate', { expression: expr, returnByValue: true });
        return r.result.value;
      };

      const finalUrl = await evalJS('window.location.href');
      const title = await evalJS('document.title');
      const csp = await evalJS(`
        (() => {
          const m = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
          return m ? m.content : null;
        })()
      `);

      const formsRaw = await evalJS(`
        JSON.stringify(
          Array.from(document.querySelectorAll('form')).map(f => ({
            action: f.action, method: f.method,
            inputs: Array.from(f.querySelectorAll('input')).map(i => ({
              name: i.name, type: i.type, placeholder: i.placeholder
            }))
          }))
        )
      `);
      const forms = JSON.parse(formsRaw || '[]');

      const oauthRaw = await evalJS(`
        JSON.stringify(
          Array.from(document.querySelectorAll(
            'a[href*="oauth"], a[href*="sso"], a[href*="okta"], a[href*="saml"], ' +
            'a[href*="login"], button[class*="google"], button[class*="microsoft"], button[class*="sso"]'
          )).map(e => ({ tag: e.tagName, text: e.textContent.trim().slice(0,80), href: e.href || '' }))
        )
      `);
      const oauthButtons = JSON.parse(oauthRaw || '[]');

      const scriptsRaw = await evalJS(`
        JSON.stringify(
          Array.from(document.querySelectorAll('script[src]'))
            .map(s => s.src)
            .filter(s => s.includes('humo.be') || s.includes('dpg') || s.includes('assets'))
        )
      `);
      const scripts = JSON.parse(scriptsRaw || '[]');

      const cookies = await evalJS('document.cookie');
      const bodySize = await evalJS('document.body ? document.body.innerHTML.length : 0');

      const gqlHintsRaw = await evalJS(`
        (() => {
          const html = document.documentElement.innerHTML;
          const m = html.match(/graphql|__typename|introspect|apollo/gi);
          return m ? [...new Set(m)] : [];
        })()
      `);
      const gqlHints = Array.isArray(gqlHintsRaw) ? gqlHintsRaw : [];

      const entry = {
        url, finalUrl, title, csp, forms, oauthButtons,
        scripts, cookies, bodySize, gqlHints,
        timestamp: new Date().toISOString()
      };
      results[label] = entry;

      console.log(`  final: ${finalUrl}`);
      console.log(`  title: ${title}`);
      console.log(`  forms: ${forms.length}, oauth: ${oauthButtons.length}`);
      console.log(`  scripts: ${scripts.length}, body: ${bodySize} chars`);
      if (gqlHints.length) console.log(`  GQL hints: ${gqlHints.join(', ')}`);
      forms.forEach((f, i) =>
        console.log(`  form[${i}]: action=${f.action} inputs=${f.inputs.map(x=>x.name).join(',')}`)
      );
      oauthButtons.forEach((b, i) =>
        console.log(`  oauth[${i}]: ${b.tag} "${b.text}" -> ${b.href}`)
      );

      // Save HTML
      const html = await evalJS('document.documentElement.outerHTML');
      fs.writeFileSync(path.join(DIR, `${label}.html`), html || '');
      console.log(`  ✓ saved ${label}.html`);

    } catch (e) {
      console.log(`  ✗ ERROR: ${e.message}`);
      results[label] = { error: e.message };
    }

    await new Promise(r => setTimeout(r, 3000));
  }

  fs.writeFileSync(path.join(DIR, 'fingerprint.json'), JSON.stringify(results, null, 2));
  console.log(`\n=== Summary saved to fingerprint.json ===`);

  ws.close();
}

main().catch(e => { console.error(e); process.exit(1); });
