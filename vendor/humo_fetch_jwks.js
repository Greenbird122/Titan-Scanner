// humo_fetch_jwks.js — fetch JWKS via CDP browser (has WAF cookies)
const http = require('http');
const fs = require('fs');

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

  // 1. JWKS
  console.log('=== Fetching JWKS via browser ===');
  await cdp(ws, 'Page.navigate', { url: 'https://login.dpgmedia.be/.well-known/jwks' });
  await new Promise(r => setTimeout(r, 5000));
  const jwks = await cdp(ws, 'Runtime.evaluate', { expression: 'document.body.innerText', returnByValue: true });
  const jwksText = jwks.result.value || '';
  console.log(jwksText.slice(0, 2000));
  fs.writeFileSync('findings/bounties/humo-h1/dpg_jwks.json', jwksText);

  // 2. Full OIDC config
  console.log('\n=== Fetching full OIDC config via browser ===');
  await cdp(ws, 'Page.navigate', { url: 'https://login.dpgmedia.be/.well-known/openid-configuration' });
  await new Promise(r => setTimeout(r, 5000));
  const cfg = await cdp(ws, 'Runtime.evaluate', { expression: 'document.body.innerText', returnByValue: true });
  const cfgText = cfg.result.value || '';
  fs.writeFileSync('findings/bounties/humo-h1/dpg_oidc_full.json', cfgText);
  console.log(`Config length: ${cfgText.length} chars`);

  // Parse and show key details
  try {
    const parsed = JSON.parse(cfgText);
    console.log(`\nissuer: ${parsed.issuer}`);
    console.log(`scopes: ${parsed.scopes_supported}`);
    console.log(`grant_types: ${parsed.grant_types_supported}`);
    console.log(`response_types: ${parsed.response_types_supported}`);
    console.log(`userinfo_signing: ${parsed.userinfo_signing_alg_values_supported}`);
    console.log(`id_token_signing: ${parsed.id_token_signing_alg_values_supported}`);
    console.log(`claims_supported: ${parsed.claims_supported}`);
    console.log(`token_endpoint_auth: ${parsed.token_endpoint_auth_methods_supported}`);
  } catch (e) {
    console.log('Parse error:', e.message);
  }

  // 3. Try authorization endpoint with implicit flow (marker)
  console.log('\n=== Authorization endpoint test ===');
  await cdp(ws, 'Page.navigate', {
    url: 'https://login.dpgmedia.be/authorize?client_id=humo-selectives-web&response_type=token&scope=openid&redirect_uri=https://example.com&state=test123'
  });
  await new Promise(r => setTimeout(r, 5000));
  const authUrl = await cdp(ws, 'Runtime.evaluate', { expression: 'window.location.href', returnByValue: true });
  const authTitle = await cdp(ws, 'Runtime.evaluate', { expression: 'document.title', returnByValue: true });
  console.log(`  URL: ${authUrl.result.value}`);
  console.log(`  title: ${authTitle.result.value}`);

  ws.close();
}

main().catch(e => { console.error(e); process.exit(1); });
