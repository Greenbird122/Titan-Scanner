// varonis_exchange_probe.js — capture the POST /api/v2/login/code request
// body + response status/body when the snowflake oauth-landing route
// consumes a marker code (unauthenticated, browser context, identified).
const http = require('http');
const fs = require('fs');

function getJSON(path) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: 9222, path }, (r) => {
      let d = '';
      r.on('data', (c) => (d += c));
      r.on('end', () => resolve(JSON.parse(d)));
    }).on('error', reject);
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const tabs = await getJSON('/json');
  let t = tabs.find((x) => x.type === 'page' && /app\.varonis\.io/.test(x.url));
  if (!t) { console.error('NO app.varonis.io TAB'); process.exit(1); }
  const ws = new WebSocket(t.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener('open', r, { once: true }));
  let id = 0;
  const pending = new Map();
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  });
  const send = (method, params = {}) =>
    new Promise((resolve) => { const i = ++id; pending.set(i, resolve); ws.send(JSON.stringify({ id: i, method, params })); });

  await send('Network.enable');
  await send('Network.setExtraHTTPHeaders', { headers: { 'X-Bug-Bounty': 'HackerOne-Greenbird122' } });

  const exchange = { request: null, response: null };
  ws.addEventListener('message', async (ev) => {
    const m = JSON.parse(ev.data);
    if (m.method === 'Network.requestWillBeSent' && /login\/code/.test(m.params.request.url) && m.params.request.method === 'POST') {
      exchange.request = {
        url: m.params.request.url,
        postData: m.params.request.postData,
        headers: m.params.request.headers,
      };
    }
    if (m.method === 'Network.responseReceived' && /login\/code/.test(m.params.response.url)) {
      const rid = m.params.requestId;
      try {
        const body = await send('Network.getResponseBody', { requestId: rid });
        exchange.response = { status: m.params.response.status, body: (body.body || '').slice(0, 900) };
      } catch (e) {
        exchange.response = { status: m.params.response.status, body: '(body unavailable: ' + e.message + ')' };
      }
    }
  });

  await send('Page.enable');
  await send('Page.navigate', { url: 'https://app.varonis.io/snowflake/oauth-landing?code=h1marker&state=h1marker' });
  await sleep(12000);

  const out = JSON.stringify(exchange, null, 2);
  console.log(out);
  fs.writeFileSync(
    require('path').join(__dirname, '..', 'findings', 'bounties', 'varonis-h1', 'login_code_exchange.json'),
    out
  );
  console.log('\nsaved -> findings/bounties/varonis-h1/login_code_exchange.json');
  process.exit(0);
})().catch((e) => { console.error('ERR', e.message); process.exit(1); });
