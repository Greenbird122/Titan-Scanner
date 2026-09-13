// varonis_route_probe.js — navigate unauth handler routes via CDP,
// with X-Bug-Bounty header set at network level (policy compliance).
// Captures: final URL, redirects, API calls fired, console errors.
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
  await send('Runtime.enable');
  await send('Page.enable');

  // Identify all browser traffic per policy
  await send('Network.setExtraHTTPHeaders', {
    headers: { 'X-Bug-Bounty': 'HackerOne-Greenbird122' },
  });

  const apiCalls = [];
  const consoleErrs = [];
  const redirects = [];
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.method === 'Network.requestWillBeSent') {
      const u = m.params.request.url;
      if (/api\.app\.varonis\.io/.test(u)) apiCalls.push(m.params.request.method + ' ' + u.slice(0, 130));
      if (m.params.redirectResponse) redirects.push(u.slice(0, 130));
    }
    if (m.method === 'Runtime.exceptionThrown') {
      consoleErrs.push((m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text).slice(0, 200));
    }
  });

  // Benign marker params — no real code values, no state forgery beyond markers
  const routes = [
    '/postauth?code=h1marker&state=h1marker',
    '/postauth?error=access_denied&error_description=h1marker',
    '/snowflake/oauth-landing?code=h1marker&state=h1marker',
    '/gatekeeper',
    '/download/report?id=00000000-0000-0000-0000-000000000000',
  ];

  const results = [];
  for (const r of routes) {
    apiCalls.length = 0; redirects.length = 0; consoleErrs.length = 0;
    await send('Page.navigate', { url: 'https://app.varonis.io' + r });
    await sleep(9000);
    const loc = await send('Runtime.evaluate', { expression: 'location.href', returnByValue: true });
    const line = {
      route: r,
      finalUrl: loc.result?.result?.value || '?',
      apiCalls: [...new Set(apiCalls)],
      redirects: [...new Set(redirects)],
      consoleErrs: [...new Set(consoleErrs)].slice(0, 4),
    };
    results.push(line);
    console.log('\n=== ' + r);
    console.log('final: ' + line.finalUrl);
    if (line.apiCalls.length) console.log('api:   ' + line.apiCalls.join(' | '));
    if (line.redirects.length) console.log('redir: ' + line.redirects.join(' | '));
    if (line.consoleErrs.length) console.log('err:   ' + line.consoleErrs.join(' | '));
    await sleep(2500);
  }

  fs.writeFileSync(
    require('path').join(__dirname, '..', 'findings', 'bounties', 'varonis-h1', 'route_probe_results.json'),
    JSON.stringify(results, null, 2)
  );
  console.log('\nsaved -> findings/bounties/varonis-h1/route_probe_results.json');
  process.exit(0);
})().catch((e) => { console.error('ERR', e.message); process.exit(1); });
