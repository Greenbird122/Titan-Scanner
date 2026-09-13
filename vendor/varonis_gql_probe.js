// varonis_gql_probe.js — in-page GraphQL probes via debug Chrome (CDP).
// Test A: with X-Bug-Bounty header (custom header -> preflight check)
// Test B: exact SPA request shape (Content-Type only)
// Paced, minimal, evidence to stdout + file.
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

(async () => {
  const tabs = await getJSON('/json');
  let t = tabs.find((x) => x.type === 'page' && /app\.varonis\.io/.test(x.url));
  if (!t) {
    console.error('NO app.varonis.io TAB — open it in the debug Chrome first');
    process.exit(1);
  }
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

  const query = 'query GetPossibleTypes { __schema { types { kind name possibleTypes { name } } } }';
  const body = JSON.stringify({ operationName: 'GetPossibleTypes', query });

  const mkFetch = (withHeader) => {
    const headers = withHeader
      ? "{'Content-Type':'application/json','X-Bug-Bounty':'HackerOne-Greenbird122'}"
      : "{'Content-Type':'application/json'}";
    return `fetch('https://api.app.varonis.io/api/graphql',{method:'POST',headers:${headers},body:${JSON.stringify(body)}})
      .then(async r => { let b=''; try { b = await r.text(); } catch(e) { b='(body read fail)'; }
        return 'STATUS ' + r.status + ' CT ' + (r.headers.get('content-type')||'-') + ' :: ' + b.slice(0,600); })
      .catch(e => 'FETCH-FAIL ' + e.message);`;
  };

  const out = [];
  for (const [label, withHeader] of [['A (with H1 header)', true], ['B (SPA shape)', false]]) {
    const res = await send('Runtime.evaluate', {
      expression: mkFetch(withHeader), awaitPromise: true, returnByValue: true,
    });
    const val = res.result && res.result.result ? res.result.result.value : JSON.stringify(res);
    const line = `TEST ${label}: ${val}`;
    console.log(line);
    out.push(line);
    await new Promise((r) => setTimeout(r, 3000));
  }

  fs.writeFileSync(__dirname + '/../findings/bounties/varonis-h1/gql_probe_result.txt', out.join('\n\n'));
  console.log('saved -> findings/bounties/varonis-h1/gql_probe_result.txt');
  process.exit(0);
})().catch((e) => { console.error('ERR', e.message); process.exit(1); });
