// humo_sweep3.js — remaining tests without RSC (which hangs).
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
    const t = setTimeout(() => j(new Error('timeout')), 12000);
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

  // 1. CORS
  console.log('=== CORS ===');
  var cors = await evalAsync(
    'var r = await fetch("https://www.humo.be/api/_next-api/bookmarks?userId=1", {mode:"cors"});' +
    'return JSON.stringify({origin:r.headers.get("access-control-allow-origin"),methods:r.headers.get("access-control-allow-methods"),creds:r.headers.get("access-control-allow-credentials")});'
  );
  console.log('  ' + cors); results.cors = cors;

  // 2. postMessage
  console.log('\n=== postMessage ===');
  var pm = await evalAsync(
    'var h=document.documentElement.outerHTML;var r=[];' +
    'r.push((h.match(/addEventListener\\s*\\(\\s*["\']message["\']/g)||[]).length+" listeners");' +
    'r.push((h.match(/onmessage/g)||[]).length+" onmessage");' +
    'r.push((h.match(/postMessage/g)||[]).length+" calls");return r.join("; ");'
  );
  console.log('  ' + pm); results.postmessage = pm;

  // 3. Service Worker
  console.log('\n=== Service Worker ===');
  var sw = await evalAsync(
    'if(!navigator.serviceWorker)return "not supported";' +
    'var regs=await navigator.serviceWorker.getRegistrations();' +
    'if(!regs.length)return "none";return regs.map(r=>r.scope).join("; ");'
  );
  console.log('  ' + sw); results.sw = sw;

  // 4. Rate limit
  console.log('\n=== Rate limit (5 rapid) ===');
  var rl = [];
  for (var k = 0; k < 5; k++) {
    var rr = await evalAsync('var r=await fetch("https://www.humo.be/api/_next-api/bookmarks?userId='+(k+1)+'");return r.status;');
    rl.push(rr);
  }
  console.log('  ' + rl.join(', ')); results.rl = rl.join(',');

  // 5. Error pages
  console.log('\n=== Error pages ===');
  var errTests = ['/nonexistent-xyz-12345', '/api/_next-api/bookmarks?userId=../../etc/passwd'];
  for (var e = 0; e < errTests.length; e++) {
    var er = await evalAsync(
      'var r=await fetch("https://www.humo.be'+errTests[e]+'");var t=(await r.text()).slice(0,200);return r.status+" | "+t.replace(/\\n/g," ").slice(0,120);'
    );
    console.log('  ' + errTests[e] + ': ' + er); results['err'+e] = er;
  }

  // 6. .env via browser
  console.log('\n=== .env ===');
  var env = await evalAsync(
    'var r=await fetch("https://www.humo.be/.env");return r.status+" | "+(await r.text()).slice(0,300).replace(/\\n/g," ");'
  );
  console.log('  ' + env); results.env = env;

  // 7. Case-insensitive bypass deep
  console.log('\n=== Case bypass ===');
  var caseTests = ['/API/_NEXT-API/BOOKMARKS?userId=1', '/Api/_Next-Api/Bookmarks?userId=1'];
  for (var c = 0; c < caseTests.length; c++) {
    var cr = await evalAsync(
      'var r=await fetch("https://www.humo.be'+caseTests[c]+'");return r.status+" | "+(await r.text()).slice(0,100);'
    );
    console.log('  ' + caseTests[c] + ': ' + cr); results['case'+c] = cr;
  }

  // 8. Check for __NEXT_DATA__ after fresh load
  console.log('\n=== __NEXT_DATA__ ===');
  var nd = await evalAsync(
    'var el=document.getElementById("__NEXT_DATA__");if(el)return el.textContent.slice(0,1000);return "not found";'
  );
  console.log('  ' + nd.slice(0, 200)); results.nextData = nd.slice(0, 200);

  // 9. robots.txt disallowed paths
  console.log('\n=== robots.txt hidden paths ===');
  var robots = await evalAsync(
    'var r=await fetch("https://www.humo.be/robots.txt");return (await r.text()).slice(0,500);'
  );
  console.log('  ' + robots.replace(/\n/g, '\n  ')); results.robots = robots;

  // 10. Check for GraphQL (from Parool F4 pattern)
  console.log('\n=== GraphQL probe ===');
  var gql = await evalAsync(
    'var r=await fetch("https://www.humo.be/graphql",{method:"POST",headers:{"Content-Type":"application/json"},' +
    'body:JSON.stringify({query:"{__schema{types{name}}}"})});return r.status+" | "+(await r.text()).slice(0,200);'
  );
  console.log('  ' + gql); results.gql = gql;

  fs.writeFileSync(path.join(DIR, 'deep_sweep3_results.json'), JSON.stringify(results, null, 2));
  console.log('\n=== All saved ===');
  ws.close();
}

main().catch(function(e) { console.error(e); process.exit(1); });
