// humo_final_pass3.js — simplified, no sitemap (WAF rate limit).
// Direct article URLs from build manifest patterns + remaining angles.
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

  // 1. Navigate to magazine section (known path from build manifest)
  console.log('=== 1. Article page XSS ===');
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be/magazine' });
  await new Promise(r => setTimeout(r, 6000));
  var title = await evalAsync('return document.title;');
  console.log('  title: ' + title);

  var xss = await evalAsync(
    'var html=document.documentElement.outerHTML;' +
    'var r=[];' +
    'r.push("innerHTML:"+((html.match(/\\.innerHTML/g)||[]).length));' +
    'r.push("eval:"+((html.match(/[^a-z]eval\\(/gi)||[]).length));' +
    'r.push("dangerouslySet:"+((html.match(/dangerouslySetInnerHTML/g)||[]).length));' +
    'r.push("body:"+document.body.innerHTML.length);' +
    'return r.join(", ");'
  );
  console.log('  sinks: ' + xss);
  results.magazine_xss = xss;

  // 2. Check meta tag content injection
  var meta = await evalAsync(
    'var r=[];' +
    'var tags=document.querySelectorAll("meta[property],meta[name]");' +
    'tags.forEach(function(m){' +
    '  var v=m.getAttribute("content")||"";' +
    '  if(v.length>5&&v.length<300)r.push((m.getAttribute("property")||m.getAttribute("name"))+"="+v.slice(0,60));' +
    '});' +
    'return r.slice(0,6).join("\\n");'
  );
  console.log('  meta:\n    ' + meta);
  results.magazine_meta = meta;

  // 3. Cache headers
  console.log('\n=== 2. Cache headers ===');
  await new Promise(r => setTimeout(r, 3000));
  var ch = await evalAsync(
    'var r=await fetch("https://www.humo.be/api/_next-api/bookmarks?userId=1");' +
    'var h={};["cache-control","etag","last-modified","x-nextjs-cache","vary","age"].forEach(function(k){h[k]=r.headers.get(k);});' +
    'return JSON.stringify(h);'
  );
  console.log('  ' + ch);
  results.cache_headers = ch;

  // 4. _data parameter
  console.log('\n=== 3. _data parameter ===');
  await new Promise(r => setTimeout(r, 2000));
  var dt = await evalAsync(
    'var r=await fetch("https://www.humo.be/api/_next-api/bookmarks?userId=1&_data=/api/_next-api/bookmarks");' +
    'return r.status+" | ct="+r.headers.get("content-type")+" | "+(await r.text()).slice(0,150);'
  );
  console.log('  ' + dt);
  results.data_param = dt;

  // 5. Chunk analysis
  console.log('\n=== 4. Chunk analysis ===');
  await new Promise(r => setTimeout(r, 2000));
  var chunks = await evalAsync(
    'var s=Array.from(document.querySelectorAll("script[src*=\\"chunk\\"]"));' +
    'return s.map(function(x){return x.src;}).slice(0,2).join("\\n");'
  );
  if (chunks) {
    var first = chunks.split('\n')[0];
    var ca = await evalAsync(
      'var r=await fetch("' + first + '");var t=await r.text();' +
      'var f=[];f.push("sz:"+t.length);' +
      'f.push("ih:"+((t.match(/innerHTML/g)||[]).length));' +
      'f.push("fetch:"+((t.match(/fetch\\(/g)||[]).length));' +
      'f.push("ls:"+((t.match(/localStorage/g)||[]).length));' +
      'if(t.match(/graphql/i))f.push("GQL");' +
      'if(t.match(/apiKey|api_key/i))f.push("APIKEY");' +
      'return f.join(",");'
    );
    console.log('  ' + first.split('/').pop().split('?')[0] + ': ' + ca);
    results.chunk = ca;
  }

  // 6. Check for open redirect via known DPG tracking params
  console.log('\n=== 5. Open redirect via tracking ===');
  await new Promise(r => setTimeout(r, 2000));
  var redir = await evalAsync(
    'var r=await fetch("https://www.humo.be/?redirectUri=https://example.com",{redirect:"manual"});' +
    'return r.status+" | location="+r.headers.get("location");'
  );
  console.log('  redirectUri: ' + redir);
  results.open_redirect = redir;

  // 7. Check for verbose error on GraphQL
  console.log('\n=== 6. GraphQL verbose error ===');
  await new Promise(r => setTimeout(r, 2000));
  var gqlErr = await evalAsync(
    'var r=await fetch("https://www.humo.be/graphql",{method:"POST",headers:{"Content-Type":"application/json"},' +
    'body:JSON.stringify({query:"{nonexistent}"})});' +
    'return r.status+" | "+(await r.text()).slice(0,300);'
  );
  console.log('  ' + gqlErr);
  results.gql_error = gqlErr;

  fs.writeFileSync(path.join(DIR, 'final_pass3_results.json'), JSON.stringify(results, null, 2));
  console.log('\n=== Saved ===');
  ws.close();
}

main().catch(function(e) { console.error(e); process.exit(1); });
