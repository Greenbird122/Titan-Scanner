// humo_final_pass.js — deep-dive on the most promising remaining leads.
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

  // ===== 1. Get real article URLs from sitemap =====
  console.log('=== 1. Real article URLs from sitemap ===');
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be' });
  await new Promise(r => setTimeout(r, 5000));

  var articleUrls = await evalAsync(
    'var r=await fetch("https://www.humo.be/sitemap.xml");var t=await r.text();' +
    'var matches=t.match(/<loc>(https:\\/\\/www\\.humo\\.be\\/[^<]+)<\\/loc>/g);' +
    'if(!matches)return "none";' +
    'return matches.slice(0,5).map(function(m){return m.replace(/<\\/?>/g,"");}).join("\\n");'
  );
  console.log(articleUrls);
  var urls = (articleUrls || '').split('\n').filter(function(u) { return u.length > 10; });

  // ===== 2. Navigate to a real article and check for XSS sinks =====
  if (urls.length > 0) {
    console.log('\n=== 2. Article XSS ===');
    var articleUrl = urls[0];
    // Skip sitemap/dossier URLs, find a real article
    for (var u = 0; u < urls.length; u++) {
      if (urls[u].includes('~b') || urls[u].match(/\/[^\/]+-b[0-9]/)) {
        articleUrl = urls[u];
        break;
      }
    }
    console.log('  testing: ' + articleUrl.slice(0, 80));
    await cdp(ws, 'Page.navigate', { url: articleUrl });
    await new Promise(r => setTimeout(r, 6000));

    var xssSinks = await evalAsync(
      'var r=[];' +
      'var html=document.documentElement.outerHTML;' +
      'r.push("innerHTML:"+(html.match(/\\.innerHTML/g)||[]).length);' +
      'r.push("outerHTML:"+(html.match(/\\.outerHTML/g)||[]).length);' +
      'r.push("document.write:"+(html.match(/document\\.write/g)||[]).length);' +
      'r.push("eval:"+(html.match(/[^a-z]eval\\(/gi)||[]).length);' +
      'r.push("setTimeout(string:"+(html.match(/setTimeout\\s*\\(\\s*["\']/g)||[]).length);' +
      'r.push("setInterval(string:"+(html.match(/setInterval\\s*\\(\\s*["\']/g)||[]).length);' +
      'r.push("Function:"+(html.match(/new\\s+Function/g)||[]).length);' +
      'r.push("dangerouslySetInnerHTML:"+(html.match(/dangerouslySetInnerHTML/g)||[]).length);' +
      'r.push("script src:"+(html.match(/<script[^>]+src/gi)||[]).length);' +
      'var title=document.title;' +
      'r.push("title:"+title.slice(0,50));' +
      'r.push("body size:"+document.body.innerHTML.length);' +
      'return r.join(", ");'
    );
    console.log('  sinks: ' + xssSinks);
    results.article_xss = xssSinks;

    // Check if URL params are reflected in the article page
    var paramReflect = await evalAsync(
      'var r=[];' +
      'r.push("url:"+window.location.href.slice(0,80));' +
      'r.push("hash:"+window.location.hash);' +
      'return r.join("; ");'
    );
    console.log('  ' + paramReflect);
  }

  // ===== 3. _data parameter deep test =====
  console.log('\n=== 3. _data parameter ===');
  var dataTests = [
    '/api/_next-api/bookmarks?userId=1&_data=root',
    '/api/_next-api/bookmarks?userId=1&_data=/api/_next-api/bookmarks',
    '/api/_next-api/bookmarks?userId=1&_data=/api/bookmarks',
    '/api/_next-api/bookmarks?userId=1&_data=/api/_next-api/v1/auth/login',
    '/?_data=/api/_next-api/bookmarks&userId=1',
  ];
  for (var d = 0; d < dataTests.length; d++) {
    var dr = await evalAsync(
      'var r=await fetch("https://www.humo.be' + dataTests[d] + '");' +
      'return r.status+" | ct="+r.headers.get("content-type")+" | "+(await r.text()).slice(0,150);'
    );
    console.log('  ' + dataTests[d] + ': ' + dr);
    results['data_' + d] = dr;
    await new Promise(r => setTimeout(r, 2000));
  }

  // ===== 4. Cache headers analysis =====
  console.log('\n=== 4. Cache headers on bookmarks ===');
  var cacheHeaders = await evalAsync(
    'var r=await fetch("https://www.humo.be/api/_next-api/bookmarks?userId=1");' +
    'var h={};' +
    '["cache-control","etag","last-modified","x-nextjs-cache","vary","age","x-cache"].forEach(function(k){' +
    '  h[k]=r.headers.get(k);' +
    '});' +
    'return JSON.stringify(h);'
  );
  console.log('  ' + cacheHeaders);
  results.cache_headers = cacheHeaders;
  await new Promise(r => setTimeout(r, 2000));

  // ===== 5. Check for cache on other user IDs =====
  console.log('\n=== 5. Cache differentiation ===');
  var cd1 = await evalAsync(
    'var r=await fetch("https://www.humo.be/api/_next-api/bookmarks?userId=999");' +
    'var etag=r.headers.get("etag");var cc=r.headers.get("cache-control");' +
    'return r.status+" | etag="+etag+" | cc="+cc+" | "+(await r.text()).slice(0,100);'
  );
  console.log('  userId=999: ' + cd1);
  results.cache_diff = cd1;
  await new Promise(r => setTimeout(r, 2000));

  // ===== 6. Download and analyze a JS chunk =====
  console.log('\n=== 6. JS chunk analysis ===');
  var chunkInfo = await evalAsync(
    'var scripts=Array.from(document.querySelectorAll("script[src*=\\"_next\\"]"));' +
    'var urls=scripts.map(function(s){return s.src;}).filter(function(s){return s.includes("chunk");});' +
    'if(!urls.length)return "no chunks";' +
    'return urls.slice(0,3).join("\\n");'
  );
  console.log('  chunks: ' + (chunkInfo || '').split('\n').length);

  // Download first chunk and analyze
  if (chunkInfo && chunkInfo !== 'no chunks') {
    var firstChunk = chunkInfo.split('\n')[0];
    var chunkAnalysis = await evalAsync(
      'var r=await fetch("' + firstChunk + '");' +
      'var t=await r.text();' +
      'var findings=[];' +
      'if(t.match(/api[_-]?key|apiKey|API_KEY/i))findings.push("API_KEY");' +
      'if(t.match(/secret|SECRET/i))findings.push("SECRET");' +
      'if(t.match(/graphql|GRAPHQL/i))findings.push("GRAPHQL");' +
      'if(t.match(/innerHTML/gi))findings.push("INNERHTML:"+((t.match(/innerHTML/g)||[]).length));' +
      'if(t.match(/localStorage/gi))findings.push("LOCALSTORAGE:"+((t.match(/localStorage/g)||[]).length));' +
      'if(t.match(/sessionStorage/gi))findings.push("SESSIONSTORAGE:"+((t.match(/sessionStorage/g)||[]).length));' +
      'if(t.match(/fetch\\(/gi))findings.push("FETCH:"+((t.match(/fetch\\(/g)||[]).length));' +
      'if(t.match(/\\b(POST|PUT|DELETE)\\b/gi))findings.push("HTTP_METHODS");' +
      'return "size:"+t.length+" | "+(findings.length?findings.join(","):"clean");'
    );
    console.log('  ' + firstChunk.split('/').pop() + ': ' + chunkAnalysis);
    results.chunk_analysis = chunkAnalysis;
  }

  fs.writeFileSync(path.join(DIR, 'final_pass_results.json'), JSON.stringify(results, null, 2));
  console.log('\n=== All saved ===');
  ws.close();
}

main().catch(function(e) { console.error(e); process.exit(1); });
