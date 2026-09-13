// humo_final_pass2.js — fixed sitemap parsing and remaining angles.
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

  // 1. Get actual article URLs from monthly sitemap
  console.log('=== 1. Real articles ===');
  var articles = await evalAsync(
    'var r=await fetch("https://www.humo.be/sitemaps/202609.xml");var t=await r.text();' +
    'var matches=t.match(/<loc>([^<]+)<\\/loc>/g);' +
    'if(!matches)return "none";' +
    'return matches.slice(0,5).map(function(m){return m.replace(/<loc>|<\\/loc>/g,"");}).join("\\n");'
  );
  console.log(articles);
  var articleList = (articles || '').split('\n').filter(function(u) { return u.startsWith('http'); });

  // 2. Navigate to a real article
  if (articleList.length > 0) {
    var testArticle = articleList[0];
    console.log('\n=== 2. Article XSS: ' + testArticle.slice(0, 60) + ' ===');
    await cdp(ws, 'Page.navigate', { url: testArticle });
    await new Promise(r => setTimeout(r, 6000));

    var title = await evalAsync('return document.title;');
    console.log('  title: ' + title);

    var xssSinks = await evalAsync(
      'var html=document.documentElement.outerHTML;' +
      'var r=[];' +
      'r.push("innerHTML:"+(html.match(/\\.innerHTML/g)||[]).length);' +
      'r.push("eval:"+(html.match(/[^a-z]eval\\(/gi)||[]).length);' +
      'r.push("document.write:"+(html.match(/document\\.write/g)||[]).length);' +
      'r.push("dangerouslySet:"+(html.match(/dangerouslySetInnerHTML/g)||[]).length);' +
      'r.push("script tags:"+(html.match(/<script/gi)||[]).length);' +
      'r.push("size:"+document.body.innerHTML.length);' +
      'return r.join(", ");'
    );
    console.log('  sinks: ' + xssSinks);
    results.article_xss = xssSinks;

    // Check if article content is reflected in meta tags (common DOM XSS pattern)
    var metaReflect = await evalAsync(
      'var r=[];' +
      'var metas=document.querySelectorAll("meta[property],meta[name]");' +
      'metas.forEach(function(m){' +
      '  var v=m.getAttribute("content")||"";' +
      '  if(v.length>0&&v.length<200)r.push(m.getAttribute("property")||m.getAttribute("name")+":"+v.slice(0,60));' +
      '});' +
      'return r.slice(0,8).join("\\n");'
    );
    console.log('  meta tags:\n    ' + metaReflect.replace(/\n/g, '\n    '));
    results.article_meta = metaReflect;
  }

  // 3. _data parameter abuse
  console.log('\n=== 3. _data parameter ===');
  await cdp(ws, 'Page.navigate', { url: 'https://www.humo.be' });
  await new Promise(r => setTimeout(r, 4000));

  var dataTests = [
    '/api/_next-api/bookmarks?userId=1&_data=root',
    '/api/_next-api/bookmarks?userId=1&_data=/api/_next-api/bookmarks',
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

  // 4. Cache headers
  console.log('\n=== 4. Cache headers ===');
  var ch = await evalAsync(
    'var r=await fetch("https://www.humo.be/api/_next-api/bookmarks?userId=1");' +
    'var h={};["cache-control","etag","last-modified","x-nextjs-cache","vary","age","x-cache"].forEach(function(k){h[k]=r.headers.get(k);});' +
    'return JSON.stringify(h);'
  );
  console.log('  ' + ch);
  results.cache_headers = ch;
  await new Promise(r => setTimeout(r, 2000));

  // 5. Chunk analysis
  console.log('\n=== 5. Chunk analysis ===');
  var chunkInfo = await evalAsync(
    'var scripts=Array.from(document.querySelectorAll("script[src*=\\"_next\\"]"));' +
    'return scripts.map(function(s){return s.src;}).filter(function(s){return s.includes("chunk");}).slice(0,3).join("\\n");'
  );
  if (chunkInfo && chunkInfo !== 'no chunks') {
    var firstChunk = chunkInfo.split('\n')[0];
    var ca = await evalAsync(
      'var r=await fetch("' + firstChunk + '");var t=await r.text();' +
      'var f=[];' +
      'if(t.match(/api[_-]?key|apiKey/i))f.push("API_KEY");' +
      'if(t.match(/graphql/i))f.push("GRAPHQL");' +
      'f.push("innerHTML:"+((t.match(/innerHTML/g)||[]).length));' +
      'f.push("fetch:"+((t.match(/fetch\\(/g)||[]).length));' +
      'f.push("localStorage:"+((t.match(/localStorage/g)||[]).length));' +
      'return "size:"+t.length+" | "+f.join(",");'
    );
    console.log('  ' + firstChunk.split('/').pop() + ': ' + ca);
    results.chunk = ca;
  }

  fs.writeFileSync(path.join(DIR, 'final_pass2_results.json'), JSON.stringify(results, null, 2));
  console.log('\n=== Saved ===');
  ws.close();
}

main().catch(function(e) { console.error(e); process.exit(1); });
