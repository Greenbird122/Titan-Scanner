// dpg_cross_brand2.js — re-test with proper .text() serialization.
// Key question: do brands share the same userId database?
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
    { name: 'Humo (control)', host: 'www.humo.be' },
  ];

  const results = {};

  for (const brand of brands) {
    console.log(`\n=== ${brand.name} (${brand.host}) ===`);

    try {
      // Navigate
      await cdp(ws, 'Page.navigate', { url: `https://${brand.host}` });
      await new Promise(r => setTimeout(r, 6000));

      const title = await cdp(ws, 'Runtime.evaluate', {
        expression: 'document.title', returnByValue: true
      });
      console.log(`  title: ${title.result.value}`);

      // Accept privacy gate if present
      const accepted = await cdp(ws, 'Runtime.evaluate', {
        expression: `
          (() => {
            const btn = document.querySelector('[data-testid="accept-all"], button[class*="accept"], .privacy-gate button, #didomi-notice-agree-button');
            if (btn) { btn.click(); return 'accepted'; }
            return 'no gate';
          })()
        `, returnByValue: true
      });
      console.log(`  privacy gate: ${accepted.result.value}`);
      await new Promise(r => setTimeout(r, 2000));

      // Test bookmarks — properly await and .text()
      for (const userId of [1, 2, 3]) {
        const result = await cdp(ws, 'Runtime.evaluate', {
          expression: `(async () => {
            try {
              const r = await fetch('https://${brand.host}/api/_next-api/bookmarks?userId=${userId}');
              const text = await r.text();
              return r.status + ' | ' + text.slice(0, 300);
            } catch(e) {
              return 'fetch error: ' + e.message;
            }
          })()`,
          awaitPromise: true, returnByValue: true
        });
        console.log(`  userId=${userId}: ${result.result.value}`);
      }

      // Check build manifest
      const manifest = await cdp(ws, 'Runtime.evaluate', {
        expression: `(async () => {
          try {
            // Try to find the build ID from the page
            const scripts = Array.from(document.querySelectorAll('script[src*="_next"]'));
            if (scripts.length > 0) {
              const match = scripts[0].src.match(/_next\\/static\\/([a-f0-9]+)/);
              if (match) {
                const buildId = match[1];
                const r = await fetch('https://${brand.host}/_next/static/' + buildId + '/_buildManifest.js');
                return 'buildId=' + buildId + ' | ' + (await r.text()).slice(0, 500);
              }
            }
            return 'no _next scripts found';
          } catch(e) { return 'error: ' + e.message; }
        })()`,
        awaitPromise: true, returnByValue: true
      });
      console.log(`  manifest: ${(manifest.result.value || '').slice(0, 200)}`);

      results[brand.name] = {
        host: brand.host,
        title: title.result.value,
        privacyGate: accepted.result.value,
        manifest: (manifest.result.value || '').slice(0, 200),
      };

    } catch (e) {
      console.log(`  ERROR: ${e.message}`);
      results[brand.name] = { error: e.message };
    }

    await new Promise(r => setTimeout(r, 3000));
  }

  // Cross-brand comparison: check if userId=1 has the same bookmarks on all brands
  console.log('\n=== CROSS-BRAND COMPARISON ===');
  console.log('If userId=1 returns the same contentId across brands, they share a backend.');

  fs.writeFileSync('findings/bounties/humo-h1/cross_brand_results2.json', JSON.stringify(results, null, 2));
  console.log('\n=== Results saved ===');

  ws.close();
}

main().catch(e => { console.error(e); process.exit(1); });
