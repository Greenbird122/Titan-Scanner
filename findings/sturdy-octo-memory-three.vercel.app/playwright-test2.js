const { chromium } = require('playwright');

(async () => {
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    
    // Set realistic browser fingerprint
    await page.setExtraHTTPHeaders({
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
    });
    
    try {
        await page.goto('https://sturdy-octo-memory-three.vercel.app');
        await page.waitForTimeout(2000);
        
        const title = await page.title();
        console.log("Page title:", title);
        
        // Try to fetch session
        const session = await page.evaluate(async () => {
            const res = await fetch('/api/auth/session');
            return { status: res.status, body: await res.text() };
        });
        console.log("Session:", JSON.stringify(session));
        
    } catch (e) {
        console.log("Error:", e.message);
    }
    
    await browser.close();
})();
