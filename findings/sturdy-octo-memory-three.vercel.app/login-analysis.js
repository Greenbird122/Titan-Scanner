const { chromium } = require('playwright');

(async () => {
    console.log("=== Login Mechanism Analysis ===");
    
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    
    // Monitor network requests
    const requests = [];
    page.on('request', req => {
        requests.push({ url: req.url(), method: req.method(), postData: req.postData() });
    });
    
    // Monitor responses
    const responses = [];
    page.on('response', res => {
        responses.push({ url: res.url(), status: res.status() });
    });
    
    // Navigate to target
    await page.goto('https://sturdy-octo-memory-three.vercel.app/login');
    await page.waitForTimeout(2000);
    
    // Analyze the form
    console.log("\nAnalyzing login form...");
    const formInfo = await page.evaluate(() => {
        const form = document.querySelector('form');
        if (!form) return null;
        
        return {
            action: form.action,
            method: form.method,
            enctype: form.enctype,
            inputs: [...form.querySelectorAll('input')].map(i => ({
                type: i.type,
                name: i.name,
                value: i.value,
                id: i.id
            })),
            buttons: [...form.querySelectorAll('button')].map(b => ({
                type: b.type,
                text: b.textContent
            }))
        };
    });
    console.log("Form info:", JSON.stringify(formInfo, null, 2));
    
    // Try different password and monitor what happens
    console.log("\nTrying password and monitoring network...");
    requests.length = 0;
    responses.length = 0;
    
    await page.fill('input', 'testpassword');
    await page.click('button[type=submit]');
    await page.waitForTimeout(3000);
    
    console.log("\nRequests made:");
    requests.forEach(r => console.log(`  ${r.method} ${r.url} ${r.postData || ''}`));
    
    console.log("\nResponses received:");
    responses.forEach(r => console.log(`  ${r.status} ${r.url}`));
    
    // Check final URL
    console.log("\nFinal URL:", page.url());
    
    // Check page content
    const pageText = await page.evaluate(() => document.body.innerText.substring(0, 500));
    console.log("Page text:", pageText);
    
    // Check cookies
    const cookies = await context.cookies();
    console.log("\nCookies:", cookies.map(c => `${c.name}=${c.value}`));
    
    await browser.close();
    
    console.log("\n=== Analysis Complete ===");
})();
