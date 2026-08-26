# Titan — Module Deep-Dive (All 36 Detectors, As-Is)

> Compiled 2026-08-24 from a line-by-line read of every detector source under
> `titan/modules/`. Each module runs inside the `TitanEngine` pipeline and emits a
> `Finding` (or, for the cloud/LLM-probe modules, a structured audit dict). The
> cross-cutting truth: **zero parameter whitelisting** (every discovered
> query/body/header/JSON-AST leaf is tested) and **evidence-gated verification**
> (a finding must pass a named oracle or it is demoted/unverified).

## How a module is wired

- **Surface is exhaustively enumerated.** Most detectors iterate `list(params.keys())` with no name skip, walk nested JSON AST leaves, and fuzz high-risk ambient headers (`User-Agent`, `X-Forwarded-For`, `X-Real-IP`, `Referer`, `X-Api-Key`, `Authorization`, …).
- **Baseline-first.** Almost every active module sends a baseline request first (often 3 samples for timing stability), then compares.
- **Oracles (anti-FP):** error-signature diffs, non-echo boolean differentials (`is_echo_differential`), math/nonce confirmation (`{{7*7}}→49`, `TITAN_<nonce>`), statistical timing (`BlindDetector`, samples=3, conf=0.95), OOB via Interactsh, and strict reflection/encoding stripping (`payload_encodings` strips raw/URL/double-URL/HTML-entity forms so a reflected payload can't self-verify).
- **Evidence grading** (`titan/verify/oracles.py` `enforce_evidence`): injection-family findings verified off *reflection alone* are auto-demoted to unverified, severity capped at MEDIUM (fixes the "reflection-verifies storm").
- **Timeouts:** 3000 ms is the default per request; cloud deep-audit and graphql use larger budgets.

---

## Track A — Client-Side & Browser (`titan/modules/clientside/`)

### A1. `csp` — `CSPDetector`
- **What:** Parses the `Content-Security-Policy` header (or `<meta>` fallback) and grades it. No payloads; the policy text is the oracle.
- **Checks:** `unsafe-inline` (HIGH), `unsafe-eval` (MEDIUM), `*` wildcard (HIGH), missing `frame-ancestors` (LOW), missing `object-src` (MEDIUM), missing `base-uri` (LOW), no CSP at all (MEDIUM).
- **Emits:** `CSP_WEAKNESS`, `verified=True`, confidence 0.7–HIGH.

### A2. `domxss` — `DomXSSDetector` (Playwright)
- **What:** Installs JS sink wrappers *before page scripts run* (`add_init_script`) that record every write to `Element.innerHTML/outerHTML`, `document.write/writeln`, `window.eval/Function`, `setTimeout(string)`. Injects a unique `titanmx…` marker as a query param.
- **Oracle:** marker appears in a hooked dangerous sink **and** not inert. One verified DOM-XSS per page.
- **Emits:** `DOM_XSS`, CRITICAL, `verified=True`, conf 0.9.

### A3. `postmessage` — `PostMessageDetector` (Playwright)
- **What:** Wraps `EventTarget.addEventListener`, captures every `message` handler source, and dispatches a `MessageEvent` from `https://attacker-controlled.example` to see if any handler acts on it **without** an `event.origin` check.
- **Oracle:** handler exists + no origin check + probe was actually received.
- **Emits:** `POSTMESSAGE`, HIGH, `verified=True`, conf 0.85.

### A4. `prototype` — `PrototypePollutionDetector` (Playwright)
- **What:** Three engines — query `__proto__[marker]=`, JSON body `{"__proto__":{"marker":…}}`, and deep nested `a[__proto__][marker]=`. Reads the polluted prop off a fresh `{}`.
- **Oracle:** marker absent before probe, present after (strict before/after).
- **Emits:** `PROTO_POLLUTION`, HIGH, `verified=True`, conf 0.90.

### A5. `thirdparty` — `ThirdPartyDetector` (Playwright)
- **What:** Heuristic Magecart/skimmer finder. Enumerates `<script src>` and sensitive inputs (card/ssn/cvv/iban…), scores each external/unlisted script. **Unverified by design** (`verified=False`).
- **Anti-FP gate:** if the page has *zero* sensitive inputs, it's a tracker, never a skimmer (kills the `adsbygoogle` false positive).
- **Emits:** `SKIMMER`, MEDIUM, conf ≤0.85.

---

## Track B — Identity & Access Control

### B1. `idor` — `IDORDetector`
- **What:** Mutates every param/URL-path numeric segment. `_generate_mutations` branches by type: numeric (`±1, 0, 9999, 2147483647`), UUID (keep 4 segs, randomize last 12 hex), Mongo ObjectID (`±1, +0xFFFF` on last 8 hex), Base64 (decode→mutate→re-encode). Also `_scan_cross_session` replays with a second identity's headers.
- **Oracle:** status escalation (403/404→200, body>20) **or** `json_differential`/`json_value_changes` (excluding the test value itself) **or** new sensitive-field emergence. Conservative fallback = LOW/unverified.
- **Emits:** `IDOR`, CRITICAL/HIGH/LOW, conf up to 0.85.

### B2. `bola` — `BOLADetector`
- **What:** Strict **3-way cross-tenant differential** requiring `len(authed) ≥ 2` identities. Owner requests own resource; attacker requests own (baseline) and owner's. Numeric stepping only (`+1`).
- **Oracle:** cross-response ≠ attacker's own baseline **and** contains unique owner markers absent from attacker's record (`unique_owner_markers`/`markers_present`). Eliminates id-ignoring/shared endpoints.
- **Emits:** `BOLA`, CRITICAL, `verified=True`, conf 0.95.

### B3. `massassignment` — `MassAssignmentDetector`
- **What:** POST/PUT/PATCH only. Injects a **22-field privilege matrix** (`role`, `is_admin`, `isAdmin`, `is_superuser`, `level:9`, `permissions:["admin"]`, `tier:"premium"`, `credits:99999`, `org_id:1`, …) into JSON (deep AST walk) or form bodies.
- **Oracle:** field/value echoed **and** absent from baseline **and** persisted in parsed response JSON (recursive `_verify_json_field`) — not just HTML reflection.
- **Emits:** `MASS_ASSIGNMENT`, HIGH, `verified=True`, conf 0.90.

### B4. `sessionfix` — `SessionFixationDetector`
- **What:** Sends `Cookie: {name}=titanfixationprobe42` for an 11-name matrix (PHPSESSID, JSESSIONID, ASP.NET_SessionId, connect.sid, …) to auth-hinted endpoints (login/auth/sso…).
- **Oracle:** probe value survives in `Set-Cookie`/body after the auth POST → session not rotated.
- **Emits:** `SESSION_FIXATION`, HIGH, `verified=True`, conf 0.85.

### B5. `jwt` — `JWTDetector`
- **What:** Forges tokens and checks protected endpoints (baseline must be 401/403). Techniques: `alg:none` variants (`none`/`None`/`NONE`/`nOnE`/`""`/`HS256 `), 90+ weak-secret wordlist (incl. base64/UUID/framework defaults), RS256→HS256 confusion (re-sign with public key as HMAC secret), `kid` path traversal / SQLi (`../../dev/null`, `' UNION SELECT 'secret'--`), claim tampering (role/admin=true).
- **Oracle:** status escalation to 200 only (binary; no echo self-verify). Short-circuits on first hit.
- **Emits:** `JWT_WEAKNESS`, CRITICAL (alg:none/weak/kid/confusion) / HIGH (tampering), `verified=True`, conf 0.75–0.97.

### B6. `auth` — `AuthDetector`
- **What:** SQLi/NoSQLi auth-bypass strings (`admin' --`, `' or '1'='1`), default creds (admin/admin…), IP/role spoofing headers (`X-Forwarded-For:127.0.0.1`, `X-Admin:true`), URL-rewrite headers (`X-Original-URL`), HTTP verb tampering (`HEAD/PUT/PATCH/OPTIONS/PROPFIND/TRACE`), path normalization (`/..;/`, `;/`, `;.css`, `%00`).
- **Oracle:** baseline protected (401/403/405) → test 200/302, body not a failure/404, len>20; or login-form success-indicator emergence.
- **Emits:** `AUTH_BYPASS`, CRITICAL, `verified=True`, conf 0.90–0.95.

---

## Track C — LLM & AI Application Defense

### C1. `llm` — `LLMDetector` (`llm/detector.py` + `channel.py` + `payloads.py`)
- **What:** Behavioral-contract probing of one AI endpoint via `LLMChannel` (aiohttp transport, OpenAI-style `messages`, 3-shape fallback ladder: `{messages}`→`{prompt}`→`{input}`). Four checks: `prompt_injection` (goal-hijack + system-update context poison, `TITANCMD…` marker), `system_leak` (repeat system prompt), `data_exfil` (orders model to fetch a **fresh interactsh callback**), `agency` (tool-call templates, `TITANTOOL…`).
- **Oracle:** **consensus judge** — `verified = compliant >= max(1, min_agree)`; default 3 trials, ≥2 must comply. Each judge is a deterministic function (marker echo / system-prompt structure / OOB callback fired / tool-call block). Exfil skipped if no interactsh.
- **Emits:** `PROMPT_INJECTION` (HIGH), `SYSTEM_LEAK` (MEDIUM), `LLM_EXFIL` (CRITICAL), `LLM_AGENCY` (HIGH), `verified=True`.

### C2. `llm_deep` — `LLMDeepDetector`
- **What:** **Payload generator** (no live verification). Returns structured dicts for RAG poisoning (hidden instruction override), tool-use hijacking (exec/ssrf-via-tool/data-exfil), training-data extraction (repetition/completion-hijack), adversarial suffixes (DAN-style), system-prompt leak. Hardcoded CVSS (RAG 9.1, tool hijack 9.8, training 7.5, jailbreak 7.2, leak 5.3).
- **Note:** returns plain dicts, not `Finding` objects; consumed by whatever orchestrator runs them.

---

## Track D — Cloud & Control Plane

### D1. `cloud/storage` — `StorageProbe`
- **What:** Extracts bucket refs **only from prior findings** (body/payload/metadata), never guesses. Probes S3/GCS/Azure/R2 listing URLs (max 3 buckets, GET-only, 8 s timeout).
- **Oracle:** 200 + XML listing markers (`<Contents>`,`<Key>`,`<Blob>`,`<Name>`). 403/404 → nothing.
- **Emits:** `PUBLIC_STORAGE`, HIGH, `verified=True`, conf 0.9.

### D2. `cloud_control` — `CloudControlDetector` + `IMDSProber` (`imds.py`)
- **What:** Response analysis + active IMDS probing *through a caller-supplied SSRF sink* (never contacts IMDS directly). AWS IMDSv1 (`169.254.169.254/latest/meta-data/`) and IMDSv2 (PUT token `X-aws-ec2-metadata-token-ttl-seconds:21600` then GET with token), GCP (`metadata.google.internal` + `Metadata-Flavor:Google`), Azure (`Metadata:true`), IPv6 `fd00::2`. Extracts IAM role creds (`AccessKeyId`+`SecretAccessKey`+`Token`), service-account tokens, STS `AssumeRole`, cross-account trusts.
- **Oracle:** all three AWS cred keys present in one JSON body; IMDSv2 token 200+non-empty; shell/shebang user-data. Concurrency via `Semaphore(3)`, body cap 10k.
- **Emits:** `cloud_imds_exposure`, `cloud_credential_exposure`, `cloud_userdata_exposure`, `cloud_privilege_escalation`, `cloud_cross_account`, etc. — mostly CRITICAL, `tier:confirmed`.

---

## Server-Side Injection & Misc

### S1. `sqli` — `SQLiDetector` (912 lines, the flagship)
- **What:** Five engines — params, 12 injectable headers, nested JSON leaves, OOB/Interactsh, and a **UNION column bisector** (binary search ORDER BY 1–64, then string-column probe, random `TITANxxxxxx` marker). Multi-dialect payloads: `SLEEP/pg_sleep/WAITFOR DELAY/BENCHMARK`, error-based (`extractvalue`/`updatexml`), comment-token WAF bypasses (`/**/`), MySQL versioned comments (`/*!50000UNION*/`), whitespace/CHAR()/double-encoding polymorphisms.
- **Oracle:** 55-string `_SQLI_ERROR_SIGNATURES` (MySQL/PG/MSSQL/SQLite/Oracle/DB2/H2/CockroachDB/Hibernate) absent from baseline; sanity-pair boolean (`_get_opposite_payload` + `is_echo_differential`); `BlindDetector` timing; OOB poll; UNION marker reflection.
- **Emits:** `SQLI`, HIGH (error/echo) / CRITICAL (500 or blind), `verified` only with real evidence.

### S2. `xss` — `XSSDetector`
- **What:** Six context engines — HTML tag, attribute breakout, JS-string, CSTI, header, JSON-AST. Payloads incl. `<script>`, `<img onerror>`, `<<script>//` parser confusion, null-byte/newline bypasses, CSTI `{{7*7}}`/`${7*7}`/`#{7*7}`, WAF variants (mixed case, `javascript:`/`data:` URIs). Context-aware suite selection by param name (`callback`/`url`/`redirect`…).
- **Oracle:** unique `TITANXSS<nonce>` marker; **encoded-marker guard** (skip if HTML-escaped), **attribute-context inert-echo guard** (strip markers inside `value="…"`), HTML-response guard, CSTI requires `49` present and `{{7*7}}` absent.
- **Emits:** `XSS`, CRITICAL (exec-context sink) / HIGH, `verified` via `score_signals`.

### S3. `ssti` — `SSTIDetector`
- **What:** Multi-engine math probes with discriminators — `{{7*7}}`(49), `{{7*'7'}}`(7777777, Jinja2-only), `${777*777}`(freemarker/spel/mako), `#{…}`(thymeleaf), `{…}`(smarty), `<%= %>`(erb/ejs), `[[…]]`(thymeleaf). Plus escape probes (`{{config}}`, `__globals__`).
- **Oracle:** word-bounded `_has_answer` (answer as standalone token, not embedded in a bigger number); raw-echo guard; baseline diff; template-engine error classes (jinja2/twig/freemarker/…); eval-error isolation (filesystem errors excluded).
- **Emits:** `SSTI`, CRITICAL (verified) / HIGH, `verified` via `score_signals`.

### S4. `rce` — `RCEDetector`
- **What:** Multi-OS separators (`; & | && || $()` POSIX, `&` Windows) + delay families (`sleep 4`, `ping -n 3`/`ping -c 3`, backticks/`$()`), reflection markers (`;echo RCE…`), OOB (`;ping/curl {oob}`). Covers params/headers/JSON.
- **Oracle:** 8-char marker echo (no error classes), `BlindDetector` timing with delay-family dedup (≤6 total), OS content fingerprints (`uid=`/`root:`/`phpinfo`), OOB poll.
- **Emits:** `RCE`, CRITICAL (verified) / HIGH, `verified` via `score_signals`.

### S5. `ssrf` — `SSRFDetector`
- **What:** Cloud metadata probes (AWS/GCP/Azure/DO/Alibaba, incl. `100.100.100.200`), IP obfuscation (`2130706433`, `0x7f000001`, `0177.0.0.1`, `127.0.0.1.nip.io`), same-origin internal paths prioritized first, headers, JSON AST, OOB.
- **Oracle:** **strict encoded-echo stripping** (strips payload + host in every encoding before scanning for `ami-id`/`meta-data`/`169.254`/`root:` content indicators), error-class diff, content-change.
- **Emits:** `SSRF`, CRITICAL (verified) / HIGH (unverified `best_weak`), `verified` via `score_signals`.

### S6. `lfi` — `LFIDetector`
- **What:** Traversal cores (`../../etc/passwd`, Windows `win.ini`, `....//`, `%2e%2e%2f`, `%252f` double-encode), PHP wrappers (`php://filter/convert.base64-encode/resource=`), null-byte. Headers + JSON AST.
- **Oracle:** `CONTENT_MARKERS` are **file-content strings only** (`root:x:0:0:`, `daemon:x:`, `[fonts]`, `[boot loader]`) — deliberately never path strings, preventing self-verify; encoded-echo stripping; filesystem error-class differential.
- **Emits:** `LFI`, CRITICAL (verified) / HIGH, `verified` via `score_signals`.

### S7. `nosqli` — `NoSQLiDetector`
- **What:** Bracket-notation (`[$ne]=1`, `[$regex]=.*`, `[$where]=1==1`), JSON operator values (`{"$ne":null}`, `{"$in":[…]}`), string payloads, WAF-bypass variants if `fingerprint["waf"]`. Nested JSON AST + headers (`X-User-Id`,`X-Filter`,`X-Query`).
- **Oracle:** boolean differential via `_get_opposite_payload` (`$ne`→`$eq`, `1==1`→`1==2`) + `is_echo_differential`; error classes `{generic,python,java,nosql}`; data-volume oracle (body >1.3× baseline & >200 B).
- **Emits:** `NO_SQLI`, CRITICAL (verified) / HIGH.

### S8. `xxe` — `XXEDetector`
- **What:** In-band file disclosure (`file:///etc/passwd`, SSRF via `file:///169.254.169.254`), XInclude fallback, SVG upload, OOB (`%ext; SYSTEM "{oob_url}"`).
- **Oracle:** content-leak markers (`root:x:0:0:`, `ssh-rsa`, `BEGIN RSA PRIVATE KEY`) on encoded-stripped body; XML parser error diff (`xml`/`generic`/`python`/`java`); OOB poll (conf 0.97).
- **Emits:** `XXE`, CRITICAL (verified) / HIGH.

### S9. `deser` — `DeserDetector`
- **What:** Passive signature scan of baseline (gadget regexes: `java.io.`, `javax.naming.`, `com.sun.rowset.`, `org.apache.commons.collections.`, `pickle.loads`, `BinaryFormatter`), then active probes — Java `rO0AB…`, Fastjson/Jackson `{"@type":…}`, PHP `O:8:"stdClass"`, Python pickle/PyYAML, .NET `BinaryFormatter`, Node `_$$ND_FUNC$$_`, plus OOB Fastjson. Probes `session`/`rememberMe`/`token` cookies too.
- **Oracle:** passive gadget match (verified, 0.75–0.85); error markers vs baseline (`_pickle.unpicklingerror`, `yaml.constructor…`); OOB poll (0.95).
- **Emits:** `DESERIALIZATION`, CRITICAL (both passive + active), `verified`.

### S10. `cors` — `CORSDetector`
- **What:** Origin probes — `evil.com`, `null`, subdomain confusion (`attacker.{host}`), suffix (`{host}.evil.com`), HTTP-downgrade, null-byte truncation. Pre-flight (OPTIONS) + Vary-missing checks.
- **Oracle:** **strict equality** `acao == origin`; `*` without credentials is explicitly excluded; reflected origin + `ACAC:true` = CRITICAL. Stateless (no baseline).
- **Emits:** `INFO_LEAK`, CRITICAL (reflected+ creds) / HIGH / MEDIUM (preflight, vary-missing), `verified=True`.

### S11. `cache` — `CacheDetector`
- **What:** Three engines — param poisoning (random `TITANCACHEPOISON` marker + unkeyed header harness), unkeyed-header reflection (`X-Forwarded-Host/Scheme/Proto/Prefix`), Web Cache Deception (`/nonexistent.css` etc.).
- **Oracle:** `_is_shared_cacheable` (cf-cache-status/x-cache/age/varnish/cache-control public). Plus cache-buster nonces so production caches aren't polluted.
- **Emits:** `CACHE_POISONING`, HIGH, `verified=True`, conf 0.80–0.90.

### S12. `smuggling` — `SmugglingDetector`
- **What:** CRLF param probes (`%0d%0aContent-Length: 0%0d%0a%0d%0aGET /admin…`) + `Transfer-Encoding` obfuscation (duplicate headers, comma-list, `xchunked`, CRLF-in-value).
- **Oracle:** **multi-level keyword echo peel** (strips payload + `content-length`/`transfer-encoding`/etc. in all encodings, incl. nested layer) before matching error markers; duplicate-TE-header detection; gateway 5xx only counts if baseline wasn't already 5xx.
- **Emits:** `REQUEST_SMUGGLING`, HIGH (5xx) / MEDIUM, `verified=bool(matches)`.

### S13. `crypto` — `CryptoDetector`
- **What:** Scans params matching `token|secret|key|password|hash|jwt|…` (≤3) + response body for weak algorithms (MD5/SHA1/DES/RC4/ECB regex), hex digests in named JSON fields (40→sha1, else md5), JWT `alg:none` (decoded header), and a **hardcoded-secret matrix** (AKIA/ASIA, `sk_live_`, `AIza`, `ghp_`/`github_pat_`, `sk-proj-`/OpenAI, `sk-ant-`/Anthropic, Slack/Discord, private-key blocks, generic `api_key=…`). AWS/key patterns require assignment context; generic token uses `(?!eyJ)` negative lookahead to skip JWTs.
- **Oracle:** contextual/assignment-gated regexes; AKIA only with access-key-id key; hex only in named field; JWT none is structural.
- **Emits:** `CRYPTO_WEAKNESS`, CRITICAL (Stripe/AWS/private-key/GitHub/OpenAI/Anthropic) / HIGH (Google/Slack/Discord/generic) / HIGH (weak algo/digest), `verified=True`.

### S14. `headers` — `HeadersDetector`
- **What:** Pure header audit (single request): missing/weak `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security` (HTTPS, max-age<126d weak), `Content-Security-Policy` (unsafe-inline/eval/wildcard), `Referrer-Policy`, `Permissions-Policy`; info-leak headers (with `\d+\.\d+` version); `Set-Cookie` (Secure on HTTPS, HttpOnly, SameSite).
- **Oracle:** presence/absence + value checks; XFO waived if CSP `frame-ancestors` present.
- **Emits:** `INFO_LEAK`, MEDIUM/LOW, conf 0.85–0.95.

### S15. `logic` — `LogicDetector`
- **What:** Param tampering — `-1`, `0`, `-0.01`, `2147483648`, `0.00000001` against a `"1"` baseline (default param `amount`).
- **Oracle:** reflection (`test_val in body` and not baseline, status 200, len>20) → verified; or state-transition redirect (baseline 200 → 3xx). Redirect-only = unverified.
- **Emits:** `BUSINESS_LOGIC`, HIGH (verified) / MEDIUM, conf 0.85 / 0.5.

### S16. `race` — `RaceDetector`
- **What:** State-changing verbs only (POST/PUT/PATCH/DELETE). Fires **5 concurrent requests released on an `asyncio.Event` barrier** (microsecond sync).
- **Oracle:** divergence gate (bodies must differ) **and** counter-divergence (`_is_counter_divergence` strips all digit runs; if identical → only the number changed → double-spend signature). Filters CSRF/session/timestamp noise. Quorum ≥3 of 5 must be 200.
- **Emits:** `RACE_CONDITION`, HIGH, `verified=True`, conf 0.85.

### S17. `redirect` — `RedirectDetector`
- **What:** Dual engine. (1) HTTP open-redirect: 19 probes (`//evil.com`, `/\evil.com`, `https://evil.com%00`, subdomain-suffix, `@evil.com`…). (2) Browser client-side hijack: hooks `window.location.assign/replace/href`, `window.open`, `<meta refresh>` MutationObserver (Playwright).
- **Oracle:** 3xx `Location` containing evil host; meta-refresh `url=` regex; browser off-origin navigation vs captured origin, dedup by path, on-load/meta-refresh elevated to HIGH.
- **Emits:** `OPEN_REDIRECT` (HTTP, HIGH, verified 0.95/0.90) / `REDIRECT_HIJACK` (browser, HIGH/MEDIUM, unverified).

### S18. `upload` — `UploadDetector`
- **What:** 14-probe matrix with `TITAN_UPLOAD_OK_<nonce>`: direct `.php/.jsp/.aspx`, `.phtml`, content-type spoof, JPEG/GIF polyglots, double-extension `.php.jpg`, case-shift `.pHp`, null-byte `.php%00.png`, semicolon `.php;.jpg`, `.htaccess`, SVG, path traversal `../../titan.txt`. Multipart built by hand (latin1 to preserve bytes).
- **Oracle:** in-band marker echo (CRITICAL for php/jsp/aspx), follow-up GET of extracted URL (200+marker → CRITICAL, 200 no marker → HIGH), generic success keyword + filename in body.
- **Emits:** `UPLOAD`, CRITICAL/HIGH, `verified` per oracle.

### S19. `api` — `APIDetector` (+ `graphql.py`)
- **What:** Swagger/OpenAPI discovery (12 paths: `/swagger.json`, `/openapi.json`, `/v2/api-docs`…), GraphQL introspection (7 paths, `__schema` query, batch-array probe), hidden API paths (9: `/api/v1`, `/admin/api`, `/internal/api`…). `graphql.py` adds mutation probing (`createUser`, `user(id:"1"){id email password}`) + baseline diff.
- **Oracle:** swagger must parse as JSON with `paths`/`swagger`/`openapi`; graphql must have `"__schema"`; hidden path must be JSON/XML content-type (not HTML).
- **Emits:** `API_EXPOSURE`, MEDIUM (swagger/graphql) / LOW (hidden), `verified=True`.

### S20. `apixss` — `ApiXssDetector`
- **What:** Static taint-flow analyzer for API-fed DOM XSS. Extracts inline scripts + up to 3 same-origin `.js` bundles, runs a **4-pass fixed-point taint propagation** (sources: `.value`, `location.*`, `fetch/axios`, `.json()/response`, `localStorage`; sinks: `innerHTML/outerHTML/document.write/eval/Function/setTimeout(string)`). Numeric-field exclusion, generic-name exclusion (115 names), string-stripping before match.
- **Oracle:** always `verified=False` (static, not runtime); conf capped 0.6; carries `confirm` instructions to upgrade tier in browser. Source `api`/`param` → HIGH; `storage`/`error` → MEDIUM.
- **Emits:** `DOM_XSS`, HIGH/MEDIUM, unverified.

### S21. `sourcesecret` — `SourceSecretDetector`
- **What:** Fetches HTML, same-origin `<script src>` (≤5), downloads `.js.map` and parses `sourcesContent` (unminified dev source) — deepest extraction. 11 high-fidelity regexes (GitHub PAT, AKIA, `sk_live_`, OpenAI, Anthropic, `AIza`, DB connection strings, private-key blocks) + generic `api_key=…` assignment.
- **Oracle:** verified by construction (client-accessible source); high-fidelity prefixes can't be accidental; generic requires 12+ char value.
- **Emits:** `HARDCODED_SECRET`, CRITICAL (DB connstr) / HIGH (PAT/AWS/Stripe/OpenAI/Anthropic/JWT/private key) / MEDIUM, `verified=True`.

### S22. `fuzzer` — `FuzzerDetector` (novel-class)
- **What:** Up to 18 mutation variants per value (case, url/double-url/html-entity encoding, empty/huge/whitespace/null-byte/newline, delimiter, integer-overflow/negative/bool/json-null). Classifies each differential.
- **Oracle (tiered):** new strong error class in `{sql,filesystem,xml,template,java,python,ruby}` → HIGH verified 0.85; HTTP 500 vs non-500 baseline → MEDIUM 0.60; body length >1.5× → LOW 0.45; status flip → LOW 0.40. Caps 10 findings.
- **Emits:** `FUZZ_DIFFERENTIAL`, tiered per oracle.

### S23. `parserdiff` — `ParserDiffDetector` (novel-class)
- **What:** Detects **WAF/origin parser disagreement**: same param, 5 classes (lfi/sqli/xss/ssti/ssrf) × 7 encodings (double-url, html-entity, fullwidth, mixed-case, null-byte, tab, newline). Baseline → plain payload → encoded variants.
- **Oracle:** verified **only** when the encoded variant triggers a strong sink the plain one didn't (`new_sinks = (enc_classes - base_classes) - plain_classes`); content-leak markers; unescaped `<script>` only in encoded. Weak flips stay unverified. Caps 8 findings.
- **Emits:** `PARSER_DIFFERENTIAL`, verified on true parser disagreement.

### S24. `deep_audit` — `DeepAuditor` (`prober.py`, Track D helper / standalone)
- **What:** Exploitation-grade cloud probing — parses JS for Firebase/Supabase/AWS/Stripe configs, probes Firestore (`firestore.googleapis.com/v1/projects/{id}/documents/{col}?key=`), anonymous auth + token-against-collection, Supabase REST (`/rest/v1/{table}`), sensitive files (`/.env`,`/.git/config`), security headers, attack-chain synthesis, pytest generation.
- **Oracle:** HTTP 200 + `documents` array = accessible; `idToken` returned = anon auth open; Bearer token → 200 = auth bypass. All `verified=True`.
- **Emits:** custom `AuditFinding` (not core `Finding`): `DEEP-FIRESTORE-USERS`, `DEEP-AUTH-ANONYMOUS`, `DEEP-STORAGE-EXPOSED`, … with `category`/`cvss`/`proof`/`remediation`.

### S25. `supplychain` — `SupplyChainDetector` (+ `sbom.py`, Track G helper)
- **What:** `detector.py` — GitHub Actions PPE (`pull_request_target` + `actions/checkout`), secret echo patterns in workflow YAML, over-permissioned `permissions:`, unpinned actions (ref not semver/SHA), **dependency confusion** (HEAD `registry.npmjs.org/{name}` → 404 = unregistered = takeover-able), typosquatting (Levenshtein ≤2 vs 14 popular pkgs). `sbom.py` — analyzes served HTML/JS for missing SRI, cleartext (HTTP) loads, third-party/risky origins, known-vuln packages (16-entry DB), CDN dependency extraction.
- **Oracle:** PPE requires both `pull_request_target` AND checkout; dependency confusion via live 404; SBOM via DOM observation. **Caveat:** `sbom.py` matches known-vuln package *names* but does **not** compare version ranges → any lodash version trips CVE-2021-23337 (potential FP).
- **Emits:** `supply_chain_ppe` (CRITICAL), `supply_chain_secret_leak`/`dependency_confusion`/`typosquatting` (HIGH), `supply_chain_over_permission`/`unpinned_action`/SRI-missing/known-vuln (MEDIUM/LOW), `verified=True`.

---

## Track G — Hostile & Supply-Chain Surface (`titan/hostile/`)

> Note: Track G lives in `titan/hostile/` (`profiler.py`, `detectors.py`, `offense.py`, `intel.py`, `origins.json`), **not** under `titan/modules/`. It runs as a separate pass (`_run_hostile_pass`) before CVSS scoring. Read-only analysis (TLS/SRI checks, anti-debug cloaks, clickbait index, supply-chain) always runs; **active probes** (redirect-chain → phishing classification, referrer gates) only under signed consent. Ad origins are scored metadata, never vulnerability rows. A sixth spec row (`trackg`) is the spec's module #37; its logic is here, using `detectors.py` (cloak/miner/push/clickbait signatures) + `offense.py` (deterministic findings + consent-gated active probes, GET-only, bounded 3 hops / 6 chains, DNS-rebinding safe).

---

## Cross-cutting oracle reference (`titan/verify/`)

- **`oracles.py`** — `extract_error_classes`/`extract_new_error_classes` (baseline-diffing), `payload_encodings` (nested/double-encoded stripping), `is_echo_differential` + `ECHO_NOISE_RATIO=0.95`, `score_signals` (noisy-OR), `enforce_evidence`/`grade_finding` (auto-demote reflection-only injection findings).
- **`chain_analyzer.py`** — flow-typed multi-hop attack chains (e.g., SSRF→metadata + hardcoded key = Cloud Credential Exposure).
- **`llm_oracles.py`** — `judge_marker`/`judge_system_leak`/`judge_agency`/`judge_oob` + `consensus(trials, min_agree)`.
- **`identity_oracles.py`**, **`ai_escalation.py`**, **`repro.py`**, **`correlation.py`**, **`coverage.py`**, **`kernel.py`**, **`network.py`** — supporting oracles and reporting.

---

## Summary table

| # | Module | Track | Key oracle | Severity ceiling |
|---|--------|-------|-----------|------------------|
| 01 | sqli | — | error-sig + boolean diff + BlindDetector + OOB | CRITICAL |
| 02 | xss | — | nonce marker + encoded/attr-guard + CSTI 49 | CRITICAL |
| 03 | ssti | — | word-bounded math + error class | CRITICAL |
| 04 | rce | — | marker echo + timing + content FP | CRITICAL |
| 05 | ssrf | — | encoded-echo strip + content indic. | CRITICAL |
| 06 | lfi | — | content-marker (no path str) + errno diff | CRITICAL |
| 07 | idor | B | status esc / json diff / sensitive field | CRITICAL |
| 08 | nosqli | — | boolean differential + volume | CRITICAL |
| 09 | xxe | — | content leak + parser err + OOB | CRITICAL |
| 10 | jwt | B | status escalation (200) | CRITICAL |
| 11 | cors | — | strict origin equality + ACAC | CRITICAL |
| 12 | deser | — | gadget sig / err diff / OOB | CRITICAL |
| 13 | auth | B | status escalation + success indic. | CRITICAL |
| 14 | redirect | — | Location/evil + browser off-origin | HIGH |
| 15 | headers | — | header presence/value | MEDIUM |
| 16 | cache | — | shared-cacheable + marker | HIGH |
| 17 | smuggling | — | keyword echo-peel + dup-TE | HIGH |
| 18 | crypto | — | assignment-gated regex | CRITICAL |
| 19 | race | — | counter-divergence barrier | HIGH |
| 20 | logic | — | reflection / redirect state | HIGH |
| 21 | upload | — | in-band exec + public GET | CRITICAL |
| 22 | massassignment | B | JSON field persistence | HIGH |
| 23 | sourcesecret | — | verbatim client source | CRITICAL |
| 24 | sessionfix | B | probe survives auth | HIGH |
| 25 | bola | B | 3-way cross-tenant markers | CRITICAL |
| 26 | fuzzer | — | tiered error/500/length | HIGH |
| 27 | clientside/csp | A | policy text | HIGH |
| 28 | clientside/domxss | A | marker in hooked sink | CRITICAL |
| 29 | clientside/postmessage | A | no origin check + received | HIGH |
| 30 | clientside/prototype | A | before/after inheritance | HIGH |
| 31 | clientside/thirdparty | A | sensitive-input gate | MEDIUM (unverified) |
| 32 | api | — | JSON spec parse | MEDIUM |
| 33 | apixss | — | taint-flow (static) | HIGH (unverified) |
| 34 | cloud/storage | D | 200 + listing markers | HIGH |
| 35 | cloud_control | D | cred-key triple + IMDSv2 | CRITICAL |
| 36 | llm | C | N-trial consensus | CRITICAL (exfil) |
| 37 | trackg (hostile) | G | named deterministic oracles | per-finding |

### Three patterns every module shares
1. **Zero whitelisting** — every param/header/JSON leaf is a candidate; name-based skipping is the exception, not the rule.
2. **Baseline + named oracle** — no finding is reported on a bare status flip or raw reflection; it must survive echo-stripping, differential, math/nonce, timing, or OOB proof.
3. **Fail-soft + consent-aware** — exceptions are swallowed per-probe, active/exploit steps are gated behind signed consent (Track E) or S5 authorization, and production caches are never polluted (cache-buster nonces, GET-only cloud probes).
