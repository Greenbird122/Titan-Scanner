"""Page discovery: forms, links, APIs, SPA routes, specs, and brute-force probes.

Extracted from TitanEngine to keep the crawl loop clean. Each probe
is independent and runs concurrently via asyncio.gather; a failing
probe degrades to its empty default.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from titan.core.crawl import _noop_api_probe, _noop_params_probe, _noop_methods_probe


class DiscoveryEngine:
    """Runs all discovery probes concurrently and returns structured results."""

    def __init__(self, engine: Any) -> None:
        self.engine = engine

    async def discover_all(
        self,
        context: Any,
        page: Any,
        base_url: str,
        current: str,
    ) -> tuple:
        """Run all discovery probes concurrently, isolating failures.

        Returns a 10-tuple matching the caller's unpacking order:
        (forms, links, static_apis, js_apis, spa_routes, swagger,
         postman, graphql, common_params, methods).

        Respects monkey-patches on the engine instance: if the engine
        has replaced e.g. _extract_forms, that version is used.
        """
        e = self.engine

        # Use engine's version if monkey-patched, else self's version
        def _probe(method_name, *args, **kwargs):
            fn = getattr(e, method_name, None)
            if fn is not None and fn is not getattr(self, method_name, None):
                return fn(*args, **kwargs)
            return getattr(self, method_name)(*args, **kwargs)

        probes = [
            _probe('_extract_forms', page),
            _probe('_extract_links', page, base_url),
            _probe('_discover_apis', page, base_url) if e._deep else _noop_api_probe(),
            _probe('_extract_apis_from_js', page, base_url),
            _probe('_crawl_spa_routes', context, page, current),
            _probe('_parse_swagger_spec', context, current) if e._deep else _noop_api_probe(),
            _probe('_parse_postman_collection', context, current) if e._deep else _noop_api_probe(),
            _probe('_discover_graphql_endpoints', context, current) if e._deep else _noop_api_probe(),
            _probe('_brute_force_common_params', context, current, max_endpoints=5) if e._deep else _noop_params_probe(),
            _probe('_brute_force_http_methods', context, current, max_endpoints=5) if e._deep else _noop_methods_probe(),
        ]

        results = await asyncio.gather(*probes, return_exceptions=True)

        # Degrade any failed probe to its empty default
        defaults = [[], [], [], [], [], [], [], [], {}, []]
        out = []
        for r, d in zip(results, defaults):
            if isinstance(r, BaseException):
                out.append(d)
            else:
                out.append(r)

        # SPA signal detection
        forms, links, static_apis, js_apis, spa_routes = out[:5]
        try:
            if isinstance(links, list) and any("#" in l for l in links):
                e._spa_detected = True
            elif isinstance(spa_routes, list) and spa_routes:
                e._spa_detected = True
        except Exception:
            pass

        return tuple(out)

    # ------------------------------------------------------------------
    # Individual probes
    # ------------------------------------------------------------------

    async def _extract_forms(self, page: Any) -> list[dict[str, Any]]:
        """Extract all forms from the page."""
        return await page.evaluate('''() => {
            const forms = [];
            for (const f of document.querySelectorAll('form')) {
                const inputs = [];
                for (const inp of f.querySelectorAll('input, textarea, select, [contenteditable="true"]')) {
                    const isEditable = inp.getAttribute && inp.getAttribute('contenteditable') === 'true';
                    inputs.push({
                        name: inp.name || inp.id || inp.getAttribute('data-param') || '',
                        type: inp.type || (isEditable ? 'richtext' : 'text'),
                        value: inp.value || inp.innerText || '',
                        tag: inp.tagName.toLowerCase()
                    });
                }
                forms.push({
                    action: f.action || window.location.href,
                    method: (f.method || 'GET').toUpperCase(),
                    inputs
                });
            }
            return forms;
        }''')

    async def _extract_links(self, page: Any, base_url: str) -> list[str]:
        """Extract all links from the page."""
        return await page.evaluate('''(base) => {
            const links = new Set();
            for (const a of document.querySelectorAll('a[href]')) {
                try {
                    const raw = a.href || a.getAttribute('href') || '';
                    let h;
                    if (raw.startsWith('#')) {
                        const url = new URL(base);
                        h = url.origin + url.pathname + raw;
                    } else {
                        h = new URL(raw, base).href;
                    }
                    if (h && !h.startsWith('javascript:') && !h.startsWith('mailto:') && !h.startsWith('tel:')) {
                        links.add(h);
                    }
                } catch(e) {}
            }
            for (const a of document.querySelectorAll('a[onclick]')) {
                try {
                    const href = a.getAttribute('onclick') || '';
                    const match = href.match(/['"]([^'"]+)['"]/);
                    if (match) {
                        const h = new URL(match[1], base).href;
                        if (h && !h.startsWith('javascript:')) links.add(h);
                    }
                } catch(e) {}
            }
            return Array.from(links);
        }''', base_url)

    async def _extract_apis_from_js(self, page: Any, base_url: str) -> list[str]:
        """Extract API URLs referenced by JS source files."""
        e = self.engine
        apis: list[str] = []
        js_paths = await page.evaluate('''() => {
            const scripts = [];
            for (const s of document.querySelectorAll('script[src]')) {
                scripts.push(s.getAttribute('src'));
            }
            return scripts;
        }''')

        for js_path in js_paths:
            try:
                if js_path.startswith("http"):
                    js_url = js_path
                else:
                    js_url = base_url.rstrip("/") + js_path
                resp = await page.request.get(js_url, timeout=10000)
                if resp.status != 200:
                    continue
                text = await resp.text()
                apis.extend(
                    u for u in _parse_api_patterns(text, base_url)
                    if e._is_in_scope(u)
                )
            except Exception:
                continue
        return apis

    async def _discover_apis(self, page: Any, base_url: str) -> list[str]:
        """Probe common API paths with GET and POST."""
        e = self.engine
        apis: list[str] = []
        paths = [
            "/swagger.json", "/openapi.json", "/api-docs", "/api/docs",
            "/graphql", "/api/graphql", "/graphiql", "/v1/graphql", "/v2/graphql",
            "/.well-known/raml", "/api.raml", "/api/swagger.json",
            "/api/v1/swagger.json", "/api/v2/swagger.json",
            "/api/v1/docs", "/api/v2/docs",
            "/products", "/categories", "/users", "/orders", "/payments",
            "/conversations", "/messages", "/notifications", "/dashboard",
            "/api/v1/products", "/api/v1/categories", "/api/v1/users",
            "/api/v2/products", "/api/v2/categories", "/api/v2/users",
            "/sales/products", "/sales/categories", "/sales/orders",
            "/sales/users", "/sales/conversations", "/sales/messages",
            "/health", "/healthz", "/ready", "/live", "/status", "/metrics",
            "/api/health", "/api/status", "/api/metrics", "/api/version",
            "/actuator", "/actuator/health", "/actuator/info",
            "/debug", "/debug/vars", "/console", "/admin", "/administrator",
            "/phpinfo", "/info", "/server-info", "/server-status",
            "/.env", "/.git/config", "/.DS_Store", "/backup", "/bak",
            "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/token",
            "/api/v1/patients", "/api/v1/appointments", "/api/v1/facilities",
            "/api/v1/referrals", "/api/v1/triage", "/api/v1/followup",
            "/api/v1/voice", "/api/v1/ussd", "/api/v1/transcription",
            "/api/v1/analytics", "/api/v1/reports", "/api/v1/audit",
            "/api/v1/settings", "/api/v1/config", "/api/v1/notifications",
            "/api/v1/prescriptions", "/api/v1/lab-results", "/api/v1/vitals",
            "/sqli", "/xss", "/lfi", "/cmd", "/rce", "/ssrf", "/xxe", "/ssti",
            "/api/user", "/api/login", "/api/data", "/hash", "/config",
            "/search", "/login", "/register", "/upload", "/download", "/export",
            "/admin", "/administrator", "/manager", "/dashboard", "/panel",
            "/console", "/debug", "/test", "/dev", "/development",
            "/api/search", "/api/login", "/api/register", "/api/upload",
            "/api/download", "/api/export", "/api/admin", "/api/config",
        ]

        async def probe_get(path: str) -> list[str]:
            found: list[str] = []
            try:
                resp = await page.request.get(base_url.rstrip("/") + path, timeout=5000)
                if resp.status == 200:
                    body = await resp.text()
                    if body and not body.startswith("<!doctype"):
                        found.append(base_url.rstrip("/") + path)
                        found.extend(extract_urls_from_json(body, e._is_in_scope))
                elif resp.status in (301, 302, 307, 308):
                    location = resp.headers.get("location", "")
                    if location:
                        found.append(location)
            except Exception:
                pass
            return found

        for found in await asyncio.gather(*[probe_get(p) for p in paths]):
            apis.extend(found)

        # POST-only endpoints
        post_paths = [
            "/api/login", "/login", "/signin", "/api/signin",
            "/api/register", "/register", "/api/signup", "/signup",
            "/api/token", "/token", "/api/refresh", "/refresh",
            "/api/auth/login", "/api/auth/register", "/api/auth/token",
            "/hash", "/api/hash", "/upload", "/api/upload",
            "/api/logout", "/api/session", "/session", "/api/verify",
            "/api/forgot", "/api/reset", "/api/2fa", "/api/otp",
        ]

        async def probe_post(path: str) -> str | None:
            try:
                resp = await page.request.post(
                    base_url.rstrip("/") + path,
                    data={"test": "1"},
                    timeout=4000,
                )
                if resp.status not in (404, 405, 501):
                    return base_url.rstrip("/") + path
            except Exception:
                pass
            return None

        post_results = await asyncio.gather(*[probe_post(p) for p in post_paths])
        apis.extend(r for r in post_results if r)
        return apis

    async def _crawl_spa_routes(self, context: Any, page: Any, base_url: str) -> list[str]:
        """Discover SPA routes from JS route tables and hash links."""
        e = self.engine
        discovered: list[str] = []

        try:
            js_routes = await page.evaluate('''() => {
                const routes = new Set();
                const origin = window.location.origin;
                if (window.__ROUTES__) for (const r of window.__ROUTES__) routes.add(origin + r);
                if (window.routes) for (const r of window.routes) routes.add(origin + r);
                if (window.router) {
                    const r = window.router;
                    if (r.routes) for (const route of r.routes) {
                        if (route.path) routes.add(origin + route.path);
                        if (route.pathname) routes.add(origin + route.pathname);
                    }
                }
                document.querySelectorAll('a[href^="#"], a[href^="/"]').forEach(a => {
                    const href = a.getAttribute('href');
                    if (href && !href.startsWith('#/__')) routes.add(origin + href);
                });
                document.querySelectorAll('[data-route], [data-path], [data-link]').forEach(el => {
                    const val = el.getAttribute('data-route') || el.getAttribute('data-path') || el.getAttribute('data-link');
                    if (val) routes.add(origin + val);
                });
                return Array.from(routes).slice(0, 50);
            }''')
            for route in js_routes:
                if e._is_in_scope(route):
                    discovered.append(route)
        except Exception:
            pass

        if e._deep:
            try:
                hash_routes = await page.evaluate('''() => {
                    const routes = [];
                    const origin = window.location.origin;
                    const common = ['/', '/login', '/register', '/dashboard', '/admin', '/profile', '/settings', '/patients', '/appointments', '/referrals', '/clinical', '/triage', '/analytics', '/notifications', '/followup', '/payments', '/facilities', '/voice', '/ussd', '/transcription'];
                    for (const r of common) routes.push(origin + '#!' + r, origin + '#' + r);
                    return routes;
                }''')
                for route in hash_routes:
                    if e._is_in_scope(route):
                        discovered.append(route)
            except Exception:
                pass

        return sorted(set(discovered))

    async def _parse_swagger_spec(self, context: Any, base_url: str) -> list[dict[str, Any]]:
        """Parse Swagger/OpenAPI specs for endpoint discovery."""
        e = self.engine
        endpoints: list[dict[str, Any]] = []
        spec_urls = [
            base_url.rstrip("/") + "/swagger.json",
            base_url.rstrip("/") + "/openapi.json",
            base_url.rstrip("/") + "/api-docs",
            base_url.rstrip("/") + "/swagger.yaml",
            base_url.rstrip("/") + "/openapi.yaml",
        ]

        for spec_url in spec_urls:
            try:
                resp = await context.request.get(spec_url, timeout=10000)
                if resp.status != 200:
                    continue
                text = await resp.text()
                try:
                    spec = json.loads(text)
                except Exception:
                    continue

                paths = spec.get("paths", {})
                for path, methods in paths.items():
                    if not e._is_in_scope(base_url.rstrip("/") + path):
                        continue
                    for method, details in methods.items():
                        if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
                            continue
                        params = []
                        for param in details.get("parameters", []):
                            if param.get("in") == "query":
                                params.append(param.get("name", ""))
                            elif param.get("in") == "body":
                                schema = param.get("schema", {})
                                props = schema.get("properties", {})
                                params.extend(list(props.keys()))
                        endpoints.append({
                            "path": base_url.rstrip("/") + path,
                            "method": method.upper(),
                            "params": params,
                            "summary": details.get("summary", ""),
                            "operation_id": details.get("operationId", ""),
                        })
            except Exception:
                continue
        return endpoints

    async def _parse_postman_collection(self, context: Any, base_url: str) -> list[dict[str, Any]]:
        """Parse Postman collections for endpoint discovery."""
        e = self.engine
        endpoints: list[dict[str, Any]] = []
        collection_urls = [
            base_url.rstrip("/") + "/postman_collection.json",
            base_url.rstrip("/") + "/collection.json",
            base_url.rstrip("/") + "/api_collection.json",
        ]

        for col_url in collection_urls:
            try:
                resp = await context.request.get(col_url, timeout=10000)
                if resp.status != 200:
                    continue
                text = await resp.text()
                collection = json.loads(text)

                items = collection.get("item", [])
                for item in _flatten_postman_items(items):
                    request = item.get("request", {})
                    url = request.get("url", {})
                    method = request.get("method", "GET").upper()

                    if isinstance(url, dict):
                        raw = url.get("raw", "")
                        path = raw.split("?")[0]
                        if not path.startswith("http"):
                            path = base_url.rstrip("/") + path
                        query = url.get("query", [])
                        params = [q.get("key", "") for q in query if q.get("key")]
                    else:
                        path = str(url).split("?")[0]
                        params = []

                    if e._is_in_scope(path):
                        endpoints.append({
                            "path": path,
                            "method": method,
                            "params": params,
                            "summary": item.get("name", ""),
                        })
            except Exception:
                continue
        return endpoints

    async def _discover_graphql_endpoints(self, context: Any, base_url: str) -> list[str]:
        """Discover GraphQL endpoints by introspection."""
        endpoints: list[str] = []
        graphql_paths = ["/graphql", "/api/graphql", "/graphql/api", "/v1/graphql", "/v2/graphql"]

        for path in graphql_paths:
            try:
                resp = await context.request.post(
                    base_url.rstrip("/") + path,
                    json={"query": "{ __schema { types { name } } }"},
                    headers={"Content-Type": "application/json"},
                    timeout=10000,
                )
                text = await resp.text()
                if resp.status == 200 and "__schema" in text:
                    endpoints.append(base_url.rstrip("/") + path)
            except Exception:
                continue
        return endpoints

    async def _brute_force_common_params(
        self, context: Any, base_url: str, max_endpoints: int = 3,
    ) -> dict[str, list[str]]:
        """Brute-force common parameter names on discovered endpoints."""
        e = self.engine
        common_params = [
            "id", "user_id", "account_id", "profile_id", "patient_id", "client_id", "order_id",
            "file", "file_id", "document", "image", "name", "username",
            "email", "phone", "password", "token", "api_key", "key",
            "url", "path", "page", "search", "query", "q",
            "status", "type", "category", "action", "cmd", "command",
            "country", "city", "location", "address",
            "date", "time", "amount", "price", "quantity", "qty",
            "message", "text", "content", "title",
            "redirect", "callback", "next", "debug", "admin",
            "format", "lang", "uuid", "slug", "csrf", "source",
            "limit", "offset", "sort", "order", "filter",
            "start_date", "end_date", "from", "to",
            "include", "exclude", "fields", "expand",
            "tenant", "org", "organization", "workspace",
            "appointment_id", "referral_id", "facility_id", "visit_id",
            "doctor_id", "nurse_id", "staff_id", "department",
            "diagnosis", "prescription", "medication", "lab_result",
            "vital", "symptom", "allergy", "immunization",
            "payment_id", "invoice_id", "transaction_id", "receipt",
        ]
        common_params.extend(getattr(e, "_platform_extra_params", []) or [])
        top_params = common_params[:25]

        test_endpoints = [
            v for v in list(e.visited)[:max_endpoints]
            if not e._is_spa_shell(v)
        ]
        if not test_endpoints:
            test_endpoints = [base_url]

        discovered: dict[str, list[str]] = {}
        for endpoint in test_endpoints[:max_endpoints]:

            async def test_param(param: str) -> str | None:
                try:
                    test_params = {param: "1"}
                    resp = await context.request.get(endpoint, params=test_params, timeout=1500)
                    body = await resp.text()
                    if resp.status == 200:
                        baseline_resp = await context.request.get(endpoint, timeout=1500)
                        baseline_body = await baseline_resp.text()
                        if len(body) != len(baseline_body):
                            return param
                        elif param.lower() in body.lower() and param.lower() not in baseline_body.lower():
                            return param
                except Exception:
                    pass
                return None

            results = await asyncio.gather(*[test_param(p) for p in top_params])
            accepted_params = [r for r in results if r]
            if accepted_params:
                discovered[endpoint] = accepted_params[:10]

        return discovered

    async def _brute_force_http_methods(
        self, context: Any, base_url: str, max_endpoints: int = 3,
    ) -> list[dict[str, Any]]:
        """Brute-force HTTP methods on discovered endpoints."""
        e = self.engine
        methods = ["OPTIONS", "PUT", "PATCH", "DELETE", "HEAD"]
        results: list[dict[str, Any]] = []

        test_endpoints = [
            v for v in list(e.visited)[:max_endpoints]
            if not e._is_spa_shell(v)
        ]
        if not test_endpoints:
            test_endpoints = [base_url]

        for endpoint in test_endpoints[:max_endpoints]:

            async def test_method(method: str) -> dict[str, Any] | None:
                try:
                    resp = await context.request.fetch(endpoint, method=method, timeout=3000)
                    if resp.status not in (404, 405, 501):
                        return {
                            "path": endpoint,
                            "method": method,
                            "params": [],
                            "summary": f"Method {method} accepted (status {resp.status})",
                        }
                except Exception:
                    pass
                return None

            method_results = await asyncio.gather(*[test_method(m) for m in methods])
            results.extend(r for r in method_results if r)

        return results[:50]


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _parse_api_patterns(js_text: str, base_url: str) -> list[str]:
    """Parse JS source text for API URL patterns."""
    apis: list[str] = []
    patterns = [
        r'https?://[^\s"\'<>]+/sales/[^\s"\'<>]+',
        r'https?://[^\s"\'<>]+/api/[^\s"\'<>]+',
        r'https?://[^\s"\'<>]+/v1/[^\s"\'<>]+',
        r'https?://[^\s"\'<>]+/v2/[^\s"\'<>]+',
        r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
        r'axios\.create\([^)]*baseURL[^)]*\)',
        r'https?://[^\s"\'<>]+/auth/[^\s"\'<>]+',
        r'https?://[^\s"\'<>]+/login[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/register[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/patients[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/appointments[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/facilities[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/referrals[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/triage[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/followup[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/voice[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/ussd[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/transcription[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/analytics[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/reports[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/notifications[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/prescriptions[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/lab-results[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/vitals[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/audit[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/settings[^\s"\'<>]*',
        r'https?://[^\s"\'<>]+/config[^\s"\'<>]*',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']',
    ]
    for pat in patterns:
        matches = re.findall(pat, js_text)
        for m in matches:
            if isinstance(m, tuple):
                m = m[0] if m[0] else m[1]
            apis.append(m)
    return sorted(set(apis))


def _flatten_postman_items(items: list) -> list[dict]:
    """Recursively flatten Postman collection items."""
    result = []
    for item in items:
        if "item" in item:
            result.extend(_flatten_postman_items(item["item"]))
        else:
            result.append(item)
    return result


def extract_urls_from_json(json_text: str, is_in_scope: Any) -> list[str]:
    """Parse JSON response and extract in-scope URLs."""
    urls: list[str] = []
    try:
        data = json.loads(json_text)
        urls.extend(_scan_json(data, is_in_scope))
    except Exception:
        pass
    return urls


def _scan_json(obj: Any, is_in_scope: Any) -> list[str]:
    """Recursively scan JSON for URL-like values."""
    urls: list[str] = []
    if isinstance(obj, dict):
        for key in ("url", "href", "link", "path", "endpoint", "api", "next", "previous"):
            val = obj.get(key)
            if isinstance(val, str) and val.startswith("http") and is_in_scope(val):
                urls.append(val)
            elif isinstance(val, dict) and "url" in val:
                urls.extend(_scan_json(val, is_in_scope))
        for val in obj.values():
            urls.extend(_scan_json(val, is_in_scope))
    elif isinstance(obj, list):
        for item in obj:
            urls.extend(_scan_json(item, is_in_scope))
    return urls
