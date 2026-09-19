"""API-endpoint discovery probes: OpenAPI/Swagger specs, Postman collections,
parameter brute-force and HTTP-method brute-force.

Split out of ``discovery.py`` (where they were 300 of its 820 lines). The
methods keep their original bodies, including the ``self.engine`` handle
DiscoveryEngine handed them, so the move stays behaviour-neutral.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from titan.core.logger import get_logger

logger = get_logger("discovery.api_probes")


def _flatten_postman_items(items: list) -> list[dict]:
    """Recursively flatten Postman collection items."""
    result = []
    for item in items:
        if "item" in item:
            result.extend(_flatten_postman_items(item["item"]))
        else:
            result.append(item)
    return result


class ApiProbes:
    """Owns the spec-parsing and brute-force probes; shares the engine."""

    def __init__(self, engine: Any) -> None:
        self.engine = engine

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
                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
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
                        endpoints.append(
                            {
                                "path": base_url.rstrip("/") + path,
                                "method": method.upper(),
                                "params": params,
                                "summary": details.get("summary", ""),
                                "operation_id": details.get("operationId", ""),
                            }
                        )
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
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
                        endpoints.append(
                            {
                                "path": path,
                                "method": method,
                                "params": params,
                                "summary": item.get("name", ""),
                            }
                        )
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
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
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue
        return endpoints

    async def _brute_force_common_params(
        self,
        context: Any,
        base_url: str,
        max_endpoints: int = 3,
    ) -> dict[str, list[str]]:
        """Brute-force common parameter names on discovered endpoints."""
        e = self.engine
        common_params = [
            "id",
            "user_id",
            "account_id",
            "profile_id",
            "patient_id",
            "client_id",
            "order_id",
            "file",
            "file_id",
            "document",
            "image",
            "name",
            "username",
            "email",
            "phone",
            "password",
            "token",
            "api_key",
            "key",
            "url",
            "path",
            "page",
            "search",
            "query",
            "q",
            "status",
            "type",
            "category",
            "action",
            "cmd",
            "command",
            "country",
            "city",
            "location",
            "address",
            "date",
            "time",
            "amount",
            "price",
            "quantity",
            "qty",
            "message",
            "text",
            "content",
            "title",
            "redirect",
            "callback",
            "next",
            "debug",
            "admin",
            "format",
            "lang",
            "uuid",
            "slug",
            "csrf",
            "source",
            "limit",
            "offset",
            "sort",
            "order",
            "filter",
            "start_date",
            "end_date",
            "from",
            "to",
            "include",
            "exclude",
            "fields",
            "expand",
            "tenant",
            "org",
            "organization",
            "workspace",
            "appointment_id",
            "referral_id",
            "facility_id",
            "visit_id",
            "doctor_id",
            "nurse_id",
            "staff_id",
            "department",
            "diagnosis",
            "prescription",
            "medication",
            "lab_result",
            "vital",
            "symptom",
            "allergy",
            "immunization",
            "payment_id",
            "invoice_id",
            "transaction_id",
            "receipt",
        ]
        common_params.extend(getattr(e, "_platform_extra_params", []) or [])
        top_params = common_params[:25]

        test_endpoints = [v for v in list(e.visited)[:max_endpoints] if not e._is_spa_shell(v)]
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
                        if len(body) != len(baseline_body) or (
                            param.lower() in body.lower() and param.lower() not in baseline_body.lower()
                        ):
                            return param
                except Exception as exc:
                    logger.debug(f"suppressed exception: {exc}")
                    pass
                return None

            results = await asyncio.gather(*[test_param(p) for p in top_params])
            accepted_params = [r for r in results if r]
            if accepted_params:
                discovered[endpoint] = accepted_params[:10]

        return discovered

    async def _brute_force_http_methods(
        self,
        context: Any,
        base_url: str,
        max_endpoints: int = 3,
    ) -> list[dict[str, Any]]:
        """Brute-force HTTP methods on discovered endpoints."""
        e = self.engine
        methods = ["OPTIONS", "PUT", "PATCH", "DELETE", "HEAD"]
        results: list[dict[str, Any]] = []

        test_endpoints = [v for v in list(e.visited)[:max_endpoints] if not e._is_spa_shell(v)]
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
                except Exception as exc:
                    logger.debug(f"suppressed exception: {exc}")
                    pass
                return None

            method_results = await asyncio.gather(*[test_method(m) for m in methods])
            results.extend(r for r in method_results if r)

        return results[:50]
