"""REST/GraphQL API module dispatch.

Split out of ``modules_runner.py``. ``ModuleRunner`` inherits this
class, so ``_run_api_modules`` / ``_test_rest_api`` / ``_run_graphql``
resolve on the runner exactly as before — including the regression
tests in ``test_graphql_dispatch.py``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from titan.core.logger import get_logger

if TYPE_CHECKING:
    from titan.core.models import Finding

logger = get_logger("api_dispatch")


class ApiModuleDispatch:
    """Dispatch the module matrix against discovered API endpoints."""

    # State supplied by the host runner before any mixin method runs.
    engine: Any

    async def _run_api_modules(
        self,
        context: Any,
        target: str,
        api_url: str,
        fingerprint: dict[str, Any],
    ) -> list[Finding]:
        """Run module matrix against a discovered API endpoint."""
        e = self.engine
        findings: list[Finding] = []
        if e._driver_dead:
            return findings
        # GraphQL dispatch fires on URL path OR fingerprinted tech, so
        # GraphQL at nonstandard paths (/gql, /query) still gets scanned.
        fp_techs = {str(t).lower() for t in (fingerprint or {}).get("technologies", [])}
        is_graphql = "graphql" in api_url.lower() or any("graphql" in t for t in fp_techs)
        if is_graphql:
            findings.extend(await self._run_graphql(context, target, api_url, fingerprint))
        else:
            findings.extend(await e._test_rest_api(context, target, api_url, fingerprint))
        for f in findings:
            f.verified = False
        return findings

    async def _test_rest_api(self, context, target, api_url, fingerprint):
        """Test a REST API endpoint with GET and POST phases."""
        from urllib.parse import parse_qs, urlparse

        from titan.core.route_scorer import score_url

        findings: list[Finding] = []
        parsed = urlparse(api_url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}
        if not params:
            params = {"id": "1", "q": "test", "search": "test", "page": "1", "limit": "10"}

        base_url = api_url.split("?")[0]
        if not await self._endpoint_is_alive(context, base_url, params):
            print(f"    [i] Skipping dead endpoint {base_url}")
            return []

        api_score = score_url(
            api_url, params=list(params.keys()), technologies=fingerprint.get("technologies", []) if fingerprint else []
        )
        findings.extend(
            await self.engine._run_attack_modules(
                context,
                target,
                "GET",
                api_url,
                params,
                fingerprint,
                route_score=api_score,
            )
        )

        post_url = api_url.split("?")[0]
        post_data = dict(params) if params else {"test": "1", "id": "1", "q": "test"}
        findings.extend(
            await self.engine._run_attack_modules(
                context,
                target,
                "POST",
                post_url,
                post_data,
                fingerprint,
                route_score=api_score,
            )
        )
        return findings

    async def _endpoint_is_alive(self, context, base_url, params):
        """Check if an endpoint is alive (not a dead route)."""
        try:
            resp = await context.request.get(base_url, params=params, timeout=5000)
            status = resp.status
        except Exception:
            return True
        if status in (404, 410):
            return await self._post_probe(context, base_url)
        if status == 200:
            try:
                body = await resp.text()
            except Exception:
                return True
            from titan.core.helpers import is_soft_404

            if is_soft_404(body):
                return await self._post_probe(context, base_url)
        return True

    async def _post_probe(self, context, base_url):
        """Benign POST probe for endpoint liveness."""
        try:
            post_resp = await context.request.post(base_url, data={"test": "1"}, timeout=5000)
        except Exception:
            return False
        if post_resp.status in (404, 410):
            return False
        try:
            body = await post_resp.text()
        except Exception:
            return post_resp.status == 200
        head = body[:4000].lower()
        is_html = "<html" in head or head.startswith("<!doctype")
        if post_resp.status == 200:
            from titan.core.helpers import is_soft_404

            if is_html and is_soft_404(body):
                return False
            return True
        return not is_html

    async def _run_graphql(self, ctx, t, api_url, fp):
        from titan.modules.api.graphql import GraphQLScanner

        return await GraphQLScanner(self.engine.payload_smith, fp).scan(ctx, t, api_url)
