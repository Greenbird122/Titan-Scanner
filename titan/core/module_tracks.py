"""Identity (Track B) and browser (Track A) module tracks.

Split out of ``modules_runner.py``. ``ModuleRunner`` inherits both
classes, so ``run_identity_modules`` / ``run_browser_modules`` and the
``_run_domxss``-style detectors resolve on the runner exactly as before.
"""

from __future__ import annotations

import asyncio
import random
from typing import TYPE_CHECKING, Any

from titan.core.helpers import consume_task_exception
from titan.core.logger import get_logger

if TYPE_CHECKING:
    from titan.core.models import Finding, ScanResult

logger = get_logger("module_tracks")


class IdentityModulesMixin:
    """Cross-identity detectors: BOLA, mass assignment, JWT, session fix."""

    # State supplied by the host runner before any mixin method runs.
    engine: Any

    # ------------------------------------------------------------------
    # Identity modules (Track B)
    # ------------------------------------------------------------------

    async def run_identity_modules(
        self,
        context: Any,
        target: str,
        api_url: str,
        fingerprint: dict[str, Any],
    ) -> list[Finding]:
        """BOLA, mass assignment, JWT, session fixation across identities."""
        e = self.engine
        findings: list[Finding] = []
        identities = e.session_pool.all()
        if len(identities) < 2:
            return findings

        method = "GET"
        url = api_url.split("?")[0]
        from urllib.parse import parse_qs, urlparse

        qs = parse_qs(urlparse(api_url).query)
        params = {k: v[0] for k, v in qs.items() if v}

        # BOLA
        try:
            from titan.modules.bola.detector import BOLADetector

            bola = BOLADetector(e.payload_smith, fingerprint)
            findings.extend(await bola.scan(context, target, method, url, params, identities))
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        # Mass assignment
        if e._looks_like_api(url) or e._is_state_changing_path(url):
            try:
                from titan.modules.massassignment.detector import MassAssignmentDetector

                ma = MassAssignmentDetector(e.payload_smith, fingerprint)
                findings.extend(await ma.scan(context, target, "POST", url, params))
            except Exception as exc:
                logger.debug(f"suppressed exception: {exc}")
                pass

        # JWT
        try:
            from titan.modules.jwt.detector import JWTDetector

            jwt_det = JWTDetector(e.payload_smith, fingerprint)
            findings.extend(await jwt_det.scan(context, target, method, url, params))
        except Exception as exc:
            logger.debug(f"suppressed exception: {exc}")
            pass

        # Session fixation
        if e._looks_like_api(url):
            try:
                from titan.modules.sessionfix.detector import SessionFixationDetector

                sf = SessionFixationDetector(e.payload_smith, fingerprint)
                findings.extend(await sf.scan(context, target, "POST", url, params))
            except Exception as exc:
                logger.debug(f"suppressed exception: {exc}")
                pass

        return findings


class BrowserDetectorsMixin:
    """Client-side browser security detectors (Track A)."""

    # State supplied by the host runner before any mixin method runs.
    engine: Any

    # ------------------------------------------------------------------
    # Browser modules (Track A)
    # ------------------------------------------------------------------

    async def run_browser_modules(
        self,
        context: Any,
        page: Any,
        target: str,
        fingerprint: dict[str, Any],
        result: ScanResult,
    ) -> None:
        """Client-side browser security detectors."""
        e = self.engine
        if e._driver_dead:
            return

        if not getattr(e, "_client_marker", None):
            e._client_marker = "titanmx" + "".join(random.choices("0123456789abcdef", k=12))

        targets = [u for u in list(e.visited)[:2] if not e._is_spa_shell(u)]
        if not targets:
            targets = [target]

        modules_cfg = e.config.get("clientside", {})

        for page_url in targets:
            b_page = None
            np_task = asyncio.ensure_future(context.new_page())
            np_task.add_done_callback(consume_task_exception)
            np_done, _ = await asyncio.wait({np_task}, timeout=10)
            if np_task not in np_done:
                np_task.cancel()
                continue
            try:
                b_page = np_task.result()
            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")
                continue
            try:
                from urllib.parse import parse_qs, urlparse

                qs = parse_qs(urlparse(page_url).query)
                params = {k: v[0] for k, v in qs.items() if v}

                checks = [
                    ("domxss", self._run_domxss),
                    ("postmessage", self._run_postmessage),
                    ("prototype", self._run_proto_pollution),
                    ("third_party", self._run_third_party),
                    ("csp", self._run_csp),
                    ("redirect", self._run_redirect),
                ]
                for name, runner in checks:
                    if not modules_cfg.get(name, {}).get("enabled", True):
                        continue
                    det_task = asyncio.ensure_future(runner(b_page, target, page_url, params))
                    det_task.add_done_callback(consume_task_exception)
                    det_done, _ = await asyncio.wait({det_task}, timeout=15)
                    if det_task not in det_done:
                        det_task.cancel()
                        continue
                    try:
                        findings = det_task.result()
                    except Exception:
                        findings = []
                    result.findings.extend(findings)
            finally:
                try:
                    close_task = asyncio.ensure_future(b_page.close())
                    close_task.add_done_callback(consume_task_exception)
                    close_done, _ = await asyncio.wait({close_task}, timeout=5)
                    if close_task not in close_done:
                        close_task.cancel()
                except Exception as exc:
                    logger.debug(f"suppressed exception: {exc}")
                    pass

    # ------------------------------------------------------------------
    # Individual browser detectors
    # ------------------------------------------------------------------

    async def _run_domxss(self, b_page, target: str, page_url: str, params: dict[str, str]):
        from titan.modules.clientside.domxss.detector import DomXSSDetector

        det = DomXSSDetector(self.engine.payload_smith, {})
        return await det.scan(b_page, target, page_url, params, marker=getattr(self.engine, "_client_marker", None))

    async def _run_postmessage(self, b_page, target: str, page_url: str, params: dict[str, str]):
        from titan.modules.clientside.postmessage.detector import PostMessageDetector

        det = PostMessageDetector(self.engine.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)

    async def _run_proto_pollution(self, b_page, target: str, page_url: str, params: dict[str, str]):
        from titan.modules.clientside.prototype.detector import PrototypePollutionDetector

        det = PrototypePollutionDetector(self.engine.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)

    async def _run_third_party(self, b_page, target: str, page_url: str, params: dict[str, str]):
        from titan.modules.clientside.thirdparty.detector import ThirdPartyDetector

        det = ThirdPartyDetector(self.engine.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)

    async def _run_csp(self, b_page, target: str, page_url: str, params: dict[str, str]):
        from titan.modules.clientside.csp.detector import CSPDetector

        det = CSPDetector(self.engine.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)

    async def _run_redirect(self, b_page, target: str, page_url: str, params: dict[str, str]):
        from titan.modules.redirect.detector import RedirectDetector

        det = RedirectDetector(self.engine.payload_smith, {})
        return await det.scan(b_page, target, page_url, params)
