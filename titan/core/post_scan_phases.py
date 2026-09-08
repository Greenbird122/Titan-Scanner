"""Optional post-scan phases for TitanEngine.

Extracted from titan/core/engine.py. Supplies the Track C/D/F/G optional
phase runners (LLM channel probing, cloud storage, subdomain takeover,
cloud IMDS through SSRF sinks, SBOM analysis, deep audit) plus the
``_run_optional_phases`` orchestrator that gates them by config. State the
runners read (``config``, ``visited``, interactsh/channel/fetcher handles)
stays on the host engine; this mixin only supplies behavior.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from titan.core.logger import get_logger
from titan.core.models import Finding

logger = get_logger("post_scan_phases")


class PostScanPhasesMixin:
    """Config-gated optional scan phases for TitanEngine."""

    # State supplied by the host engine before any mixin method runs.
    config: dict
    visited: Any
    interactsh: Any
    _llm_channel: Any
    _llm_interactsh: Any
    _storage_fetcher: Any

    async def _run_optional_phases(self, target, result, page):
        """Run LLM, storage, subdomain, IMDS, SBOM, and deep audit phases."""
        if self.config.get("llm", {}).get("enabled", True):
            await self._run_llm_channel(target, result)
        if self.config.get("cloud", {}).get("storage", {}).get("enabled", True):
            await self._run_storage_probe(target, result)
        if self.config.get("subdomain_takeover", {}).get("enabled", True):
            await self._run_subdomain_takeover(target, result)
        if self.config.get("cloud", {}).get("imds", {}).get("enabled", True):
            await self._probe_cloud_imds(target, result)
        if self.config.get("crawl", {}).get("supplychain", {}).get("enabled", True):
            await self._run_sbom_analysis(target, result, page)
        if self.config.get("deep_audit", {}).get("enabled", True):
            await self._run_deep_audit(target, result)

    # ==================================================================
    # Optional phase implementations (LLM, storage, subdomain, etc.)
    # ==================================================================

    @staticmethod
    def _is_llm_endpoint(url: str) -> bool:
        path = urlparse(url).path.lower()
        markers = (
            "/api/chat", "/chat/completions", "/v1/chat", "/v1/completions",
            "/api/assistant", "/api/generate", "/api/completion",
            "/api/message", "/api/ai", "/api/ask", "/api/answer",
            "/api/query", "/api/inference", "/api/prompt", "/api/completions",
        )
        return any(m in path for m in markers)

    async def _run_llm_channel(self, target, result):
        llm_cfg = self.config.get("llm", {})
        if not llm_cfg.get("enabled", True):
            return
        endpoints: list[str] = [e for e in (llm_cfg.get("endpoints") or []) if e]
        discovered = [u for u in list(self.visited) if self._is_llm_endpoint(u)]
        for u in discovered:
            if u not in endpoints:
                endpoints.append(u)
        if not endpoints:
            return
        endpoints = endpoints[:2]
        try:
            from titan.modules.llm.channel import LLMChannel
            from titan.modules.llm.detector import LLMDetector
            channel = getattr(self, "_llm_channel", None)
            if channel is None:
                channel = LLMChannel(
                    timeout=float(llm_cfg.get("timeout", 15)),
                    model=llm_cfg.get("model", "gpt-4o-mini"),
                )
            interactsh = getattr(self, "_llm_interactsh", None) or self.interactsh
            detector = LLMDetector(channel, interactsh, llm_cfg)
            per_endpoint = float(llm_cfg.get("per_endpoint_timeout", 40))
            for ep in endpoints:
                logger.info(f"[+] LLM channel: probing {ep}")
                try:
                    findings = await asyncio.wait_for(detector.scan(target, ep), timeout=per_endpoint)
                    result.findings.extend(findings)
                    if findings:
                        logger.info(f"    [+] Track C: {len(findings)} LLM findings on {ep}")
                except (asyncio.TimeoutError, Exception) as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue
        except Exception:
            return

    async def _run_storage_probe(self, target, result):
        if not self.config.get("cloud", {}).get("storage", {}).get("enabled", True):
            return
        try:
            from titan.modules.cloud.storage import StorageProbe
            probe = StorageProbe(fetcher=getattr(self, "_storage_fetcher", None))
            storage_findings = await probe.scan(target, result.findings)
            result.findings.extend(storage_findings)
            if storage_findings:
                logger.info(f"[+] Track D: {len(storage_findings)} publicly listable bucket(s) found")
        except Exception:
            return

    async def _run_subdomain_takeover(self, target, result):
        if not self.config.get("subdomain_takeover", {}).get("enabled", True):
            return
        try:
            from titan.modules.subdomain_takeover.detector import SubdomainTakeoverDetector
            detector = SubdomainTakeoverDetector()
            takeover_findings = await detector.scan(
                context=None, target=target, method="GET",
                url=target, params={}, fingerprint={},
            )
            result.findings.extend(takeover_findings)
            if takeover_findings:
                logger.info(f"[+] Subdomain takeover: {len(takeover_findings)} vulnerable subdomain(s) found")
        except Exception as exc:
            logger.warning(f"[!] Subdomain takeover detection failed: {exc}")

    async def _probe_cloud_imds(self, target, result):
        ssrf_findings = [
            f for f in result.findings
            if str(getattr(f, "type", "")) in ("ssrf", "AttackType.SSRF", "cloud_imds_exposure")
            and f.url
        ]
        if not ssrf_findings:
            return
        try:
            from titan.modules.cloud_control.imds import IMDSProber
        except ImportError:
            return
        prober = IMDSProber(timeout=5.0)
        ssrf_url = ssrf_findings[0].url
        ssrf_param = ssrf_findings[0].param or "url"

        async def _ssrf_sink(imds_url, method="GET", headers=None, timeout=5.0):
            from urllib.parse import parse_qs, urlencode
            from urllib.parse import urlparse as _up

            import aiohttp
            parsed = _up(ssrf_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[ssrf_param] = [imds_url]
            new_query = urlencode(params, doseq=True)
            sink_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            try:
                async with aiohttp.ClientSession() as session, session.request(
                    method=method, url=sink_url, headers=headers or {},
                    timeout=aiohttp.ClientTimeout(total=timeout), ssl=False,
                ) as resp:
                    body = await resp.text(errors="replace")
                    return (resp.status, dict(resp.headers), body)
            except Exception:
                return (0, {}, "")

        logger.info("[+] Cloud IMDS probing through SSRF sink...")
        imds_findings = await prober.probe(_ssrf_sink)
        if imds_findings:
            result.findings.extend(imds_findings)
            critical = sum(1 for f in imds_findings if f.get("severity") == "critical")
            logger.info(f"[+] Cloud IMDS: {len(imds_findings)} finding(s) ({critical} critical)")

    async def _run_sbom_analysis(self, target, result, page=None):
        try:
            from titan.modules.supplychain.sbom import SBOMAnalyzer
        except ImportError:
            return
        analyzer = SBOMAnalyzer()
        html = ""
        if page:
            try:
                html = await page.content()
            except Exception as exc:
                logger.debug(f"suppressed exception: {exc}")
                pass
        if not html:
            return
        report = analyzer.analyze(html, page_url=target)
        if report.findings:
            for f_dict in report.findings:
                try:
                    from titan.core.models import AttackType, Severity
                    severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                                    "medium": Severity.MEDIUM, "low": Severity.LOW}
                    finding = Finding(
                        type=AttackType.SUPPLY_CHAIN if hasattr(AttackType, 'SUPPLY_CHAIN') else AttackType.OTHER,
                        severity=severity_map.get(f_dict.get("severity", "medium"), Severity.MEDIUM),
                        title=f_dict.get("title", "Supply Chain Finding"),
                        url=target, param=f_dict.get("type", ""),
                        evidence=f_dict.get("evidence", ""), confidence=0.8,
                        cvss_score=f_dict.get("cvss_score", 5.0),
                        tags=["supplychain", "sbom"],
                        metadata=f_dict.get("metadata", {}),
                    )
                    result.findings.append(finding)
                except Exception as exc:
                    logger.debug(f"suppressed exception: {exc}")
                    pass
            logger.info(f"[+] SBOM: {len(report.findings)} finding(s)")

    async def _run_deep_audit(self, target, result):
        try:
            from titan.modules.deep_audit.prober import DeepAuditor
            auditor = DeepAuditor()
            audit_result = await auditor.audit(
                target, budget=float(self.config.get("deep_audit", {}).get("budget", 60)),
            )
            from titan.core.models import AttackType, Severity
            for af in audit_result.findings:
                if af.severity in ("critical", "high", "medium"):
                    try:
                        sev = Severity(af.severity)
                    except ValueError:
                        sev = Severity.MEDIUM
                    try:
                        atype = AttackType(af.category.replace("_", "-").replace("misconfiguration", "info-leak"))
                    except ValueError:
                        atype = AttackType.INFO_LEAK
                    finding = Finding(
                        target=target, url=target, method="GET", param="deep-audit",
                        location="cloud", payload=af.description[:200],
                        attack_type=atype, severity=sev,
                        confidence=0.95 if af.verified else 0.7,
                        status=200, evidence=af.proof,
                        tier="confirmed" if af.verified else "suspicious",
                        tags=["deep-audit", af.category, af.id],
                        notes=f"{af.title}: {af.remediation}",
                    )
                    result.findings.append(finding)
            verified = sum(1 for f in audit_result.findings if f.verified)
            logger.info(f"[+] Deep Audit: {len(audit_result.findings)} finding(s), {verified} verified")
        except Exception as exc:
            result.errors.append(f"Deep audit failed: {exc}")
            logger.warning(f"[!] Deep audit: {exc}")

