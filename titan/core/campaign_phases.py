"""Post-scan campaign phases for TitanEngine.

Extracted from titan/core/engine.py. Supplies the post-scan phase
orchestrator plus its leaf runners: hostile surface pass, anti-forensics,
brain mutation loop, evolution engine, Track E exploit staging, and fleet
scan. State the runners read (``config``, ``visited``, ``stealth``,
``redirect_chain``, transport handle) stays on the host engine; this mixin
only supplies behavior.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from titan.core.logger import get_logger
from titan.core.models import Finding

logger = get_logger("campaign_phases")


class CampaignPhasesMixin:
    """Post-scan campaign phases for TitanEngine."""

    # State supplied by the host engine before any mixin method runs.
    config: dict
    visited: Any
    stealth: Any
    redirect_chain: list[dict[str, Any]]
    _hostile: bool
    _transport_http: Any
    _transport_send: Any
    _is_in_scope: Any
    _is_spa_shell: Any
    _has_consent: Any
    _prior_observed: Any

    # ==================================================================
    # Post-scan phases (hostile, brain, evolution, anti-forensics, fleet)
    # ==================================================================

    async def _run_post_scan_phases(self, target, result):
        """Fleet, hostile pass, anti-forensics, brain loop, evolution."""
        if self.config.get("fleet", {}).get("enabled", False):
            await self._run_fleet_scan(target, result)

        supplychain_cfg = self.config.get("crawl", {}).get("supplychain", {})
        if self._hostile or supplychain_cfg.get("enabled", True):
            try:
                await self._run_hostile_pass(target, result)
            except Exception as exc:
                result.errors.append(f"Track G hostile pass failed: {exc}")

        try:
            await self._apply_anti_forensics(target, result)
        except Exception as exc:
            result.errors.append(f"Anti-forensics failed: {exc}")

        try:
            await self._run_brain_loop(target, result)
        except Exception as exc:
            result.errors.append(f"Brain loop failed: {exc}")

        try:
            await self._run_evolution(target, result)
        except Exception as exc:
            result.errors.append(f"Evolution engine failed: {exc}")

        # CVSS & PoC generation
        from titan.core.cvss import CVSSScorer
        from titan.core.poc import PoCGenerator

        for f in result.findings:
            if f.tier != "confirmed":
                f.cvss_score = None
                f.cvss_vector = ""
                f.poc_curl = ""
                f.poc_python = ""
                continue
            if "ai_escalation" in f.metadata or not f.cvss_score:
                cvss_data = CVSSScorer.score(f)
                f.cvss_score = cvss_data["cvss_score"]
                f.cvss_vector = cvss_data["cvss_vector"]
            if not f.poc_curl or not f.poc_python:
                poc = PoCGenerator.generate(f)
                f.poc_curl = poc["curl"]
                f.poc_python = poc["python"]

        # Exploit phase
        try:
            await self._run_exploit_modules(target, result)
        except Exception as exc:
            result.errors.append(f"Track E exploit phase failed: {exc}")

    async def _run_hostile_pass(self, target, result):
        import aiohttp

        from titan.hostile import findings_from_dicts, run_pass


        candidates = [target] + [
            u for u in self.visited
            if self._is_in_scope(u) and not self._is_spa_shell(u)
        ]
        candidates = list(dict.fromkeys(candidates))[:3]
        samples: list[dict] = []
        for u in candidates:
            try:
                ua = self.stealth.get_user_agent()
                _hdrs = {"User-Agent": ua} if ua else {}
                transport_resp = await self._transport_send(u, headers=_hdrs, timeout=12.0)
                if transport_resp and not transport_resp.is_error and transport_resp.status == 200:
                    samples.append({"url": u, "html": transport_resp.text[:600000]})
                    continue
                async with aiohttp.ClientSession() as _sess:
                    async with _sess.get(u, timeout=12, ssl=False, headers=_hdrs or None) as resp:
                        if resp.status == 200:
                            text = await resp.text(errors="replace")
                            samples.append({"url": u, "html": text[:600000]})
            except Exception:
                continue
        if not samples:
            return
        consented = self._has_consent(target)
        async with aiohttp.ClientSession() as _hostile_session:
            payload = await run_pass(
                samples, target, target=target, session=_hostile_session,
                consented=consented, prior_observed=self._prior_observed(target),
            )
        payload["redirect_chain"] = self.redirect_chain[-50:]
        result.hostile = payload
        new_findings = findings_from_dicts(payload.get("findings", []))
        result.findings.extend(new_findings)
        logger.info(f"[+] Track G: {len(new_findings)} hostile-surface finding(s)")

    async def _apply_anti_forensics(self, target, result):
        af_cfg = self.config.get("stealth", {}).get("anti_forensics", {})
        if not af_cfg.get("enabled", False):
            return
        try:
            from titan.stealth.advanced import AntiForensics
            af = AntiForensics(
                profile=af_cfg.get("profile", "browser"),
                decoy_count=int(af_cfg.get("decoy_count", 3)),
                polymorphic_count=int(af_cfg.get("polymorphic_count", 3)),
            )
            if self._transport_http:
                try:
                    sent = await af.decoys.inject(target, self._transport_http, count=int(af_cfg.get("decoy_count", 3)))
                    if sent:
                        logger.info(f"[+] Anti-forensics: {sent} decoy request(s) sent")
                except Exception:
                    pass
            high_value = [f for f in result.findings if f.confidence >= 0.7 and f.payload][:5]
            if high_value:
                report_data = []
                for finding in high_value:
                    attack = af.prepare_attack(finding.payload, target, variant="auto")
                    report_data.append({
                        "original": finding.payload,
                        "variants": attack["polymorphic_payloads"],
                    })
                logger.info(f"[+] Anti-forensics: {len(report_data)} payload(s) polymorphized")
        except Exception as exc:
            result.errors.append(f"Anti-forensics failed: {exc}")
            logger.warning(f"[!] Anti-forensics: {exc}")

    async def _run_brain_loop(self, target, result):
        brain_cfg = self.config.get("brain", {})
        if not brain_cfg.get("enabled", True):
            return
        high_value = [
            f for f in result.findings
            if f.confidence >= 0.6 and f.attack_type.value in (
                "SQLi", "XSS", "SSRF", "RCE", "LFI", "SSTI", "XXE", "NoSQLi",
            )
        ]
        if not high_value:
            return
        logger.info(f"[+] Brain loop: {len(high_value)} high-value finding(s) to mutate")
        try:
            from titan.brain.loop import BrainLoop
            brain = BrainLoop(target=target)
            budget = float(brain_cfg.get("budget", 90))
            deadline = time.time() + budget
            mutations_found = 0
            bypasses_found = 0
            for finding in high_value:
                if time.time() > deadline:
                    break
                try:
                    from titan.stealth.advanced import PolymorphicEngine
                    poly = PolymorphicEngine()
                    variants = poly.generate(
                        finding.payload, variant="auto",
                        count=int(brain_cfg.get("variants_per_finding", 5)),
                    )
                except Exception:
                    variants = [finding.payload]
                for variant in variants:
                    if time.time() > deadline:
                        break
                    try:
                        test_url = self._build_variant_url(finding, variant)
                        if not test_url:
                            continue
                        resp = await self._transport_send(test_url, method=finding.method, timeout=8.0)
                        if resp is None or resp.is_error:
                            continue
                        is_bypass = self._detect_bypass(finding, resp)
                        mutations_found += 1
                        if is_bypass:
                            bypasses_found += 1
                            bypass_finding = Finding(
                                url=test_url, method=finding.method,
                                param=finding.param, location=finding.location,
                                payload=variant, attack_type=finding.attack_type,
                                severity=finding.severity,
                                confidence=min(finding.confidence + 0.1, 0.99),
                                status=resp.status,
                                evidence="Brain bypass: variant produced different response",
                                tier="suspicious",
                                tags=finding.tags + ["brain:bypass", "mutation:true"],
                                notes=f"Mutated from {finding.attack_type.value} at {finding.url}",
                            )
                            result.findings.append(bypass_finding)
                    except Exception:
                        continue
                try:
                    brain.strategy.record_result(
                        module=f"brain_{finding.attack_type.value.lower()}",
                        success=bypasses_found > 0, value=0.1,
                    )
                except Exception:
                    pass
            if mutations_found:
                logger.info(f"[+] Brain loop: {mutations_found} mutations tested, {bypasses_found} bypass(es) found")
        except Exception as exc:
            result.errors.append(f"Brain loop failed: {exc}")
            logger.warning(f"[!] Brain loop: {exc}")

    def _build_variant_url(self, finding, variant: str) -> str | None:
        from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse
        try:
            parsed = urlparse(finding.url)
            if finding.location == "query":
                qs = parse_qs(parsed.query, keep_blank_values=True)
                if finding.param in qs:
                    qs[finding.param] = [variant]
                rebuilt: str = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                return rebuilt
            elif finding.location == "path":
                replaced: str = finding.url.replace(finding.param, quote(variant, safe=""))
                return replaced
            return None
        except Exception:
            return None

    def _detect_bypass(self, original_finding, resp) -> bool:
        try:
            if resp.status != getattr(original_finding, "status", 200):
                if resp.status == 200 and getattr(original_finding, "status", 200) in (403, 405, 503):
                    return True
                if resp.status == 200 and original_finding.attack_type.value in ("SQLi", "XSS", "RCE"):
                    return True
            body = resp.text.lower() if hasattr(resp, "text") else ""
            if original_finding.attack_type.value == "SQLi" and any(m in body for m in ["sql", "syntax", "mysql", "sqlite", "postgres", "ORA-"]):
                return True
            if original_finding.attack_type.value == "XSS" and any(m in body for m in ["<script", "alert(", "onerror", "onload"]):
                return True
            return False
        except Exception:
            return False

    async def _run_evolution(self, target, result):
        evolution_cfg = self.config.get("brain", {}).get("evolution", {})
        if not evolution_cfg.get("enabled", True):
            return
        bypass_findings = [f for f in result.findings if "brain:bypass" in (f.tags or [])]
        if not bypass_findings:
            return
        logger.info(f"[+] Evolution engine: {len(bypass_findings)} bypass finding(s) to analyze")
        try:
            from titan.brain.evolution import EvolutionEngine
            engine = EvolutionEngine()
            generated = 0
            for finding in bypass_findings[:5]:
                try:
                    detector_code = engine.generate(
                        finding_type=finding.attack_type.value,
                        pattern=finding.payload,
                        context=finding.notes or "",
                    )
                    if not detector_code:
                        continue
                    if not engine.validate(detector_code):
                        continue
                    if evolution_cfg.get("persist", True):
                        path = engine.write_detector(
                            detector_code,
                            name=f"auto_{finding.attack_type.value.lower()}_{generated}",
                        )
                        if path:
                            logger.info(f"    [+] Evolution: wrote detector to {path}")
                            generated += 1
                except Exception:
                    continue
            if generated:
                logger.info(f"[+] Evolution engine: {generated} detector(s) generated")
        except Exception as exc:
            result.errors.append(f"Evolution engine failed: {exc}")
            logger.warning(f"[!] Evolution engine: {exc}")

    async def _run_exploit_modules(self, target, result):
        cfg = self.config.get("exploit", {})
        if not cfg.get("enabled", False):
            return
        verified = [f for f in result.findings if f.verified]
        if not verified:
            return
        from pathlib import Path

        from titan.exploit.consent import ConsentError
        from titan.exploit.listener import ExploitListener
        from titan.exploit.planner import PlanningError, stage_and_register, usable_findings
        from titan.exploit.sqli_extractor import ExtractionError
        from titan.exploit.sqlidump import sqlidump, usable_sqli_findings
        from titan.exploit.ssrfpivot import PivotError, ssrf_pivot, usable_ssrf_findings
        from titan.exploit.upload_planner import stage_webshell, usable_upload_findings


        consent_dir = Path(cfg.get("consent_dir", "consent"))
        output_dir = Path(cfg.get("output_dir", "findings"))
        key_path = Path(cfg["key_path"]) if cfg.get("key_path") else None
        max_per_type = int(cfg.get("max_per_type", 2))
        budget = float(cfg.get("budget", 120))

        lcfg = cfg.get("listener", {})
        listener = ExploitListener(
            host=lcfg.get("host", "127.0.0.1"),
            port=int(lcfg.get("port", 8770)),
            nonce=lcfg.get("nonce"),
        )
        started = False
        if lcfg.get("start", False):
            try:
                await asyncio.wait_for(listener.start(), timeout=10)
                started = True
                logger.info(f"[+] Track E: listener up at {listener.bound_url}")
            except Exception as exc:
                result.errors.append(f"Track E listener failed to start: {exc}")
                logger.warning(f"[!] Track E: listener failed to start ({exc})")

        deadline = time.time() + budget
        sessions: list[dict[str, Any]] = []

        async def guarded(what, coro):
            remaining = deadline - time.time()
            if remaining <= 0:
                coro.close()
                return None
            try:
                return await asyncio.wait_for(coro, timeout=max(1.0, min(remaining, 60)))
            except (ConsentError, PlanningError, ExtractionError, PivotError, asyncio.TimeoutError) as exc:
                result.errors.append(f"Track E {what}: skipped ({exc})")
                logger.warning(f"    [!] Track E {what}: {exc}")
            except Exception as exc:
                result.errors.append(f"Track E {what}: failed ({exc})")
                logger.warning(f"    [!] Track E {what}: {exc}")
            return None

        def record(channel, store, extra=None):
            try:
                meta = store.read_meta()
            except Exception:
                meta = {}
            entry: dict[str, Any] = {
                "channel": channel, "session_id": store.session_id,
                "target": target, "status": meta.get("status", "active"),
                "dir": str(store.dir),
            }
            if extra:
                entry.update(extra)
            sessions.append(entry)
            logger.info(f"    [+] Track E: {channel} session {entry['session_id']} staged")

        for f in usable_findings(verified, target)[:max_per_type]:
            store = await guarded(
                f"RCE {f.method} {f.url}",
                stage_and_register(f, target, listener, consent_dir=consent_dir, output_dir=output_dir, key_path=key_path),
            )
            if store:
                record("rce-agent", store, {"finding_url": f.url})

        for f in usable_upload_findings(verified, target)[:max_per_type]:
            out = await guarded(
                f"upload {f.method} {f.url}",
                stage_webshell(f, target, listener, consent_dir=consent_dir, output_dir=output_dir, key_path=key_path),
            )
            if out:
                store, ws_url = out
                record("webshell", store, {"finding_url": f.url, "webshell_url": ws_url})

        for f in usable_sqli_findings(verified, target)[:max_per_type]:
            store = await guarded(
                f"sqli {f.method} {f.url}",
                sqlidump(f, target, consent_dir=consent_dir, output_dir=output_dir, key_path=key_path),
            )
            if store:
                record("sqli-extraction", store, {"finding_url": f.url})

        for f in usable_ssrf_findings(verified, target)[:max_per_type]:
            store = await guarded(
                f"ssrf {f.method} {f.url}",
                ssrf_pivot(f, target, consent_dir=consent_dir, output_dir=output_dir, key_path=key_path),
            )
            if store:
                record("ssrf-pivot", store, {"finding_url": f.url})

        if started:
            try:
                await asyncio.wait_for(listener.stop(), timeout=5)
            except Exception:
                pass
        result.exploit_sessions = sessions
        if sessions:
            logger.info(f"[+] Track E: {len(sessions)} exploitation session(s) staged")

    async def _run_fleet_scan(self, target, result):
        fleet_cfg = self.config.get("fleet", {})
        if not fleet_cfg.get("enabled", False):
            return
        try:
            from titan.fleet import AgentType, FleetCoordinator
        except ImportError:
            logger.warning("[!] Fleet module not available — skipping")
            return
        discovered = list(self.visited)[:5]
        targets = [target] + [u for u in discovered if u != target and self._is_in_scope(u)]
        targets = list(dict.fromkeys(targets))[:fleet_cfg.get("max_targets", 5)]
        agent_names = fleet_cfg.get("agents", ["recon", "identity", "learning"])
        agent_types = []
        for name in agent_names:
            try:
                agent_types.append(AgentType(name))
            except ValueError:
                pass
        if not agent_types:
            agent_types = [AgentType.RECON, AgentType.IDENTITY, AgentType.LEARNING]
        budget = fleet_cfg.get("budget", 120.0)
        logger.info(f"[+] Fleet scan: {len(targets)} target(s), {len(agent_types)} agent type(s), budget={budget}s")
        coordinator = FleetCoordinator(
            max_concurrent=fleet_cfg.get("max_concurrent", 5),
            consent_dir=self.config.get("exploit", {}).get("consent_dir", "consent"),
        )
        context = {"findings": result.findings, "fingerprint": result.fingerprint, "transport": self._transport_http}
        fleet_result = await coordinator.scan_all(targets=targets, agent_types=agent_types, budget=budget, context=context)
        fleet_count = 0
        for merged in fleet_result.merged_findings:
            exists = any(f.type == merged.type and f.url == merged.url and f.param == merged.param for f in result.findings)
            if not exists:
                try:
                    from titan.core.models import AttackType, Severity
                    severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                                    "medium": Severity.MEDIUM, "low": Severity.LOW}
                    finding = Finding(
                        type=AttackType(merged.type) if merged.type in [e.value for e in AttackType] else AttackType.OTHER,
                        severity=severity_map.get(merged.severity, Severity.MEDIUM),
                        title=f"[Fleet] {merged.type}: {merged.param or 'global'}",
                        url=merged.url, param=merged.param, evidence=merged.evidence,
                        confidence=merged.effective_confidence, cvss_score=merged.cvss_score,
                        tags=["fleet", f"sources:{','.join(merged.sources)}"],
                        metadata={"fleet_sources": merged.sources, "corroborated": merged.is_corroborated},
                    )
                    result.findings.append(finding)
                    fleet_count += 1
                except Exception:
                    pass
        if fleet_result.mutations:
            result.mutations = getattr(result, "mutations", []) + fleet_result.mutations
        if fleet_count:
            logger.info(f"[+] Fleet: {fleet_count} new finding(s) merged")

