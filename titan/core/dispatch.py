"""Multi-role, session replay, and verification glue for TitanEngine.

Extracted from titan/core/engine.py. Supplies the additional-role scan
pass, authenticated session replay of gated routes, and the verification /
evidence-gate phase (oracles, auto-verify, role-aware adjustment, chain
analysis, inference, AI escalation). State the runners read stays on the
host engine; this mixin only supplies behavior.
"""

from __future__ import annotations

import asyncio
from typing import Any

from titan.core.logger import get_logger
from titan.core.sessions import Identity
from titan.verify.flows import apply_flows
from titan.verify.role_aware import RoleAwareScanner

logger = get_logger("dispatch")


class DispatchMixin:
    """Multi-role, session replay, and verification phases for TitanEngine."""

    # State supplied by the host engine before any mixin method runs.
    config: dict
    visited: Any
    _driver_dead: bool
    _gated_routes: Any
    _coverage: dict[str, Any]
    _crawl_context: Any
    _platform_brain: Any
    auth_engine: Any
    _role_scanner: Any
    session_pool: Any
    _modules: Any
    _transport_send: Any

    # ==================================================================

    # Multi-role, session replay, optional phases

    # ==================================================================



    async def _run_multi_role(self, context, page, target, fingerprint, result):

        roles = self.config.get("auth", {}).get("roles", [])

        if not roles or self._driver_dead:

            return

        logger.info(f"[+] Testing {len(roles)} additional roles...")

        for role_creds in roles:

            try:

                await self.auth_engine.logout(context, page, target)

                logged_in = await self.auth_engine.login_as_role(context, page, target, role_creds)

                if logged_in:

                    role_name = role_creds.get("role", "unknown")

                    logger.info(f"[+] Scanning as role: {role_name}")

                    self._role_scanner.record_role(role_name)

                    auth_headers = self.auth_engine.get_auth_headers()

                    if auth_headers:

                        await context.set_extra_http_headers(auth_headers)

                    self.session_pool.add(Identity(

                        name=role_name, headers=dict(auth_headers),

                        cookies=self.auth_engine.get_cookies(),

                    ))

                    for visited_url in list(self.visited)[:10]:

                        try:

                            api_findings = await asyncio.wait_for(

                                self._modules._run_api_modules(context, target, visited_url, {}),

                                timeout=15,

                            )

                            for f in api_findings:

                                f.tags = f.tags + [f"role:{role_name}"]

                            result.findings.extend(api_findings)

                        except Exception as exc:
                            logger.debug(f"variant failed, continuing: {exc}")

                            continue

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")

                continue



    async def _run_session_replay(self, context, target, result):

        if not self._gated_routes or self._driver_dead:

            return

        replay_count = 0

        replay_limit = min(len(self._gated_routes), 10)

        logger.info(f"[+] Session replay: re-scanning {replay_limit} gated routes with auth...")

        for gated_url in list(self._gated_routes)[:replay_limit]:

            try:

                _auth_hdrs = dict(self.auth_engine.get_auth_headers() or {})

                t_resp = await self._transport_send(gated_url, headers=_auth_hdrs, timeout=10.0)

                gated_status = 0

                if t_resp and not t_resp.is_error:

                    gated_status = t_resp.status

                else:

                    gated_resp = await asyncio.wait_for(

                        context.request.get(gated_url, timeout=10000), timeout=15,

                    )

                    if gated_resp:

                        gated_status = gated_resp.status

                if gated_status == 200:

                    logger.info(f"    [+] REPLAY {gated_url} → {gated_status} (was 401/403, now open)")

                    replay_findings = await asyncio.wait_for(

                        self._modules._run_api_modules(context, target, gated_url, {}),

                        timeout=15,

                    )

                    for f in replay_findings:

                        f.tags = f.tags + ["scope:auth", "replay:true"]

                    result.findings.extend(replay_findings)

                    replay_count += 1

            except Exception as exc:
                logger.debug(f"variant failed, continuing: {exc}")

                continue

        if replay_count:

            logger.info(f"    [i] Session replay: {replay_count} routes re-opened with auth")

        self._coverage["replayed_gated"] = replay_count



    # ==================================================================

    # Verification & evidence gates

    # ==================================================================



    async def _run_verification(self, result):

        from titan.verify.oracles import enforce_evidence

        ev_stats = enforce_evidence(result.findings)

        if ev_stats.get("demoted"):

            logger.warning(f"[!] Evidence gate: demoted {ev_stats['demoted']} verified finding(s)")



        from titan.verify.auto_verify import AutoVerifier

        av = AutoVerifier()

        if getattr(self, "_crawl_context", None):

            verified_count = 0

            demoted_count = 0

            for f in result.findings:

                if f.verified and f.confidence >= 0.5:

                    original_verified = f.verified

                    await av.verify_finding(self._crawl_context, f)

                    if original_verified and not f.verified:

                        demoted_count += 1

                    elif f.verified:

                        verified_count += 1

            if demoted_count:

                logger.warning(f"[!] Auto-verify: demoted {demoted_count} finding(s)")

            if verified_count:

                logger.info(f"[+] Auto-verify: {verified_count} finding(s) passed")



        role_scanner = getattr(self, "_role_scanner", None)

        if isinstance(role_scanner, RoleAwareScanner):

            role_adjusted = 0

            for f in result.findings:

                if getattr(f, "verified", False):

                    role_scanner.adjust_finding(f)

                    if getattr(f, "metadata", {}).get("role_gated"):

                        role_adjusted += 1

            if role_adjusted:

                logger.info(f"[i] Role-aware: adjusted {role_adjusted} finding(s)")



        platform_brain = getattr(self, "_platform_brain", None)

        if platform_brain is not None:

            for f in result.findings:

                try:

                    platform_brain.tag_finding(f)

                except Exception as exc:
                    logger.debug(f"suppressed exception: {exc}")

                    pass



        apply_flows(result.findings)



        try:

            from titan.verify.chain_analyzer import ChainAnalyzer

            chains = ChainAnalyzer().detect(result.findings)

            result.chains = [c.to_dict() for c in chains]

            for chain in chains:

                for f in chain.hops:

                    others = [h.url for h in chain.hops if h is not f]

                    if others:

                        f.chain = list(dict.fromkeys(others))

            if chains:

                logger.info(f"[+] Track D: {len(chains)} attack chains composed")

        except Exception as exc:

            result.errors.append(f"Chain analysis failed: {exc}")



        try:

            from titan.verify.inference import CrossDataInferenceEngine

            inf_engine = CrossDataInferenceEngine()

            result.inferences = [i.to_dict() for i in inf_engine.infer(result.findings)]

            if result.inferences:

                logger.info(f"[+] Inference: {len(result.inferences)} cross-data inference(s)")

        except Exception as exc:

            result.errors.append(f"Inference failed: {exc}")



        ai_cfg = self.config.get("ai", {})

        if ai_cfg.get("escalate", {}).get("enabled", False):

            try:

                from titan.verify.ai_escalation import AIEscalator

                esc = AIEscalator(ai_cfg)

                result.ai_escalation = await esc.escalate(result.findings)

                logger.info(f"[+] AI escalation: {result.ai_escalation.get('sent', 0)} sent")

            except Exception as exc:

                result.errors.append(f"AI escalation failed: {exc}")



