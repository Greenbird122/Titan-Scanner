"""Autonomous Brain Loop — The reasoning engine.

This is what makes Titan not just a scanner but a thinking red-team operator.
It observes, analyzes, plans, executes, verifies, chains, and learns — all
autonomously, with budget and depth constraints.

The loop:
  1. OBSERVE: What do we know about the target?
  2. ANALYZE: What are the highest-value next probes? (Thompson Sampling)
  3. PLAN: Generate targeted attack requests
  4. EXECUTE: Send probes via transport layer, collect evidence
  5. VERIFY: Apply evidence oracles, confirm/deny
  6. CHAIN: Connect findings into attack paths
  7. LEARN: Harvest mutations, generate new detectors
  8. DECIDE: Continue probing OR report to operator

Usage:
    from titan.brain.loop import BrainLoop

    brain = BrainLoop(target="https://target.com", consent=consent)
    result = await brain.run(max_iterations=100, budget=300)
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class Probe:
    """A planned probe to execute."""
    target: str
    module: str           # Which detector module to use
    attack_type: str      # What we're testing
    priority: float       # 0.0 - 1.0 (higher = more valuable)
    payload: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


@dataclass
class ProbeResult:
    """Result of executing a probe."""
    probe: Probe
    finding: dict | None = None
    verified: bool = False
    elapsed: float = 0.0
    error: str | None = None
    raw_response: Any = None


@dataclass
class BrainResult:
    """Final result of the brain loop."""
    findings: list[dict] = field(default_factory=list)
    chains: list[dict] = field(default_factory=list)
    mutations: list[dict] = field(default_factory=list)
    iterations: int = 0
    total_probes: int = 0
    duration: float = 0.0
    budget_used: float = 0.0
    module_stats: dict = field(default_factory=dict)


class BrainLoop:
    """The autonomous reasoning engine.

    Usage:
        brain = BrainLoop(
            target="https://target.com",
            transport=transport,          # Optional: specific transport
            module_runner=run_modules,    # Callable that runs detector modules
            consent=consent,              # Optional: consent object
        )
        result = await brain.run(max_iterations=100, budget=300)
    """

    def __init__(
        self,
        target: str,
        transport: Any = None,
        module_runner: Callable | None = None,
        consent: Any = None,
    ):
        self.target = target
        self.transport = transport
        self.module_runner = module_runner
        self.consent = consent

        # State
        self.knowledge: dict[str, Any] = {"target": target}
        self.findings: list[dict] = []
        self.chains: list[dict] = []
        self.mutations: list[dict] = []
        self._probe_history: list[ProbeResult] = []
        self._start_time = 0.0

        # Strategy (lazy init)
        self._strategy: Any = None

    @property
    def strategy(self):
        """Lazy-init the Thompson Sampling strategy."""
        if self._strategy is None:
            from titan.brain.strategy import ProbeStrategy
            self._strategy = ProbeStrategy()
        return self._strategy

    async def run(
        self,
        max_iterations: int = 100,
        budget: float = 300.0,
        depth_ceiling: float = 0.8,
    ) -> BrainResult:
        """Run the autonomous brain loop.

        Args:
            max_iterations: Maximum number of loop iterations.
            budget: Wall-clock time budget in seconds.
            depth_ceiling: Stop exploring when this fraction of budget is used (0.0-1.0).

        Returns:
            BrainResult with all findings, chains, and mutations.
        """
        self._start_time = time.time()
        iteration = 0

        logger.info(
            f"Brain loop starting: target={self.target}, "
            f"budget={budget}s, max_iter={max_iterations}"
        )

        while iteration < max_iterations:
            # Check budget
            elapsed = time.time() - self._start_time
            if elapsed > budget:
                logger.info(f"Budget exhausted: {elapsed:.1f}s > {budget}s")
                break

            iteration += 1

            # 1. OBSERVE — What do we know?
            state = self._observe()

            # 2. ANALYZE — What's the highest-value next probe?
            probes = self._analyze(state, depth_ceiling)

            if not probes:
                logger.info("No more probes — all surfaces explored")
                break

            # 3-4. EXECUTE — Run the probes
            remaining_budget = budget - (time.time() - self._start_time)
            results = await self._execute(probes, remaining_budget)

            # 5. VERIFY — Confirm or deny
            verified = self._verify(results)

            # 6. CHAIN — Connect into attack paths
            new_chains = self._chain(verified)

            # 7. LEARN — Harvest mutations
            new_mutations = self._learn(verified)

            # Update Thompson Sampling scores
            self._update_scores(probes, results)

            logger.info(
                f"Iteration {iteration}: "
                f"{len(verified)} verified, "
                f"{len(new_chains)} new chains, "
                f"{len(new_mutations)} mutations, "
                f"{time.time() - self._start_time:.1f}s elapsed"
            )

        result = BrainResult(
            findings=self.findings,
            chains=self.chains,
            mutations=self.mutations,
            iterations=iteration,
            total_probes=len(self._probe_history),
            duration=time.time() - self._start_time,
            budget_used=min(time.time() - self._start_time, budget),
            module_stats=self.strategy.get_module_stats(),
        )

        logger.info(
            f"Brain loop complete: "
            f"{len(result.findings)} findings, "
            f"{len(result.chains)} chains, "
            f"{result.iterations} iterations, "
            f"{result.duration:.1f}s"
        )
        return result

    def _observe(self) -> dict:
        """Gather current knowledge about the target."""
        return {
            "target": self.target,
            "findings_count": len(self.findings),
            "chains_count": len(self.chains),
            "probes_run": len(self._probe_history),
            "modules_tried": list(self.strategy.scores.keys()),
            "elapsed": time.time() - self._start_time,
        }

    def _analyze(self, state: dict, depth_ceiling: float) -> list[Probe]:
        """Select highest-value next probes using Thompson Sampling.

        Strategy:
          1. No findings yet → broad reconnaissance (all modules)
          2. Has findings, no chains → depth on high-severity modules
          3. Has chains → complete chain gaps
          4. Depth ceiling hit → reduce exploration
        """
        all_modules = self._get_available_modules()

        if state["findings_count"] == 0:
            # Phase 1: Broad recon — sample from all modules
            if self.strategy.should_explore(0.3):
                # Pure exploration: try modules we haven't tried yet
                untried = [m for m in all_modules if m not in self.strategy.scores]
                if untried:
                    selected = self.strategy.select_next(untried, n=min(5, len(untried)))
                else:
                    selected = self.strategy.select_next(all_modules, n=5)
            else:
                selected = self.strategy.select_next(all_modules, n=5)

            return [
                Probe(
                    target=self.target,
                    module=module,
                    attack_type=self._module_to_attack_type(module),
                    priority=0.8,
                )
                for module in selected
            ]

        elif state["chains_count"] == 0:
            # Phase 2: Depth on high-value findings
            probes = []
            for finding in sorted(
                self.findings,
                key=lambda f: f.get("cvss_score", 0) or 0,
                reverse=True,
            )[:5]:
                if (finding.get("cvss_score") or 0) >= 7.0:
                    probes.append(Probe(
                        target=self.target,
                        module="exploit",
                        attack_type=finding.get("type", "unknown"),
                        priority=0.95,
                        payload={"finding": finding},
                    ))

            # Also continue exploring with remaining budget
            if not probes:
                selected = self.strategy.select_next(all_modules, n=3)
                probes = [
                    Probe(
                        target=self.target,
                        module=module,
                        attack_type=self._module_to_attack_type(module),
                        priority=0.7,
                    )
                    for module in selected
                ]

            return probes

        else:
            # Phase 3: Chain completion — probe for missing flows
            probes = []
            for chain in self.chains:
                if chain.get("status") == "incomplete":
                    missing_flow = chain.get("missing_flow")
                    if missing_flow:
                        probes.append(Probe(
                            target=self.target,
                            module=self._flow_to_module(missing_flow),
                            attack_type=missing_flow,
                            priority=0.9,
                            payload={"chain": chain},
                        ))

            # If no chain gaps, keep exploring
            if not probes:
                selected = self.strategy.select_next(all_modules, n=3)
                probes = [
                    Probe(
                        target=self.target,
                        module=module,
                        attack_type=self._module_to_attack_type(module),
                        priority=0.6,
                    )
                    for module in selected
                ]

            return probes

    async def _execute(self, probes: list[Probe], remaining_budget: float) -> list[ProbeResult]:
        """Execute probes and collect results.

        If a module_runner is provided, it's called with the probe details.
        Otherwise, probes are executed via the transport layer directly.
        """
        results = []

        for probe in probes:
            # Check budget per probe
            elapsed = time.time() - self._start_time
            if elapsed > remaining_budget:
                break

            start = time.time()
            try:
                if self.module_runner:
                    # Use the provided module runner (real detector modules)
                    finding = await asyncio.wait_for(
                        self.module_runner(
                            module=probe.module,
                            target=probe.target,
                            attack_type=probe.attack_type,
                            payload=probe.payload,
                        ),
                        timeout=min(30.0, remaining_budget - (time.time() - self._start_time)),
                    )
                    result = ProbeResult(
                        probe=probe,
                        finding=finding,
                        elapsed=time.time() - start,
                    )
                elif self.transport:
                    # Use transport layer directly
                    from titan.transport import AttackRequest, RequestMethod
                    response = await self.transport.send(AttackRequest(
                        url=probe.target,
                        method=RequestMethod.GET,
                        timeout=15.0,
                    ))
                    result = ProbeResult(
                        probe=probe,
                        raw_response=response,
                        elapsed=time.time() - start,
                    )
                else:
                    # No runner or transport — record the probe but can't execute
                    result = ProbeResult(
                        probe=probe,
                        elapsed=time.time() - start,
                        error="No module_runner or transport configured",
                    )

                results.append(result)
                self._probe_history.append(result)

            except asyncio.TimeoutError:
                results.append(ProbeResult(
                    probe=probe,
                    elapsed=time.time() - start,
                    error="Probe timed out",
                ))
            except Exception as e:
                results.append(ProbeResult(
                    probe=probe,
                    elapsed=time.time() - start,
                    error=str(e),
                ))

        return results

    def _verify(self, results: list[ProbeResult]) -> list[ProbeResult]:
        """Apply evidence oracles to confirm or deny findings.

        A finding is verified when:
          1. It has a non-null finding dict with evidence
          2. It has a named oracle marker (not just reflection)
          3. It passes the evidence gate (tier >= confirmed)
        """
        verified = []
        for result in results:
            if result.finding and not result.error:
                # Check for evidence quality
                evidence = result.finding.get("evidence", "")
                oracle = result.finding.get("oracle", "")
                tier = result.finding.get("tier", "suspicious")

                # A finding is verified if it has evidence AND an oracle marker
                # OR if it's already marked as confirmed by the module
                if (evidence and oracle) or tier == "confirmed":
                    result.verified = True
                    verified.append(result)
                    self.findings.append(result.finding)

                    # Update knowledge
                    self.knowledge[f"finding_{len(self.findings)}"] = result.finding

        return verified

    def _chain(self, verified: list[ProbeResult]) -> list[dict]:
        """Connect verified findings into attack paths.

        Chains are composed when findings have compatible flow types:
          - creds + url_fetch → credential chain
          - creds + auth_bypass → privilege escalation
          - url_fetch + code_exec → SSRF to RCE
          - file_read + data_leak → data exfiltration
        """
        new_chains = []

        # Flow compatibility matrix
        chain_patterns = [
            ({"creds", "url_fetch"}, "credential_chain", "data_exfil"),
            ({"creds", "auth_bypass"}, "privilege_escalation", "admin_access"),
            ({"url_fetch", "code_exec"}, "ssrf_to_rce", "remote_code_exec"),
            ({"file_read", "data_leak"}, "data_exfiltration", "sensitive_data"),
            ({"url_fetch", "creds"}, "ssrf_to_creds", "cloud_credential_exposure"),
        ]

        for result in verified:
            if not result.finding:
                continue

            finding_flows = set(result.finding.get("flow_types", []))

            for required_flows, chain_type, goal in chain_patterns:
                # Check if this finding contributes to a chain
                if finding_flows & required_flows:
                    # Look for existing chains to extend
                    extended = False
                    for chain in self.chains:
                        if chain.get("chain_type") == chain_type:
                            # Add this finding to the chain
                            if result.finding not in chain.get("steps", []):
                                chain["steps"].append(result.finding)
                                chain["status"] = "complete"
                                chain["confidence"] = min(
                                    chain.get("confidence", 0.5) + 0.15, 0.99
                                )
                                extended = True
                                break

                    if not extended:
                        # Start a new chain
                        chain = {
                            "chain_type": chain_type,
                            "attack_goal": goal,
                            "steps": [result.finding],
                            "status": "incomplete",
                            "missing_flow": self._find_missing_flow(
                                required_flows, finding_flows
                            ),
                            "confidence": 0.5,
                        }
                        if chain["missing_flow"] is None:
                            chain["status"] = "complete"
                            chain["confidence"] = 0.7

                        new_chains.append(chain)
                        self.chains.append(chain)

        return new_chains

    def _learn(self, verified: list[ProbeResult]) -> list[dict]:
        """Harvest mutations from verified findings.

        If a finding was detected by a probe that no existing module covers,
        the mutation is recorded for potential detector generation.
        """
        mutations = []
        known_modules = self._get_available_modules()

        for result in verified:
            if not result.finding:
                continue

            finding_type = result.finding.get("type", "")
            module = result.probe.module

            # A mutation is when a module found something outside its normal scope
            # OR when a finding type isn't covered by any known module
            if finding_type and finding_type not in known_modules:
                mutation = {
                    "finding_type": finding_type,
                    "detection_pattern": result.finding.get("evidence", ""),
                    "attack_type": result.probe.attack_type,
                    "severity": result.finding.get("severity", "medium"),
                    "source_module": module,
                    "confidence": result.finding.get("confidence", 0.5),
                }
                mutations.append(mutation)
                self.mutations.append(mutation)

                logger.info(
                    f"Mutation harvested: {finding_type} "
                    f"(from {module}, severity={mutation['severity']})"
                )

        return mutations

    def _update_scores(self, probes: list[Probe], results: list[ProbeResult]):
        """Update Thompson Sampling scores for modules."""
        for probe, result in zip(probes, results):
            success = result.verified and result.finding is not None
            value = 0.0
            if success and result.finding:
                value = result.finding.get("cvss_score", 5.0) or 5.0

            self.strategy.record_result(probe.module, success=success, value=value)

    def _get_available_modules(self) -> list[str]:
        """List of all available detector modules."""
        return [
            "headers", "sqli", "xss", "ssrf", "lfi", "rce",
            "nosqli", "ssti", "xxe", "idor", "bola", "massassignment",
            "jwt", "sessionfix", "auth", "cors", "redirect", "upload",
            "race", "cache", "smuggling", "logic", "crypto", "deser",
            "fuzzer", "parserdiff", "sourcesecret", "apixss",
            "domxss", "postmessage", "prototype", "thirdparty", "csp",
            "cloud_control", "supplychain",
        ]

    def _module_to_attack_type(self, module: str) -> str:
        """Map a module name to its attack type."""
        mapping = {
            "headers": "info_leak",
            "sqli": "injection",
            "xss": "xss",
            "ssrf": "ssrf",
            "lfi": "file_read",
            "rce": "code_exec",
            "nosqli": "injection",
            "ssti": "template_injection",
            "xxe": "xxe",
            "idor": "idor",
            "bola": "authorization",
            "massassignment": "mass_assignment",
            "jwt": "auth_bypass",
            "sessionfix": "session_fixation",
            "auth": "auth_bypass",
            "cors": "misconfiguration",
            "redirect": "open_redirect",
            "upload": "file_upload",
            "race": "race_condition",
            "cache": "cache_poisoning",
            "smuggling": "request_smuggling",
            "logic": "business_logic",
            "crypto": "weak_crypto",
            "deser": "deserialization",
            "fuzzer": "fuzzing",
            "parserdiff": "parser_differential",
            "sourcesecret": "secret_exposure",
            "apixss": "xss",
            "domxss": "xss",
            "postmessage": "xss",
            "prototype": "prototype_pollution",
            "thirdparty": "supply_chain",
            "csp": "misconfiguration",
            "cloud_control": "cloud_misconfig",
            "supplychain": "supply_chain",
        }
        return mapping.get(module, "unknown")

    def _flow_to_module(self, flow_type: str) -> str:
        """Map a flow type to a detector module."""
        mapping = {
            "url_fetch": "ssrf",
            "creds": "cloud_control",
            "auth_bypass": "auth",
            "code_exec": "rce",
            "data_leak": "idor",
            "file_read": "lfi",
            "oob": "ssrf",
            "client_exec": "domxss",
            "model_control": "llm",
        }
        return mapping.get(flow_type, "fuzzer")

    def _find_missing_flow(self, required: set, have: set) -> str | None:
        """Find which flow type is missing from a chain."""
        missing = required - have
        return missing.pop() if missing else None
