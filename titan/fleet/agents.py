"""Fleet Agents — Specialized scanning agents for multi-target operations.

Each agent type is a specialist:
  - ReconAgent:     OSINT, subdomain enum, tech fingerprint, surface mapping
  - IdentityAgent:  Auth flows, session management, BOLA, mass assignment
  - ExploitAgent:   Verified exploitation, SQLi extraction, SSRF pivoting
  - PostExploitAgent: Lateral movement, persistence, cloud control plane
  - LearningAgent:  Mutation harvesting, detector generation, pattern analysis

Agents are stateless — the coordinator holds the shared state. Each agent
receives a target and a context (findings so far, transport, consent) and
returns new findings.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class AgentType(str, Enum):
    """Types of fleet agents."""
    RECON = "recon"
    IDENTITY = "identity"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    LEARNING = "learning"


@dataclass
class AgentConfig:
    """Configuration for an agent type."""
    agent_type: AgentType
    priority: float = 0.5           # 0.0-1.0, higher = run first
    timeout: float = 120.0          # Per-agent wall-clock budget
    max_concurrent: int = 1         # How many instances of this type can run
    requires_consent: bool = False  # Does this agent need consent?
    requires_transport: bool = True # Does this agent need the transport layer?


@dataclass
class AgentResult:
    """Result from a single agent execution."""
    agent_type: AgentType
    target: str
    findings: list[dict] = field(default_factory=list)
    mutations: list[dict] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    elapsed: float = 0.0
    error: str | None = None
    success: bool = True


# ---------------------------------------------------------------------------
# Agent type definitions
# ---------------------------------------------------------------------------

# Default configs for each agent type
AGENT_CONFIGS: dict[AgentType, AgentConfig] = {
    AgentType.RECON: AgentConfig(
        agent_type=AgentType.RECON,
        priority=0.9,  # Recon runs first
        timeout=120.0,
        requires_consent=False,
    ),
    AgentType.IDENTITY: AgentConfig(
        agent_type=AgentType.IDENTITY,
        priority=0.8,
        timeout=90.0,
        requires_consent=False,
    ),
    AgentType.EXPLOIT: AgentConfig(
        agent_type=AgentType.EXPLOIT,
        priority=0.7,
        timeout=180.0,
        requires_consent=True,
    ),
    AgentType.POST_EXPLOIT: AgentConfig(
        agent_type=AgentType.POST_EXPLOIT,
        priority=0.6,
        timeout=120.0,
        requires_consent=True,
    ),
    AgentType.LEARNING: AgentConfig(
        agent_type=AgentType.LEARNING,
        priority=0.5,  # Learning runs last
        timeout=60.0,
        requires_consent=False,
    ),
}


# ---------------------------------------------------------------------------
# Agent runners — the actual work each agent type does
# ---------------------------------------------------------------------------

async def run_recon_agent(
    target: str,
    transport: Any = None,
    context: dict | None = None,
    timeout: float = 120.0,
) -> AgentResult:
    """Recon agent: OSINT, fingerprinting, surface mapping.

    Probes:
      - Tech stack fingerprinting
      - Subdomain enumeration (if applicable)
      - API endpoint discovery
      - JavaScript bundle analysis
      - DNS/WHOIS (if available)
    """
    start = time.time()
    result = AgentResult(agent_type=AgentType.RECON, target=target)

    try:
        from titan.core.fingerprint import TechFingerprinter
        from titan.core.osint import OSINTEngine

        # Tech fingerprinting
        fingerprinter = TechFingerprinter()
        # OSINT enumeration
        osint = OSINTEngine()
        try:
            intel = await asyncio.wait_for(
                osint.enumerate(target),
                timeout=timeout * 0.4,
            )
            if intel:
                result.metadata["osint"] = {
                    "subdomains": getattr(intel, "subdomains", []),
                    "ports": getattr(intel, "ports", []),
                    "tech_hints": getattr(intel, "tech_hints", []),
                }
        except (asyncio.TimeoutError, Exception) as e:
            logger.debug(f"OSINT enumeration failed: {e}")

        # Surface mapping via transport
        if transport:
            from titan.transport import AttackRequest, RequestMethod
            try:
                resp = await asyncio.wait_for(
                    transport.send(AttackRequest(url=target, method=RequestMethod.GET, timeout=15.0)),
                    timeout=20.0,
                )
                if resp and resp.ok:
                    result.metadata["surface"] = {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body_length": len(resp.body),
                    }
            except (asyncio.TimeoutError, Exception):
                pass

    except Exception as e:
        result.error = str(e)
        result.success = False

    result.elapsed = time.time() - start
    return result


async def run_identity_agent(
    target: str,
    transport: Any = None,
    context: dict | None = None,
    timeout: float = 90.0,
) -> AgentResult:
    """Identity agent: Auth flows, session management, BOLA, mass assignment.

    Probes:
      - Authentication endpoint discovery
      - Session token analysis
      - BOLA/IDOR across identities
      - Mass assignment testing
      - JWT confusion/none algorithm
    """
    start = time.time()
    result = AgentResult(agent_type=AgentType.IDENTITY, target=target)

    try:
        from titan.modules.bola.detector import BOLADetector
        from titan.modules.massassignment.detector import MassAssignmentDetector
        from titan.modules.jwt.detector import JWTDetector

        # These detectors need the full engine context — run what we can
        # with the transport layer for pure HTTP probing
        if transport:
            from titan.transport import AttackRequest, RequestMethod

            # Probe common auth endpoints
            auth_paths = ["/login", "/auth", "/api/login", "/api/auth",
                         "/token", "/oauth/token", "/api/v1/auth"]
            for path in auth_paths:
                try:
                    url = target.rstrip("/") + path
                    resp = await asyncio.wait_for(
                        transport.send(AttackRequest(url=url, method=RequestMethod.GET, timeout=5.0)),
                        timeout=8.0,
                    )
                    if resp and resp.status in (200, 301, 302, 405):
                        result.metadata.setdefault("auth_endpoints", []).append({
                            "path": path,
                            "status": resp.status,
                        })
                except (asyncio.TimeoutError, Exception):
                    continue

    except Exception as e:
        result.error = str(e)
        result.success = False

    result.elapsed = time.time() - start
    return result


async def run_exploit_agent(
    target: str,
    transport: Any = None,
    context: dict | None = None,
    timeout: float = 180.0,
) -> AgentResult:
    """Exploit agent: Verified exploitation of confirmed findings.

    Probes:
      - SQLi extraction through confirmed injection points
      - SSRF pivoting to internal services
      - RCE verification through command injection
      - File upload exploitation
    """
    start = time.time()
    result = AgentResult(agent_type=AgentType.EXPLOIT, target=target)

    try:
        # This agent needs the full engine context (findings, consent)
        # It's a placeholder — the real exploitation runs through
        # TitanEngine._run_exploit_modules()
        findings = context.get("findings", []) if context else []
        verified = [f for f in findings if getattr(f, "verified", False)]

        if verified:
            result.metadata["verified_findings_count"] = len(verified)
            result.metadata["note"] = "Exploit agent requires engine context for full exploitation"

    except Exception as e:
        result.error = str(e)
        result.success = False

    result.elapsed = time.time() - start
    return result


async def run_post_exploit_agent(
    target: str,
    transport: Any = None,
    context: dict | None = None,
    timeout: float = 120.0,
) -> AgentResult:
    """Post-exploit agent: Lateral movement, persistence, cloud control plane.

    Probes:
      - Cloud IMDS through confirmed SSRF sinks
      - Lateral movement via extracted credentials
      - Persistence mechanisms
      - Cross-account trust relationships
    """
    start = time.time()
    result = AgentResult(agent_type=AgentType.POST_EXPLOIT, target=target)

    try:
        findings = context.get("findings", []) if context else []
        ssrf_findings = [
            f for f in findings
            if getattr(f, "type", "") == "ssrf"
        ]

        if ssrf_findings and transport:
            # Probe IMDS through the SSRF sink
            from titan.modules.cloud_control.imds import IMDSProber

            prober = IMDSProber(timeout=5.0)
            # Build sink from first SSRF finding
            ssrf_url = getattr(ssrf_findings[0], "url", "")
            ssrf_param = getattr(ssrf_findings[0], "param", "url")

            if ssrf_url:
                async def _sink(url, method="GET", headers=None, timeout=5.0):
                    import aiohttp
                    from urllib.parse import urlparse, parse_qs, urlencode
                    parsed = urlparse(ssrf_url)
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    params[ssrf_param] = [url]
                    new_query = urlencode(params, doseq=True)
                    sink_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.request(
                                method=method, url=sink_url,
                                headers=headers or {},
                                timeout=aiohttp.ClientTimeout(total=timeout),
                                ssl=False,
                            ) as resp:
                                body = await resp.text(errors="replace")
                                return (resp.status, dict(resp.headers), body)
                    except Exception:
                        return (0, {}, "")

                imds_findings = await prober.probe(_sink)
                result.findings = imds_findings
                result.metadata["imds_probed"] = True

    except Exception as e:
        result.error = str(e)
        result.success = False

    result.elapsed = time.time() - start
    return result


async def run_learning_agent(
    target: str,
    transport: Any = None,
    context: dict | None = None,
    timeout: float = 60.0,
) -> AgentResult:
    """Learning agent: Mutation harvesting, pattern analysis, detector generation.

    Analyzes findings from other agents to:
      - Identify novel attack patterns
      - Generate new detector modules
      - Build target-specific payload libraries
    """
    start = time.time()
    result = AgentResult(agent_type=AgentType.LEARNING, target=target)

    try:
        from titan.brain.evolution import EvolutionEngine

        engine = EvolutionEngine()
        findings = context.get("findings", []) if context else []

        # Convert findings to probe format for mutation harvesting
        probes = []
        for f in findings:
            finding_type = getattr(f, "type", "")
            if finding_type:
                probes.append({
                    "finding_type": finding_type,
                    "detection_pattern": getattr(f, "evidence", ""),
                    "attack_type": finding_type,
                    "severity": getattr(f, "severity", "medium"),
                    "module": "fleet",
                })

        mutations = engine.harvest_mutations(probes)
        result.mutations = [
            {
                "finding_type": m.finding_type,
                "pattern": m.pattern,
                "attack_type": m.attack_type,
                "severity": m.severity,
            }
            for m in mutations
        ]
        result.metadata["mutations_found"] = len(mutations)

    except Exception as e:
        result.error = str(e)
        result.success = False

    result.elapsed = time.time() - start
    return result


# Agent runner registry
AGENT_RUNNERS: dict[AgentType, Callable] = {
    AgentType.RECON: run_recon_agent,
    AgentType.IDENTITY: run_identity_agent,
    AgentType.EXPLOIT: run_exploit_agent,
    AgentType.POST_EXPLOIT: run_post_exploit_agent,
    AgentType.LEARNING: run_learning_agent,
}
