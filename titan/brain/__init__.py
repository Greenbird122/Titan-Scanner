"""Titan Brain — Autonomous reasoning and self-evolution.

The brain loop is what makes Titan think, not just scan.
It selects probes, verifies findings, chains exploits,
and learns from every engagement.

Usage:
    from titan.brain import BrainLoop, EvolutionEngine, ProbeStrategy

    brain = BrainLoop(target="https://target.com")
    result = await brain.run(budget=300)
"""

from titan.brain.loop import BrainLoop, BrainResult, Probe, ProbeResult
from titan.brain.evolution import EvolutionEngine, Mutation, DetectorModule
from titan.brain.strategy import ProbeStrategy, ModuleScore

__all__ = [
    "BrainLoop",
    "BrainResult",
    "Probe",
    "ProbeResult",
    "EvolutionEngine",
    "Mutation",
    "DetectorModule",
    "ProbeStrategy",
    "ModuleScore",
]
