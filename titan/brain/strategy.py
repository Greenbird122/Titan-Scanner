"""Probe Selection Strategy — Thompson Sampling for module selection.

Uses Bayesian optimization to select the highest-value next probe.
Balances exploration (trying new modules) with exploitation
(focusing on modules that found things before).

The math:
  Each module is modeled as a Beta(alpha, beta) distribution.
  alpha = successes + 1  (prior successes)
  beta  = failures + 1   (prior failures)

  Thompson Sampling draws a sample from each module's Beta distribution
  and selects the module with the highest sample. This naturally:
    - Explores modules with high uncertainty (few attempts)
    - Exploits modules with high success rates
"""

from __future__ import annotations

import logging
import math
import random
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ModuleScore:
    """Score for a detector module."""
    name: str
    successes: int = 0
    attempts: int = 0
    total_value: float = 0.0  # Sum of CVSS scores from findings

    @property
    def sample_rate(self) -> float:
        """Beta distribution parameter alpha."""
        return self.successes + 1

    @property
    def fail_rate(self) -> float:
        """Beta distribution parameter beta."""
        return self.attempts - self.successes + 1

    @property
    def average_value(self) -> float:
        """Average CVSS value per finding."""
        return self.total_value / max(self.successes, 1)

    def thompson_sample(self) -> float:
        """Draw a sample from the Beta(alpha, beta) distribution.

        Uses the relationship: Beta(a,b) = Gamma(a,1) / (Gamma(a,1) + Gamma(b,1))
        with Marsaglia & Tsang's method for Gamma sampling.
        """
        alpha = self.sample_rate
        beta = self.fail_rate
        x = self._gamma_sample(alpha)
        y = self._gamma_sample(beta)
        return x / (x + y) if (x + y) > 0 else 0.0

    @staticmethod
    def _gamma_sample(alpha: float) -> float:
        """Sample from Gamma(alpha, 1) using Marsaglia and Tsang's method."""
        if alpha < 1:
            # For alpha < 1, use the relation: Gamma(a) = Gamma(a+1) * U^(1/a)
            # where U ~ Uniform(0,1)
            return ModuleScore._gamma_sample(alpha + 1.0) * (random.random() ** (1.0 / alpha))

        # Ahrens-Dieter method for alpha >= 1
        d = alpha - 1.0 / 3.0
        c = 1.0 / math.sqrt(9.0 * d)

        while True:
            while True:
                x = random.gauss(0, 1)
                v = 1.0 + c * x
                if v > 0:
                    break

            v = v * v * v
            u = random.random()

            if u < 1 - 0.0331 * (x * x) * (x * x):
                return d * v

            if math.log(u) < 0.5 * x * x + d * (1 - v + math.log(v)):
                return d * v


class ProbeStrategy:
    """Thompson Sampling strategy for probe selection.

    Each detector module is modeled as a Beta distribution.
    The module with the highest Thompson sample gets selected next.

    This naturally balances:
      - Exploration: Modules with few attempts get sampled (uncertainty)
      - Exploitation: Modules with high success rates get sampled more

    Usage:
        strategy = ProbeStrategy()

        # Record results as probes run
        strategy.record_result("sqli", success=True, value=9.0)
        strategy.record_result("xss", success=False)

        # Select next modules
        top_modules = strategy.select_next(available_modules, n=3)
    """

    def __init__(self):
        self.scores: dict[str, ModuleScore] = {}
        self._history: list[dict] = []

    def record_result(self, module: str, success: bool, value: float = 0.0):
        """Record a probe result for a module."""
        if module not in self.scores:
            self.scores[module] = ModuleScore(name=module)

        score = self.scores[module]
        score.attempts += 1
        if success:
            score.successes += 1
            score.total_value += value

        self._history.append({
            "module": module,
            "success": success,
            "value": value,
        })

    def select_next(self, available_modules: list[str], n: int = 1) -> list[str]:
        """Select the next N modules to run using Thompson Sampling."""
        samples = []

        for module in available_modules:
            score = self.scores.get(module, ModuleScore(name=module))
            sample = score.thompson_sample()
            samples.append((module, sample))

        # Sort by Thompson sample (highest first)
        samples.sort(key=lambda x: x[1], reverse=True)

        return [module for module, _ in samples[:n]]

    def get_ranking(self, available_modules: list[str]) -> list[tuple[str, float]]:
        """Get the current ranking of modules by estimated value."""
        ranking = []

        for module in available_modules:
            score = self.scores.get(module, ModuleScore(name=module))
            ranking.append((module, score.average_value))

        ranking.sort(key=lambda x: x[1], reverse=True)
        return ranking

    def should_explore(self, exploration_rate: float = 0.2) -> bool:
        """Should we explore (try a random module) or exploit (use the best)?"""
        return random.random() < exploration_rate

    def get_module_stats(self) -> dict[str, dict]:
        """Get stats for all modules (for debugging/reporting)."""
        stats = {}
        for name, score in self.scores.items():
            stats[name] = {
                "successes": score.successes,
                "attempts": score.attempts,
                "success_rate": score.successes / max(score.attempts, 1),
                "avg_value": score.average_value,
            }
        return stats
