"""LLM Deep Detector — Probe AI/ML models beyond prompt injection.

Detects RAG poisoning, tool-use hijacking, training data extraction,
model inversion, and adversarial suffix attacks.
"""

from titan.modules.llm_deep.detector import LLMDeepDetector

__all__ = ["LLMDeepDetector"]
