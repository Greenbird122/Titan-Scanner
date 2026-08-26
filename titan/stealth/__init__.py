"""Titan Stealth — Advanced evasion and anti-forensics.

Traffic shaping, polymorphic payloads, decoy injection,
and encrypted C2 channels.
"""

from titan.stealth.advanced import (
    AntiForensics,
    TrafficShaper,
    PolymorphicEngine,
    DecoyGenerator,
    FingerprintRandomizer,
)

__all__ = [
    "AntiForensics",
    "TrafficShaper",
    "PolymorphicEngine",
    "DecoyGenerator",
    "FingerprintRandomizer",
]
