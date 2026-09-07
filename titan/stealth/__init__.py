"""Titan Stealth — Advanced evasion and anti-forensics.

Traffic shaping, polymorphic payloads, decoy injection,
and encrypted C2 channels.
"""

from titan.stealth.advanced import (
    AntiForensics,
    DecoyGenerator,
    FingerprintRandomizer,
    PolymorphicEngine,
    TrafficShaper,
)

__all__ = [
    "AntiForensics",
    "DecoyGenerator",
    "FingerprintRandomizer",
    "PolymorphicEngine",
    "TrafficShaper",
]
