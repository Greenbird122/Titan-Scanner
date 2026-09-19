"""Typed validation for ``config.yaml`` — fail loudly before a scan starts.

Titan's config *is* the operator's intent: aggression level, exploit gating,
crawl budgets. Before this module the loader was a bare ``yaml.safe_load``, so a
typo silently changed what a scan did — ``crawl.profile: "depp"`` quietly
degraded to the fast profile, and a negative ``timeout`` was accepted and
carried downstream unchecked. A consent-gated offensive tool should refuse to
start and say why instead.

Two severity tiers
------------------
* **Hard fail** (:class:`ConfigValidationError`): wrong types, out-of-range
  numbers, and unknown values for the ``crawl.profile``, ``aggression`` and
  ``browser`` enums.
* **Pass through**: unknown keys, at every level. Every shipped
  ``config.*.yaml`` profile carries sections this schema does not model
  (``governance``, ``brain``, ``ai``, ``fleet``, ``egress``, ...), so rejecting
  unknown keys would break real scans for no benefit. Models allow extras and
  :func:`validate_config` re-attaches anything unmodeled.

Three crawl keys are deliberately *not* defaulted
-------------------------------------------------
``crawl.max_pages``, ``crawl.max_depth`` and ``crawl.timeout`` have
*profile-aware* defaults inside the engine: ``max_pages`` is 5 on the fast
profile but 20 on deep/hostile, and ``crawl.timeout`` is 90 or 300
(``titan/core/engine.py:82-84`` and ``:287``). Filling a flat default here would
silently override those for any config that omits them, so the schema validates
them when present and drops them when absent, leaving the engine's own fallbacks
in charge.

Naming
------
The root model is :class:`ScanConfig` rather than ``TitanConfig``:
``titan/core/config.py`` already exports a ``TitanConfig`` describing something
different (a multi-target config file). Two same-named classes in one package is
a trap for the next reader.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

__all__ = [
    "Aggression",
    "AuthConfig",
    "Browser",
    "ConfigValidationError",
    "CrawlConfig",
    "CrawlProfile",
    "ExploitConfig",
    "ScanConfig",
    "StealthConfig",
    "validate_config",
]


class ConfigValidationError(ValueError):
    """Raised when a config fails validation before a scan starts.

    Subclasses :class:`ValueError` so any existing broad handling keeps working.
    ``str()`` carries every problem with its field path and offending value.
    """


class _Allow(BaseModel):
    """Base model: unknown keys are kept, not rejected (see module docstring)."""

    model_config = ConfigDict(extra="allow")


class CrawlProfile(str, Enum):
    fast = "fast"
    deep = "deep"
    hostile = "hostile"


class Aggression(str, Enum):
    passive = "passive"
    active = "active"
    aggressive = "aggressive"
    hostile = "hostile"


class Browser(str, Enum):
    auto = "auto"
    system = "system"
    bundled = "bundled"


class CrawlConfig(_Allow):
    profile: CrawlProfile = CrawlProfile.fast
    max_apis: int = Field(default=15, ge=0)
    # Validated when set, absent when not — see "three crawl keys" above.
    max_pages: int | None = Field(default=None, ge=1)
    max_depth: int | None = Field(default=None, ge=0)
    timeout: int | None = Field(default=None, gt=0)


class StealthConfig(_Allow):
    adaptive: bool = True
    jitter: float = Field(default=0.3, ge=0, le=10)


class AuthConfig(_Allow):
    cookies: str = ""
    url: str = ""
    username: str = ""
    password: str = ""


class ExploitConfig(_Allow):
    enabled: bool = False
    consent_dir: str = "consent"


class ScanConfig(_Allow):
    target: str | None = None
    aggression: Aggression = Aggression.passive
    headless: bool = True
    browser: Browser = Browser.auto
    browser_profile: str = ""
    output_dir: str = "findings"
    crawl: CrawlConfig = CrawlConfig()
    stealth: StealthConfig = StealthConfig()
    auth: AuthConfig = AuthConfig()
    exploit: ExploitConfig = ExploitConfig()
    # governance / brain / deep_audit / ai / reporting / proxy / modules /
    # cloud / subdomain_takeover / fleet / llm / clientside stay unmodeled on
    # purpose: extra="allow" passes them through untouched.


_PROFILE_AWARE_CRAWL_KEYS = ("max_pages", "max_depth", "timeout")


def validate_config(data: dict[str, Any]) -> dict[str, Any]:
    """Validate a parsed ``config.yaml`` dict and return a normalized copy.

    Raises :class:`ConfigValidationError` on anything in the hard-fail tier.
    YAML reading stays in the caller (``run.py``) so this is testable without
    touching the filesystem.
    """
    try:
        model = ScanConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigValidationError(str(exc)) from exc

    out: dict[str, Any] = model.model_dump(mode="json", exclude_none=False)

    # Re-attach unmodeled sections. Pydantic already carries extras through
    # model_dump, but this is explicit insurance: dropping a section here would
    # make scans misbehave in ways that are very hard to trace back.
    for key, value in data.items():
        out.setdefault(key, value)

    # Hand the profile-aware crawl keys back to the engine when unset.
    crawl = out.get("crawl")
    if isinstance(crawl, dict):
        for key in _PROFILE_AWARE_CRAWL_KEYS:
            if crawl.get(key) is None:
                crawl.pop(key, None)

    return out
