"""Typed validation for attack-module entry points.

Every attack module receives ``(target, method, url, params)`` at its
``scan()`` boundary (dispatched by ``titan/core/module_bindings.py``). That
boundary previously had no schema: malformed targets or params reached module
logic unvalidated. This module gives the boundary a pydantic model —
``ScanParams`` — and a single validation entry point,
``validate_scan_params()``, which raises the typed ``TitanValidationError``.

``TitanValidationError`` subclasses ``ValueError`` so existing broad handlers
keep working; it exists so callers can catch boundary-validation failures
specifically.

Note: ``url`` may be an absolute http(s) URL *or* an absolute path on the
target origin (the local-lab convention — tests and the engine dispatch
paths like ``/logic_negative_accepted``).

The accepted grammar is declared in ``titan/core/validation_patterns.py``
and enforced here on top of the semantic ``urlparse`` checks: every string
field is first checked against its declared pattern (fail-closed lookup),
so the boundary's input classes are declared data, not just inline logic.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from titan.core.validation_patterns import matches as _pattern_matches


class TitanValidationError(ValueError):
    """Raised when attack-module inputs fail boundary validation."""


_KNOWN_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


class ScanParams(BaseModel):
    """Schema for the per-endpoint attack-module boundary."""

    model_config = ConfigDict(extra="forbid")

    target: str
    method: str
    url: str
    params: dict[str, Any]

    @field_validator("target", "url")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        # Declared pattern first: at least one non-whitespace character.
        if not _pattern_matches("non_empty_text", v):
            raise ValueError("must be a non-empty string")
        return v

    @field_validator("target")
    @classmethod
    def _absolute_url(cls, v: str) -> str:
        # Declared pattern (whole-value shape), then the semantic check.
        if not _pattern_matches("absolute_http_url", v):
            raise ValueError(f"target must be an absolute http(s) URL, got {v!r}")
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"target must be an absolute http(s) URL, got {v!r}")
        return v

    @field_validator("url")
    @classmethod
    def _absolute_url_or_path(cls, v: str) -> str:
        # Declared patterns mirror the two accepted shapes; the semantic
        # urlparse check below stays as the second layer.
        if _pattern_matches("absolute_http_url", v) or _pattern_matches("absolute_path", v):
            parsed = urlparse(v)
            if parsed.scheme in ("http", "https"):
                if not parsed.netloc:
                    raise ValueError(f"url has a scheme but no host: {v!r}")
                return v
            if v.startswith("/"):
                return v  # absolute path on the target origin
        raise ValueError(f"url must be an absolute http(s) URL or an absolute path, got {v!r}")

    @field_validator("method")
    @classmethod
    def _known_method(cls, v: str) -> str:
        method = v.strip().upper()
        # Declared pattern against the normalized verb; the set membership
        # check remains the authority (and the source of the error message).
        if _pattern_matches("http_method", method) and method not in _KNOWN_METHODS:
            raise ValueError(f"unsupported HTTP method {v!r} (known: {sorted(_KNOWN_METHODS)})")
        if not _pattern_matches("http_method", method):
            raise ValueError(f"unsupported HTTP method {v!r} (known: {sorted(_KNOWN_METHODS)})")
        return method

    @field_validator("params")
    @classmethod
    def _string_params(cls, v: dict[str, Any]) -> dict[str, str]:
        out: dict[str, str] = {}
        for key, value in v.items():
            if not isinstance(key, str) or not _pattern_matches("non_empty_key", key):
                raise ValueError(f"param keys must be non-empty strings, got {key!r}")
            if not isinstance(value, (str, int, float, bool)):
                raise ValueError(f"param {key!r} must be a scalar, got {type(value).__name__}")
            out[key] = str(value)
        return out


def validate_scan_params(*, target: str, method: str, url: str, params: dict[str, Any] | None) -> ScanParams:
    """Validate attack-module inputs; raise ``TitanValidationError`` on failure.

    Wraps pydantic's ``ValidationError`` so the boundary raises one typed,
    catchable error instead of leaking a pydantic-specific exception.
    """
    try:
        return ScanParams(target=target, method=method, url=url, params=params or {})
    except ValidationError as exc:
        raise TitanValidationError(str(exc)) from exc
