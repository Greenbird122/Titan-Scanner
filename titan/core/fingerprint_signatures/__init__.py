"""Per-category fingerprint signature tables (re-exported verbatim)."""

from titan.core.fingerprint_signatures.base import BASE_FINGERPRINT
from titan.core.fingerprint_signatures.body import BODY_SIGNATURES
from titan.core.fingerprint_signatures.cookie import COOKIE_SIGNATURES
from titan.core.fingerprint_signatures.header import HEADER_SIGNATURES
from titan.core.fingerprint_signatures.url import URL_SIGNATURES

__all__ = [
    "BASE_FINGERPRINT",
    "BODY_SIGNATURES",
    "COOKIE_SIGNATURES",
    "HEADER_SIGNATURES",
    "URL_SIGNATURES",
]
