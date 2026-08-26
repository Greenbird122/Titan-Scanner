"""Concurrent identity pool for stateful API testing (Track B).

The stateless module matrix sends one request per param per module. Track B
(BOLA/BFLA, mass assignment, JWT, OAuth, session) fundamentally needs TWO
authenticated identities alive at once: request A's object with B's session
and diff the response. That is the only way to prove cross-tenant access.

This module is deliberately thin: an identity is a name + auth headers +
cookies. The AuthEngine produces the identities (login, login_as_role); the
identity detectors consume them via a SessionPool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Identity:
    """One authenticated persona: what a login session grants."""

    name: str
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)

    @property
    def is_authenticated(self) -> bool:
        return bool(self.headers or self.cookies)


class SessionPool:
    """Holds N identities concurrently; identity detectors read from it.

    Not thread-safe by design — detectors snapshot the identities they need
    at scan time and issue their own requests with per-identity headers.
    """

    def __init__(self) -> None:
        self._identities: Dict[str, Identity] = {}
        self._order: List[str] = []

    def add(self, identity: Identity) -> None:
        if not identity.name:
            return
        if identity.name not in self._identities:
            self._order.append(identity.name)
        self._identities[identity.name] = identity

    def get(self, name: str) -> Optional[Identity]:
        return self._identities.get(name)

    def names(self) -> List[str]:
        return list(self._order)

    def all(self) -> List[Identity]:
        return [self._identities[n] for n in self._order if self._identities[n].is_authenticated]

    def primary(self) -> Optional[Identity]:
        """The first identity added (usually the main login)."""
        for name in self._order:
            if self._identities[name].is_authenticated:
                return self._identities[name]
        return None

    def second(self) -> Optional[Identity]:
        """A different identity from the primary — needed for A/B tenant tests."""
        primary_name = None
        for name in self._order:
            if self._identities[name].is_authenticated:
                if primary_name is None:
                    primary_name = name
                else:
                    return self._identities[name]
        return None

    def __len__(self) -> int:
        return sum(1 for i in self._identities.values() if i.is_authenticated)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identities": [
                {
                    "name": i.name,
                    "header_names": list(i.headers.keys()),
                    "cookie_names": list(i.cookies.keys()),
                }
                for i in self.all()
            ]
        }
