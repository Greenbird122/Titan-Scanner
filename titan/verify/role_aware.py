"""Role-aware scanning.

Infers the current authenticated role's capabilities from observed behavior
and adjusts module selection / finding prioritization accordingly.

This does NOT change the module set arbitrarily.  It:
  - records the role observed on the current session
  - annotates findings with the role that produced them
  - downgrades findings that require a *different* role to be meaningful
    (e.g. a stored-XSS in an admin-only editor is low-risk when found as `user`)
  - feeds the hostile surface profiler so platform brains can specialize
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class Role(str, Enum):
    USER = "user"
    STAFF = "staff"
    ADMIN = "admin"
    ANON = "anon"
    UNKNOWN = "unknown"


@dataclass
class RoleCapabilities:
    """What a role can typically reach."""

    role: Role
    can_read_users: bool = False
    can_write_users: bool = False
    can_read_admin: bool = False
    can_write_admin: bool = False
    can_impersonate: bool = False
    can_manage_content: bool = False
    can_manage_payments: bool = False
    can_view_analytics: bool = False
    paths: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role.value,
            "can_read_users": self.can_read_users,
            "can_write_users": self.can_write_users,
            "can_read_admin": self.can_read_admin,
            "can_write_admin": self.can_write_admin,
            "can_impersonate": self.can_impersonate,
            "can_manage_content": self.can_manage_content,
            "can_manage_payments": self.can_manage_payments,
            "can_view_analytics": self.can_view_analytics,
            "paths": sorted(self.paths),
        }


# Heuristic role→capability map.  Real capability is inferred from observed
# access during the crawl, not from the role string alone.
_ROLE_CAPABILITY_HINTS: Dict[str, RoleCapabilities] = {
    "admin": RoleCapabilities(
        role=Role.ADMIN,
        can_read_users=True,
        can_write_users=True,
        can_read_admin=True,
        can_write_admin=True,
        can_impersonate=True,
        can_manage_content=True,
        can_manage_payments=True,
        can_view_analytics=True,
    ),
    "staff": RoleCapabilities(
        role=Role.STAFF,
        can_read_users=True,
        can_manage_content=True,
        can_manage_payments=True,
        can_view_analytics=True,
    ),
    "blink": RoleCapabilities(
        role=Role.STAFF,
        can_read_users=True,
        can_manage_content=True,
        can_manage_payments=True,
        can_view_analytics=True,
    ),
    "moderator": RoleCapabilities(
        role=Role.STAFF,
        can_read_users=True,
        can_manage_content=True,
    ),
    "user": RoleCapabilities(role=Role.USER, can_manage_content=True),
}


class RoleAwareScanner:
    """Observes authenticated access patterns and adjusts finding risk."""

    def __init__(self) -> None:
        self._role: Role = Role.ANON
        self._capabilities: RoleCapabilities = RoleCapabilities(role=Role.ANON)
        self._observed_paths: Set[str] = set()
        self._role_token_names: Set[str] = set()

    def record_role(self, role_name: Optional[str]) -> None:
        if not role_name:
            return
        key = str(role_name).lower().strip()
        self._role = Role(key)
        hint = _ROLE_CAPABILITY_HINTS.get(key)
        if hint is not None:
            self._capabilities = hint
        else:
            self._capabilities = RoleCapabilities(role=self._role)
        logger.info("Role-aware scanner: role=%s capabilities=%s", self._role.value, self._capabilities.to_dict())

    def record_access(self, url: str, status: int, body: str = "") -> None:
        try:
            from urllib.parse import urlparse
            path = urlparse(url).path.lower()
        except Exception:
            return
        self._observed_paths.add(path)
        if status == 200 and body:
            self._infer_capabilities_from_response(path, body)

    def _infer_capabilities_from_response(self, path: str, body: str) -> None:
        lower = body.lower()
        if any(k in path for k in ("/users", "/accounts", "/members")) and self._role == Role.USER:
            self._capabilities.can_read_users = True
        if any(k in path for k in ("/admin", "/dashboard", "/panel")) and self._role in (Role.ADMIN, Role.STAFF):
            self._capabilities.can_read_admin = True
        if any(k in path for k in ("/payments", "/transactions", "/billing")) and self._role in (Role.ADMIN, Role.STAFF):
            self._capabilities.can_manage_payments = True
        if any(k in path for k in ("/analytics", "/reports", "/stats")) and self._role in (Role.ADMIN, Role.STAFF):
            self._capabilities.can_view_analytics = True

    def role(self) -> Role:
        return self._role

    def capabilities(self) -> RoleCapabilities:
        return self._capabilities

    def adjust_finding(self, finding: Any) -> None:
        """Tag and downgrade findings that are not reachable by the current role."""
        if not getattr(finding, "verified", False):
            return
        if self._role == Role.ANON:
            return

        attack_type = getattr(getattr(finding, "attack_type", None), "value", "") or ""
        location = getattr(finding, "location", "") or ""
        param = getattr(finding, "param", "") or ""
        url = getattr(finding, "url", "") or ""

        if attack_type == "XSS" and location == "body":
            try:
                from urllib.parse import urlparse
                path = urlparse(url).path.lower()
            except Exception:
                path = ""
            if any(k in path for k in ("/admin", "/dashboard", "/settings")) and not self._capabilities.can_read_admin:
                finding.metadata = getattr(finding, "metadata", {}) or {}
                finding.metadata["role_gated"] = True
                finding.metadata["role_gate_reason"] = "admin-only sink, current role=%s" % self._role.value
                finding.severity = _downgrade(getattr(finding, "severity", None))
                finding.confidence = max(0.1, getattr(finding, "confidence", 0.5) - 0.2)
                return

        if attack_type == "IDOR":
            if not self._capabilities.can_read_users and any(k in (param or "").lower() for k in ("user_id", "account_id", "id")):
                finding.metadata = getattr(finding, "metadata", {}) or {}
                finding.metadata["role_gated"] = True
                finding.metadata["role_gate_reason"] = "user object reference, current role=%s" % self._role.value
                finding.severity = _downgrade(getattr(finding, "severity", None))
                finding.confidence = max(0.1, getattr(finding, "confidence", 0.5) - 0.25)
                return

        if attack_type == "BOLA":
            if not self._capabilities.can_read_users and not self._capabilities.can_read_admin:
                finding.metadata = getattr(finding, "metadata", {}) or {}
                finding.metadata["role_gated"] = True
                finding.metadata["role_gate_reason"] = "object access requires admin/staff, current role=%s" % self._role.value
                finding.severity = _downgrade(getattr(finding, "severity", None))
                finding.confidence = max(0.1, getattr(finding, "confidence", 0.5) - 0.2)
                return

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self._role.value,
            "capabilities": self._capabilities.to_dict(),
            "observed_paths": sorted(self._observed_paths),
        }


def _downgrade(severity: Any) -> Any:
    """Downgrade one step: CRITICAL -> HIGH -> MEDIUM -> LOW."""
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    try:
        s = str(severity).upper()
        idx = order.index(s)
        if idx > 0:
            return order[idx - 1]
    except ValueError:
        pass
    return severity
