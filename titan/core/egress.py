"""Egress policy — pin the scan to the consented target's IP space.

Hostname scope checks (``_is_in_scope``) can be bypassed by DNS rebinding,
open redirects that bounce requests off the target, or SSRF sinks that make
the SERVER fetch internal addresses. This module adds an IP-level backstop
for requests the SCANNER itself sends (transport layer):

  - the consented target's host is resolved once and its IPs are pinned;
  - loopback, private (RFC1918), link-local, and other non-public ranges are
    denied by default — IMDS (169.254.169.254) and internal services become
    unreachable even when a detector's payload smuggles such a URL through;
  - ``allow_private=True`` restores local-lab behavior (loopback targets are
    always allowed; the flag extends that to pinned private targets);
  - explicit ``extra_allowed_hosts`` covers operator-owned internal ranges.

Fail-closed: on any resolution or parsing problem the request is denied.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from titan.core.logger import get_logger

logger = get_logger("egress")


class EgressDeniedError(PermissionError):
    """Raised when a request URL is outside the scan's egress policy."""


# Short alias used at call sites.
EgressDenied = EgressDeniedError


def _host_ips(host: str) -> set[str]:
    """Resolve a host to all its addresses (empty set on failure)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return set()
    return {info[4][0] for info in infos}


_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")  # Azure IMDS lives here


def _is_guarded(ip: str) -> bool:
    """Ranges denied even when private egress is opted into: loopback,
    link-local (all cloud IMDS endpoints), CGNAT (Azure IMDS), reserved,
    multicast, unspecified. Unparseable input counts as guarded."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.version == 4 and addr in _CGNAT_V4:
        return True
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


class EgressPolicy:
    """Per-scan egress gate installed into the transport layer."""

    def __init__(
        self,
        target: str,
        allow_private: bool = False,
        extra_allowed_hosts: list[str] | None = None,
        allowed_ips: set[str] | None = None,
    ):
        self.target_host = (urlparse(target).hostname or "").lower()
        self.allow_private = allow_private
        self.extra_allowed_hosts = {h.lower() for h in (extra_allowed_hosts or [])}
        # Pinned IPs of the consented target (resolved eagerly so the scan
        # talks to the addresses the operator consented to, not to whatever
        # DNS answers later — that is the rebinding defense).
        if allowed_ips is not None:
            self.pinned_ips = set(allowed_ips)
        else:
            self.pinned_ips = _host_ips(self.target_host) if self.target_host else set()

    # ------------------------------------------------------------------
    # Decision core
    # ------------------------------------------------------------------

    def url_allowed(self, url: str) -> bool:
        """True when the URL's host is inside the scan's egress policy."""
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            return False
        if not host:
            return False
        if host == self.target_host or host.endswith("." + self.target_host):
            return True
        # Explicitly allow-listed hosts are trusted without IP checks.
        if host in self.extra_allowed_hosts:
            return True
        # IP-literal URLs: allowed when pinned to the target. With private
        # egress opted in, RFC1918-style space opens up — but guarded ranges
        # (IMDS, loopback, CGNAT) stay denied regardless, because those are
        # exactly what an SSRF chain wants to reach.
        if _looks_like_ip(host):
            if host in self.pinned_ips:
                return True
            return self.allow_private and not _is_guarded(host)
        # Any other host: allowed only if it resolves INSIDE the pinned IP
        # space (defends rebinding-via-different-name) — or, when private
        # egress is allowed, if none of its addresses are guarded.
        resolved = _host_ips(host)
        if not resolved:
            return False
        if resolved & self.pinned_ips:
            return True
        return self.allow_private and not any(_is_guarded(ip) for ip in resolved)

    def check(self, url: str) -> None:
        """Raise EgressDenied when the URL violates the policy."""
        if self.url_allowed(url):
            return
        host = (urlparse(url).hostname or "?").lower()
        raise EgressDenied(
            f"egress denied: {host} is outside the consented target "
            f"'{self.target_host}' (pinned IPs: {len(self.pinned_ips)}). "
            "If this host is genuinely yours, add it to egress.allow_hosts."
        )


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def from_config(target: str, egress_cfg: dict | None) -> EgressPolicy:
    """Build the scan's policy from config['egress'] (absent = default-deny)."""
    cfg = egress_cfg or {}
    return EgressPolicy(
        target=target,
        allow_private=bool(cfg.get("allow_private", False)),
        extra_allowed_hosts=list(cfg.get("allow_hosts", []) or []),
    )
