"""Egress policy tests — the IP-level backstop behind hostname scoping.

Covers: target pinning, hostname/subdomain matching, IP-literal denial,
private/link-local/IMDS denial, allow-list opt-in, allow_private, and
fail-closed behavior on resolution failure.
"""

import pytest

from titan.core.egress import EgressDenied, EgressPolicy, from_config


def test_target_host_and_subdomains_allowed():
    p = EgressPolicy("http://example.com", allowed_ips={"93.184.216.34"})
    assert p.url_allowed("http://example.com/")
    assert p.url_allowed("http://api.example.com/v1")
    assert p.url_allowed("http://example.com:8443/deep/path?x=1")


def test_other_hosts_denied():
    p = EgressPolicy("http://example.com", allowed_ips={"93.184.216.34"})
    assert not p.url_allowed("http://evil.com/")
    assert not p.url_allowed("http://notexample.com/")  # suffix-trick host


def test_private_and_link_local_denied():
    p = EgressPolicy("http://example.com", allowed_ips={"93.184.216.34"})
    for url in (
        "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
        "http://100.100.100.200/",  # Azure IMDS
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://172.16.0.9/",
        "http://169.254.5.6/",
        "http://127.0.0.1:5000/",
        "http://[::1]/",
        "http://0.0.0.0/",
    ):
        assert not p.url_allowed(url), url


def test_pinned_ip_literals_allowed():
    p = EgressPolicy("http://93.184.216.34", allowed_ips={"93.184.216.34"})
    assert p.url_allowed("http://93.184.216.34/page")


def test_private_allow_list_restores_internal_targets():
    p = EgressPolicy(
        "http://10.0.0.5",
        allow_private=True,
        extra_allowed_hosts=["10.0.0.5", "lab.internal"],
        allowed_ips={"10.0.0.5"},
    )
    assert p.url_allowed("http://10.0.0.5/")
    assert p.url_allowed("http://lab.internal/")  # allow-listed, no pin needed
    assert not p.url_allowed("http://169.254.169.254/")  # not allow-listed


def test_allow_private_option():
    """allow_private opens RFC1918 space but NEVER the guarded ranges
    (loopback, link-local/IMDS, CGNAT) — those are what SSRF chains want."""
    p = EgressPolicy("http://example.com", allow_private=True, allowed_ips={"93.184.216.34"})
    assert p.url_allowed("http://192.168.1.10/")
    assert p.url_allowed("http://10.1.2.3/")
    assert not p.url_allowed("http://169.254.169.254/")  # AWS IMDS
    assert not p.url_allowed("http://100.100.100.200/")  # Azure IMDS (CGNAT)
    assert not p.url_allowed("http://127.0.0.1:5000/")  # loopback stays guarded


def test_rebinding_name_resolves_outside_pin_denied():
    """A name that resolves OUTSIDE the pinned space (or not at all) is denied
    even though a hostname check would pass — that is the rebinding defense.
    Uses an RFC 6761 guaranteed-unresolvable name."""
    p = EgressPolicy("http://example.com", allowed_ips={"93.184.216.34"})
    assert not p.url_allowed("http://unresolvable.invalid/")


def test_check_raises_egress_denied():
    p = EgressPolicy("http://example.com", allowed_ips={"93.184.216.34"})
    with pytest.raises(EgressDenied):
        p.check("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    p.check("http://example.com/ok")  # does not raise


def test_check_denies_unresolvable_fail_closed():
    p = EgressPolicy("http://example.invalid", allowed_ips=set())
    assert not p.url_allowed("http://unresolvable.invalid/x")


def test_from_config_defaults():
    p = from_config("http://example.com", None)
    assert p.allow_private is False
    assert p.extra_allowed_hosts == set()
    p2 = from_config("http://example.com", {"allow_private": True, "allow_hosts": ["a.internal"]})
    assert p2.allow_private is True
    assert p2.extra_allowed_hosts == {"a.internal"}


# ---------------------------------------------------------------------------
# Transport enforcement (the actual egress choke point)
# ---------------------------------------------------------------------------


async def test_http_transport_blocks_denied_urls():
    from titan.transport.base import AttackRequest
    from titan.transport.http_transport import HttpTransport

    t = HttpTransport()
    t.set_egress_policy(EgressPolicy("http://example.com", allowed_ips={"93.184.216.34"}))
    resp = await t.send(AttackRequest(url="http://169.254.169.254/latest/meta-data/"))
    assert resp.status == 0 and "egress denied" in (resp.error or "")
    resp2 = await t.send(AttackRequest(url="http://192.168.0.1/"))
    assert resp2.status == 0 and "egress denied" in (resp2.error or "")
    await t.close()


async def test_http_transport_allows_pinned_and_none_policy():
    from titan.transport.base import AttackRequest
    from titan.transport.http_transport import HttpTransport

    # No policy installed -> transport behaves exactly as before.
    t_none = HttpTransport()
    assert t_none._egress is None
    # A pinned in-scope URL passes the check layer (network itself untested).
    p = EgressPolicy("http://example.com", allowed_ips={"93.184.216.34"})
    t = HttpTransport()
    t.set_egress_policy(p)
    assert p.url_allowed("http://example.com/x")
    assert not p.url_allowed("http://evil.invalid/x")
    await t.close()
    await t_none.close()


# ---------------------------------------------------------------------------
# Engine wiring: the scan installs the policy before any detector traffic
# ---------------------------------------------------------------------------


async def test_engine_installs_egress_policy(monkeypatch):
    """_ensure_transport must build the policy from the scan target and
    install it on the HTTP transport."""
    from titan.core import transport_mixin as tm

    installed = {}

    class _FakeHttp:
        def set_egress_policy(self, p):
            installed["policy"] = p

    class _FakeRegistry:
        available = ["http"]

        async def auto_register(self):
            return None

        def get(self, name):
            return _FakeHttp() if name == "http" else None

    async def _fake_auto(self):
        return None

    monkeypatch.setattr(tm, "TransportRegistry", _FakeRegistry, raising=False)

    import titan.transport as transport_pkg

    monkeypatch.setattr(transport_pkg, "TransportRegistry", _FakeRegistry, raising=False)

    class _Engine(tm.TransportMixin):
        config = {"egress": {"allow_hosts": ["cdn.target.example"]}}
        _scan_target = "http://target.example"
        _transport_ready = False
        _transport_registry = None
        _transport_http = None

    eng = _Engine()
    await eng._ensure_transport()
    p = installed.get("policy")
    assert p is not None
    assert p.target_host == "target.example"
    assert "cdn.target.example" in p.extra_allowed_hosts
    assert eng._transport_ready is True
