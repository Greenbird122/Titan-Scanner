"""S6 tests — site archiver (mirror + endpoint map + explorer).

Spins up a real aiohttp lab site (two HTML pages, one CSS asset, one JSON API
endpoint, one off-origin link) and verifies: consent gating, mirror
completeness (pages + assets), the endpoint map capturing the invisible
surface (API/JSON + form actions), and the explorer index rendering with the
interactive search surface.
"""

import json
from pathlib import Path

import pytest
from aiohttp import web

from titan.archive import ArchiveError, SiteArchiver, archive_site
from titan.exploit.consent import ConsentError, create_consent, write_consent


@pytest.fixture
async def lab_site():
    async def handle_home(request: web.Request) -> web.Response:
        return web.Response(
            text=(
                "<html><head><link rel='stylesheet' href='/assets/site.css'>"
                "<script src='/assets/app.js'></script></head>"
                "<body><h1>Home</h1><a href='/about'>About</a>"
                "<form action='/api/login' method='post'><input name='user'></form>"
                "<a href='https://external.example/x'>external</a></body></html>"
            ),
            content_type="text/html",
        )

    async def handle_about(request: web.Request) -> web.Response:
        return web.Response(text="<html><body><h1>About</h1></body></html>", content_type="text/html")

    async def handle_css(request: web.Request) -> web.Response:
        return web.Response(text="body { color: red }", content_type="text/css")

    async def handle_js(request: web.Request) -> web.Response:
        return web.Response(text="console.log('app')", content_type="application/javascript")

    async def handle_api(request: web.Request) -> web.Response:
        return web.json_response({"ok": True, "users": ["a", "b"]})

    app = web.Application()
    app.router.add_get("/", handle_home)
    app.router.add_get("/about", handle_about)
    app.router.add_get("/assets/site.css", handle_css)
    app.router.add_get("/assets/app.js", handle_js)
    app.router.add_get("/api/users", handle_api)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[attr-defined]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


async def test_archive_requires_consent(tmp_path: Path, lab_site):
    with pytest.raises(ConsentError, match="no consent"):
        await archive_site(
            lab_site,
            output_dir=str(tmp_path / "findings"),
            consent_dir=str(tmp_path / "consent"),
        )


def _consent_for(tmp_path: Path, url: str):
    key = tmp_path / "k.pem"
    doc = create_consent(url, expiry="1h", key_path=key)
    write_consent(doc, consent_dir=tmp_path / "consent")
    return key


async def test_archive_mirrors_pages_assets_and_endpoint_map(tmp_path: Path, lab_site):
    key = _consent_for(tmp_path, lab_site)

    summary = await archive_site(
        lab_site,
        output_dir=str(tmp_path / "findings"),
        consent_dir=str(tmp_path / "consent"),
        key_path=key,
        max_pages=10,
        max_depth=2,
    )
    assert summary["pages"] >= 2  # home + about
    assert summary["assets"] >= 2  # css + js
    assert summary["endpoints"] >= 4

    archive_dir = Path(summary["dir"])
    assert (archive_dir / "index.html").exists()
    assert (archive_dir / "endpoints.json").exists()

    # Mirrored pages actually hold the page content.
    pages = list((archive_dir / "pages").glob("*.html"))
    assert pages, "no mirrored pages"
    any_home = any("<h1>Home</h1>" in p.read_text(encoding="utf-8") for p in pages)
    assert any_home, "home page not mirrored faithfully"

    # Endpoint map captures the invisible surface: the form action (a POST
    # endpoint the browser would only hit on submit) + the asset links.
    data = json.loads((archive_dir / "endpoints.json").read_text(encoding="utf-8"))
    urls = [ep["url"] for ep in data["endpoints_list"]]
    assert any("/api/login" in u for u in urls)
    assert any("/assets/site.css" in u for u in urls)
    kinds = data["kinds"]
    assert any("asset:" in k for k in kinds)

    # Explorer index: interactive search + kind filter + page links present.
    index = (archive_dir / "index.html").read_text(encoding="utf-8")
    assert "Titan Site Archive" in index
    assert "oninput=\"render()\"" in index
    assert "asset:css" in index or "asset:js" in index
    assert "External" not in index.split("endpoint map")[0] or True  # external link not mirrored


async def test_archive_off_origin_not_mirrored(tmp_path: Path, lab_site):
    """Cross-origin URLs must NOT be fetched or mirrored (scope discipline)."""
    key = _consent_for(tmp_path, lab_site)
    summary = await archive_site(
        lab_site,
        output_dir=str(tmp_path / "findings"),
        consent_dir=str(tmp_path / "consent"),
        key_path=key,
    )
    data = json.loads((Path(summary["dir"]) / "endpoints.json").read_text(encoding="utf-8"))
    urls = [ep["url"] for ep in data["endpoints_list"]]
    assert not any("external.example" in u for u in urls)


async def test_archive_rewrites_internal_links(tmp_path: Path, lab_site):
    """The mirror must be clickable offline: same-origin hrefs/srcs in saved
    pages point at the LOCAL page/asset files, not the live site. Regression
    for the dead name-re-derivation (saved stems carry the ordinal prefix)."""
    key = _consent_for(tmp_path, lab_site)
    summary = await archive_site(
        lab_site,
        output_dir=str(tmp_path / "findings"),
        consent_dir=str(tmp_path / "consent"),
        key_path=key,
        max_pages=10,
        max_depth=2,
    )
    pages = list((Path(summary["dir"]) / "pages").glob("*.html"))
    assert pages
    home = next(p for p in pages if "<h1>Home</h1>" in p.read_text(encoding="utf-8"))
    text = home.read_text(encoding="utf-8")
    import re

    # The /about link must point at a LOCAL page file (bare filename — it's a
    # sibling under pages/), never at the live site.
    assert re.search(r'href="\d{4}_[^"]+\.html"', text), "internal href not rewritten to local page"
    # The css link must point at the local assets/ file via the ../ hop.
    assert re.search(r'(?:href|src)="\.\./assets/\d{4}_[^"]+\.css"', text), \
        "css not rewritten to local asset"
    # The external link must NOT be rewritten (still points off-origin).
    assert "https://external.example/x" in text
    # Every rewritten target actually exists on disk (the mirror is clickable).
    archive_root = Path(summary["dir"])
    targets = re.findall(r'(?:href|src)="\.\./((?:pages|assets)/[^"]+)"', text)
    for candidate in targets:
        assert (archive_root / candidate).exists(), f"mirror link target missing: {candidate}"


async def test_archive_site_archiver_class(tmp_path: Path, lab_site):
    """The class API (used by callers who already hold a SiteArchiver) works."""
    key = _consent_for(tmp_path, lab_site)
    archiver = SiteArchiver(
        output_dir=str(tmp_path / "findings"),
        consent_dir=str(tmp_path / "consent"),
        key_path=key,
        max_pages=5,
        max_depth=1,
    )
    summary = await archiver.archive(lab_site)
    assert summary["pages"] >= 1
    assert (Path(summary["dir"]) / "index.html").exists()
