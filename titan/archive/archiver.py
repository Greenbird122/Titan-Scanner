"""S6 — site archiver implementation.

Bounded, consent-gated read-only mirror of a target. The archive captures
BOTH the visible surface (every HTML page, every in-scope asset) and the
invisible surface (every URL the pages reference — API paths, script/JSON
endpoints, form actions — with status + content-type), then renders a local
self-contained explorer so an operator can browse the whole attack surface
offline, without hammering the live target again.

Consent: read-only GETs need no --write/--shells flag — any valid, unexpired
consent for the target authorizes mirroring it (mirrors sqli-extraction's
stance). Bounded: max_pages / max_depth / per-request timeout / asset cap, so
a huge site archives in minutes, not hours.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import re
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from aiohttp import ClientSession, ClientTimeout

from ..exploit.consent import require_consent
from ..reporting import site_slug

DEFAULT_MAX_PAGES = 40
DEFAULT_MAX_DEPTH = 2
DEFAULT_REQUEST_TIMEOUT = 8.0
DEFAULT_MAX_ASSETS = 300
DEFAULT_MAX_ASSET_BYTES = 2 * 1024 * 1024  # 2 MB per asset


class ArchiveError(Exception):
    """Raised when the archive cannot be built."""


class _LinkParser(HTMLParser):
    """Extract href/src/action URLs from an HTML page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        for name, value in attrs:
            if name in ("href", "src", "action", "data-src", "poster") and value:
                self.urls.append(value)


async def archive_site(
    target: str,
    output_dir: str = "findings",
    consent_dir: str = "consent",
    key_path: Optional[Path] = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> Dict[str, Any]:
    """One-shot convenience wrapper around SiteArchiver.archive()."""
    archiver = SiteArchiver(
        output_dir=output_dir,
        consent_dir=consent_dir,
        key_path=key_path,
        max_pages=max_pages,
        max_depth=max_depth,
    )
    return await archiver.archive(target)


def _asset_kind(url: str, content_type: str) -> str:
    ct = (content_type or "").lower()
    path = urlparse(url).path.lower()
    if "javascript" in ct or path.endswith(".js"):
        return "js"
    if "css" in ct or path.endswith(".css"):
        return "css"
    if "image" in ct or path.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico")):
        return "image"
    if "font" in ct or path.endswith((".woff", ".woff2", ".ttf", ".otf", ".eot")):
        return "font"
    if "json" in ct or path.endswith(".json"):
        return "json"
    return "other"


def _safe_name(url: str, index: int) -> str:
    """Deterministic, filesystem-safe stem for a URL."""
    parsed = urlparse(url)
    path = (parsed.path or "index").strip("/")
    if not path:
        path = "index"
    parts = [p for p in re.split(r"[^a-z0-9]+", (parsed.hostname or "h") + "-" + path, flags=re.I) if p]
    stem = "-".join(parts)[:70] or f"page{index}"
    return f"{index:04d}_{stem}"


class SiteArchiver:
    """Bounded consent-gated site mirror with explorer index."""

    def __init__(
        self,
        output_dir: str = "findings",
        consent_dir: str = "consent",
        key_path: Optional[Path] = None,
        max_pages: int = DEFAULT_MAX_PAGES,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_assets: int = DEFAULT_MAX_ASSETS,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.consent_dir = Path(consent_dir)
        self.key_path = key_path
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_assets = max_assets
        self.request_timeout = request_timeout

    def _in_scope(self, url: str, base_host: str) -> bool:
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            return False
        return bool(host) and (host == base_host or host.endswith("." + base_host))

    async def archive(self, target: str) -> Dict[str, Any]:
        """Mirror the target into findings/<slug>/archive/. Returns a summary."""
        from titan.exploit.consent import DEFAULT_KEY_PATH as _DEFAULT_KEY

        require_consent(target, consent_dir=self.consent_dir, key_path=self.key_path or _DEFAULT_KEY)

        slug = site_slug(target)
        archive_dir = self.output_dir / slug / "archive"
        pages_dir = archive_dir / "pages"
        assets_dir = archive_dir / "assets"
        pages_dir.mkdir(parents=True, exist_ok=True)
        assets_dir.mkdir(exist_ok=True)

        base_host = (urlparse(target).hostname or "").lower()
        timeout = ClientTimeout(total=self.request_timeout)
        endpoints: List[Dict[str, Any]] = []
        pages: List[Dict[str, Any]] = []
        seen_pages: Set[str] = set()
        seen_assets: Set[str] = set()
        assets_saved = 0
        # URL -> saved-file map, built as pages/assets land, so the link
        # rewriter can point mirrored hrefs/srcs at REAL local files (a name
        # re-derivation can't work — saved stems carry the ordinal prefix +
        # extension).
        url_to_file: Dict[str, str] = {}

        async with ClientSession(timeout=timeout) as client:
            queue: deque = deque([(target, 0)])
            while queue and len(pages) < self.max_pages:
                url, depth = queue.popleft()
                norm = url.split("#")[0]
                if norm in seen_pages:
                    continue
                seen_pages.add(norm)
                if not self._in_scope(norm, base_host):
                    continue

                try:
                    async with client.get(
                        norm, headers={"User-Agent": "Titan-Archive/1.0"}, allow_redirects=True
                    ) as resp:
                        status = resp.status
                        ctype = resp.headers.get("Content-Type", "")
                        body = await resp.read()
                except Exception as exc:
                    endpoints.append(
                        {
                            "url": norm,
                            "status": 0,
                            "kind": "error",
                            "note": f"{type(exc).__name__}: {exc}",
                        }
                    )
                    continue

                is_html = "html" in ctype.lower() or b"<html" in body[:2048].lower() or b"<!doctype" in body[:2048].lower()

                if is_html and len(pages) < self.max_pages:
                    name = _safe_name(norm, len(pages) + 1)
                    page_file = pages_dir / f"{name}.html"
                    url_to_file[norm.rstrip("/")] = f"pages/{page_file.name}"
                    text = body.decode("utf-8", errors="replace")
                    # Pages are saved RAW during the crawl; link rewriting
                    # happens in a final pass (below) once url_to_file is
                    # complete — a child page may not be saved yet when its
                    # parent is written, so per-page rewrite would miss it.
                    page_file.write_text(text, encoding="utf-8")
                    rel = f"pages/{page_file.name}"
                    pages.append(
                        {
                            "url": norm,
                            "file": rel,
                            "status": status,
                            "content_type": ctype,
                            "depth": depth,
                        }
                    )
                    endpoints.append(
                        {
                            "url": norm,
                            "status": status,
                            "kind": "page",
                            "content_type": ctype,
                            "file": rel,
                            "depth": depth,
                        }
                    )

                    # Discover child URLs from the page.
                    parser = _LinkParser()
                    parser.feed(text)
                    for raw in parser.urls:
                        child = urljoin(norm, raw).split("#")[0]
                        if not child.startswith(("http://", "https://")):
                            continue
                        if not self._in_scope(child, base_host):
                            continue
                        child_depth = depth + 1
                        if child_depth <= self.max_depth:
                            queue.append((child, child_depth))

                    for raw in parser.urls:
                        asset = urljoin(norm, raw).split("#")[0]
                        if not asset.startswith(("http://", "https://")):
                            continue
                        if asset in seen_assets or assets_saved >= self.max_assets:
                            continue
                        if not self._in_scope(asset, base_host):
                            continue
                        seen_assets.add(asset)
                        try:
                            async with client.get(
                                asset,
                                headers={"User-Agent": "Titan-Archive/1.0"},
                                timeout=ClientTimeout(total=self.request_timeout),
                            ) as ar:
                                abody = await ar.read()
                            if len(abody) > DEFAULT_MAX_ASSET_BYTES:
                                continue
                            kind = _asset_kind(asset, ar.headers.get("Content-Type", ""))
                            aname = _safe_name(asset, assets_saved + 1)
                            ext = {"js": ".js", "css": ".css", "image": ".img", "font": ".fnt", "json": ".json", "other": ".bin"}[kind]
                            afile = assets_dir / f"{aname}{ext}"
                            afile.write_bytes(abody)
                            url_to_file[asset.rstrip("/")] = f"assets/{afile.name}"
                            assets_saved += 1
                            endpoints.append(
                                {
                                    "url": asset,
                                    "status": ar.status,
                                    "kind": f"asset:{kind}",
                                    "content_type": ar.headers.get("Content-Type", ""),
                                    "file": f"assets/{afile.name}",
                                }
                            )
                        except Exception:
                            continue
                else:
                    # Non-HTML URL discovered during the crawl (an API/JSON
                    # endpoint or downloadable resource): map it, fetch once.
                    if norm not in seen_assets:
                        seen_assets.add(norm)
                        endpoints.append(
                            {
                                "url": norm,
                                "status": status,
                                "kind": _asset_kind(norm, ctype),
                                "content_type": ctype,
                                "bytes": len(body),
                            }
                        )

        # Final pass: rewrite every saved page's same-origin links against the
        # now-complete url_to_file so the mirror is clickable offline. Each
        # page resolves its OWN relative links (urljoin needs the page's URL).
        for p in pages:
            pf = pages_dir / Path(p["file"]).name
            try:
                raw = pf.read_text(encoding="utf-8")
                rewritten = self._rewrite_links(raw, p["url"], base_host, url_to_file)
                if rewritten != raw:
                    pf.write_text(rewritten, encoding="utf-8")
            except Exception:
                continue

        # De-dupe the endpoint map by URL (keep the first, most complete entry).
        by_url: Dict[str, Dict[str, Any]] = {}
        for ep in endpoints:
            if ep["url"] not in by_url:
                by_url[ep["url"]] = ep
        endpoints = sorted(by_url.values(), key=lambda e: (e["url"]))
        kinds: Dict[str, int] = {}
        for ep in endpoints:
            kinds[ep["kind"]] = kinds.get(ep["kind"], 0) + 1

        (archive_dir / "endpoints.json").write_text(
            json.dumps(
                {
                    "target": target,
                    "slug": slug,
                    "pages": len(pages),
                    "assets": assets_saved,
                    "endpoints": len(endpoints),
                    "kinds": kinds,
                    "endpoints_list": endpoints,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        index = self._render_index(target, slug, pages, endpoints, kinds)
        (archive_dir / "index.html").write_text(index, encoding="utf-8")

        return {
            "target": target,
            "slug": slug,
            "dir": str(archive_dir),
            "pages": len(pages),
            "assets": assets_saved,
            "endpoints": len(endpoints),
            "kinds": kinds,
        }

    def _rewrite_links(
        self,
        text: str,
        page_url: str,
        base_host: str,
        url_to_file: Dict[str, str],
    ) -> str:
        """Rewrite same-origin links to the local files actually saved.

        ``url_to_file`` maps absolute URLs (trailing-slash-stripped) to their
        mirror file path (e.g. ``http://host/about`` -> ``pages/0001_about.html``),
        so the mirror is genuinely clickable offline. Cross-origin URLs are
        left untouched (external resources, not part of this site).
        """

        def _local(attr: str, value: str) -> str:
            abs_url = urljoin(page_url, value).split("#")[0].rstrip("/")
            if not self._in_scope(abs_url, base_host):
                return value
            target = url_to_file.get(abs_url)
            if not target:
                return value
            # Pages live in archive/pages/, assets in archive/assets/. From a
            # page's own directory a sibling page is its bare filename and an
            # asset needs the ../ hop up to the archive root.
            if target.startswith("assets/"):
                return "../" + target
            return target.split("/")[-1]  # pages/<file> -> <file>

        # Only rewrite src/href/action attributes (regex keeps it simple and
        # safe; the browser will ignore a wrong guess).
        text = re.sub(
            r'(<(?:a|link|script|img|source|form|video|audio)\s[^>]*?(href|src|action)=)["\']([^"\']*)["\']',
            lambda m: f'{m.group(1)}"{_local(m.group(2), m.group(3))}"',
            text,
        )
        return text

    def _render_index(
        self,
        target: str,
        slug: str,
        pages: List[Dict[str, Any]],
        endpoints: List[Dict[str, Any]],
        kinds: Dict[str, int],
    ) -> str:
        """Self-contained explorer: searchable endpoint map + page browser."""
        page_rows = "\n".join(
            f'<tr><td><span class="sev sev-{"ok" if p["status"] < 400 else "bad"}">{p["status"]}</span></td>'
            f'<td><a href="{html.escape(p["file"], quote=True)}" target="_blank">{html.escape(p["url"])}</a></td>'
            f"<td>depth {p['depth']}</td></tr>"
            for p in pages
        )
        ep_rows = "\n".join(
            f'<tr class="ep" data-kind="{html.escape(ep["kind"], quote=True)}" '
            f'data-text="{html.escape(ep["url"] + " " + ep.get("note", ""), quote=True).lower()}">'
            f'<td><span class="sev sev-{"ok" if ep.get("status", 0) < 400 else "bad"}">{ep.get("status", "?")}</span></td>'
            f'<td class="muted">{html.escape(ep["kind"])}</td>'
            f'<td><code>{html.escape(ep["url"])}</code></td>'
            f'<td>{html.escape(ep.get("content_type", "") or (ep.get("note") or ""))}</td></tr>'
            for ep in endpoints
        )
        kind_summary = " ".join(
            f'<span class="chip">{html.escape(k)}: {v}</span>' for k, v in sorted(kinds.items())
        )
        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Titan Archive — {html.escape(target)}</title>
<style>
  :root {{ --bg:#0f1115; --panel:#171a21; --panel2:#1d2129; --text:#e8eaed; --muted:#9aa0a6; --border:#2a2f3a; --accent:#8ab4f8; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text); font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif; padding:24px; }}
  h1 {{ font-size:20px; margin-bottom:6px; }}
  h2 {{ font-size:15px; margin:26px 0 10px; border-bottom:1px solid var(--border); padding-bottom:6px; }}
  .muted {{ color:var(--muted); }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel); border-radius:10px; overflow:hidden; font-size:13px; }}
  th, td {{ text-align:left; padding:8px 12px; border-bottom:1px solid var(--border); }}
  th {{ background:var(--panel2); color:var(--muted); }}
  code {{ background:#0b0d10; border:1px solid var(--border); border-radius:6px; padding:1px 5px; font-size:12px; word-break:break-all; }}
  a {{ color:var(--accent); text-decoration:none; }} a:hover {{ text-decoration:underline; }}
  .sev {{ display:inline-block; padding:1px 8px; border-radius:10px; font-size:11px; font-weight:700; color:#0f1115; }}
  .sev-ok {{ background:#34a853; }} .sev-bad {{ background:#d93025; }}
  .chip {{ display:inline-block; background:#2b1f4d; color:#c7b4ff; border-radius:6px; padding:1px 7px; font-size:11px; margin-right:4px; }}
  .controls {{ margin:12px 0; display:flex; gap:10px; flex-wrap:wrap; }}
  .controls input, .controls select {{ background:var(--panel2); color:var(--text); border:1px solid var(--border); border-radius:8px; padding:8px 12px; font-size:13px; }}
  .controls input {{ flex:1; min-width:220px; }}
  .summary {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:12px 16px; font-size:13px; }}
</style></head><body>
<h1>Titan Site Archive — {html.escape(target)}</h1>
<p class="muted">slug <code>{html.escape(slug)}</code> · consent-gated read-only mirror · browse offline</p>
<div class="summary" style="margin-top:12px">
  <span class="chip">pages: {len(pages)}</span>{kind_summary}
</div>

<h2>Mirrored pages ({len(pages)})</h2>
<p class="muted">Click a page to open the local mirror copy.</p>
<table><thead><tr><th>Status</th><th>URL</th><th>Depth</th></tr></thead>
<tbody>{page_rows}</tbody></table>

<h2>Endpoint map ({len(endpoints)})</h2>
<div class="controls">
  <input id="q" type="text" placeholder="Search URLs, kinds, notes…" oninput="render()">
  <select id="kind" onchange="render()">
    <option value="">All kinds</option>
    <option value="page">page</option>
    <option value="asset:js">asset:js</option>
    <option value="asset:css">asset:css</option>
    <option value="asset:image">asset:image</option>
    <option value="asset:json">asset:json</option>
    <option value="json">json</option>
    <option value="other">other</option>
  </select>
</div>
<table><thead><tr><th>Status</th><th>Kind</th><th>URL</th><th>Type / note</th></tr></thead>
<tbody id="tbody">{ep_rows}</tbody></table>
<p id="count" class="muted" style="margin-top:8px"></p>

<script>
function render() {{
  const q = (document.getElementById("q").value || "").toLowerCase();
  const k = document.getElementById("kind").value;
  const rows = Array.from(document.querySelectorAll("tr.ep"));
  let shown = 0;
  rows.forEach(tr => {{
    const ok = (!q || tr.dataset.text.includes(q)) && (!k || tr.dataset.kind === k);
    tr.style.display = ok ? "" : "none";
    if (ok) shown++;
  }});
  document.getElementById("count").textContent = shown + " of " + rows.length + " endpoints";
}}
render();
</script>
</body></html>"""
