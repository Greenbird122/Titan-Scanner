"""Track G monetization profiler (M2) — pure HTML/URL analysis.

Enumerates every third-party origin the page loads (script/img/iframe/embed/
link/audio/video/source/a), classifies each via the intel DB, checks whether
the load is cleartext (http:// on an https:// page) and whether script tags
carry an ``integrity`` (SRI) attribute, and builds a per-origin risk score.
Ad origins are metadata + risk — never fake vulnerabilities (the weather.co.ke
adsbygoogle-skimmer FP lesson).
"""

from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from titan.hostile.detectors import (
    clickbait_index,
    detect_clickbait_mechanics,
    detect_cloaks,
    detect_miners,
    detect_push_notif,
)
from titan.hostile.intel import IntelDB, ObservedIntel, origin_of

# Tags whose URL attribute represents a LOADED third-party resource.
_LOAD_TAGS = {
    "script": "src",
    "img": "src",
    "iframe": "src",
    "embed": "src",
    "link": "href",
    "audio": "src",
    "video": "src",
    "source": "src",
}
# Tags whose URL is a NAVIGATION target (lower weight).
_NAV_TAGS = {"a": "href"}

_CATEGORY_WEIGHT = {
    "miner": 50,
    "risky_ad": 30,
    "popunder": 20,
    "push_notif": 12,
    "ad_network": 6,
    "tracker": 3,
    None: 3,  # unknown third-party
}


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.loads: List[Dict[str, str]] = []
        self.navs: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attr_map = dict(attrs)
        if tag in _LOAD_TAGS:
            src = (attr_map.get(_LOAD_TAGS[tag]) or "").strip()
            if src:
                self.loads.append({"url": src, "kind": tag, "integrity": bool(attr_map.get("integrity"))})
        elif tag in _NAV_TAGS:
            href = (attr_map.get("href") or "").strip()
            if href:
                self.navs.append(href)


def extract_third_party(html: str, base_url: str) -> Dict[str, List[Dict[str, str]]]:
    """Return {"loads": [...], "navs": [...]} with resolved absolute URLs."""
    parser = _LinkExtractor()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        pass
    loads, navs = [], []
    for l in parser.loads:
        url = urljoin(base_url, l["url"])
        if url.startswith(("http://", "https://")):
            loads.append({"url": url, "kind": l["kind"], "integrity": l["integrity"]})
    for href in parser.navs:
        url = urljoin(base_url, href)
        if url.startswith(("http://", "https://")):
            navs.append(url)
    return {"loads": loads, "navs": navs}


def _page_is_https(base_url: str) -> bool:
    try:
        return urlparse(base_url).scheme == "https"
    except Exception:
        return False


def analyze(html: str, base_url: str, intel: Optional[IntelDB] = None,
            observed: Optional[ObservedIntel] = None) -> Dict[str, Any]:
    """Produce the monetization profile for one page's HTML.

    Returns a dict with ``origins`` (per-host rows), ``counts`` (category
    totals), ``clickbait``, ``cloaks``, ``miners``, ``push``, ``mechanics``,
    ``page_url`` and a top-level ``monetization_score`` (0-100).
    """
    intel = intel or IntelDB()
    extracted = extract_third_party(html, base_url)
    page_https = _page_is_https(base_url)
    page_host = urlparse(base_url).netloc.lower()

    origins: Dict[str, Dict[str, Any]] = {}
    for item in extracted["loads"]:
        url = item["url"]
        host = origin_of(url)
        if not host or host == page_host or intel.is_benign(host):
            continue
        kind = item["kind"]
        cleartext = page_https and url.lower().startswith("http://")
        sri_missing = kind == "script" and not item["integrity"]
        entry = origins.setdefault(host, {
            "host": host,
            "category": intel.classify(host),
            "kinds": [],
            "count": 0,
            "cleartext": False,
            "sri_missing": False,
            "urls": [],
        })
        entry["kinds"].append(kind)
        entry["count"] += 1
        entry["cleartext"] = entry["cleartext"] or cleartext
        entry["sri_missing"] = entry["sri_missing"] or sri_missing
        if url not in entry["urls"] and len(entry["urls"]) < 8:
            entry["urls"].append(url)
        if observed is not None:
            observed.record(url, kind=kind, integrity=item["integrity"], cleartext=cleartext)

    for url in extracted["navs"]:
        host = origin_of(url)
        if not host or host == page_host or intel.is_benign(host):
            continue
        entry = origins.setdefault(host, {
            "host": host,
            "category": intel.classify(host),
            "kinds": [],
            "count": 0,
            "cleartext": False,
            "sri_missing": False,
            "urls": [],
        })
        entry["kinds"].append("nav")
        entry["count"] += 1
        if url not in entry["urls"] and len(entry["urls"]) < 8:
            entry["urls"].append(url)
        if observed is not None:
            observed.record(url, kind="nav")

    origin_rows = []
    for host, e in origins.items():
        kinds = sorted(set(e["kinds"]))
        cat = e["category"]
        weight = _CATEGORY_WEIGHT.get(cat, 3)
        score = min(100, weight + (25 if e["cleartext"] else 0) + (10 if e["sri_missing"] else 0))
        origin_rows.append({
            "host": host,
            "category": cat,
            "kinds": kinds,
            "count": e["count"],
            "cleartext": e["cleartext"],
            "sri_missing": e["sri_missing"],
            "urls": e["urls"],
            "risk_score": score,
        })
    origin_rows.sort(key=lambda r: (-r["risk_score"], r["host"]))

    counts: Dict[str, int] = {}
    for r in origin_rows:
        cat = r["category"] or "unknown"
        counts[cat] = counts.get(cat, 0) + 1

    cloaks = detect_cloaks(html)
    miners = detect_miners(html)
    push = detect_push_notif(html)
    mechanics = detect_clickbait_mechanics(html)
    clickbait = clickbait_index(html)

    monetization_score = min(
        100,
        sum(_CATEGORY_WEIGHT.get(r["category"], 3) for r in origin_rows) // 2
        + len(cloaks) * 6 + clickbait["score"] // 5 + len(miners) * 15,
    )

    return {
        "page_url": base_url,
        "monetization_score": monetization_score,
        "origins": origin_rows,
        "counts": counts,
        "clickbait": clickbait,
        "cloaks": cloaks,
        "miners": miners,
        "push": push,
        "mechanics": mechanics,
    }


def body_fingerprint(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()[:16]
