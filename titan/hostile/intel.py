"""Track G threat-intel DB — bundled taxonomy + observed origins (M1).

The bundled DB (``origins.json``) tags known ad/popunder/push/tracker/miner
origins. It is CURATED (operator-reviewed, provenance noted) and deliberately
small. On top of it, every hostile pass records the origins it actually
observed (``findings/<slug>/intel.json``); ``titan intel promote`` validates a
candidate observed entry and merges it into the operator's user DB
(``~/.titan/intel_user.json``) — the promote path, never the scan, grows the
bundled set.

Categories: ``ad_network``, ``popunder``, ``push_notif``, ``tracker``,
``miner``, ``risky_ad``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

CATEGORIES = ("ad_network", "popunder", "push_notif", "tracker", "miner", "risky_ad")

USER_DB_PATH = Path.home() / ".titan" / "intel_user.json"

# Origins that must NEVER be flagged as third-party risk (CDNs / framework
# loaders a hostile profile should not report as monetization).
KNOWN_BENIGN = {
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "code.jquery.com",
    "ajax.googleapis.com", "static.cloudflareinsights.com", "www.gstatic.com",
}


def origin_of(url: str) -> str:
    """Extract the registrable-ish host of a URL (bare hostname, lowercased)."""
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        host = ""
    return host or url.lower().split("/")[0]


class IntelDB:
    """Category lookup over the bundled DB + an optional operator DB."""

    def __init__(self, user_db_path: Optional[Path] = None):
        self.user_db_path = Path(user_db_path) if user_db_path else USER_DB_PATH
        self._map: Dict[str, str] = {}
        self._load_bundled()
        self._load_user()

    def _load_bundled(self) -> None:
        bundled = Path(__file__).with_name("origins.json")
        try:
            data = json.loads(bundled.read_text(encoding="utf-8"))
            origins = data.get("origins", {})
            for host, category in origins.items():
                if category in CATEGORIES:
                    self._map[host.lower()] = category
        except Exception:
            pass

    def _load_user(self) -> None:
        try:
            data = json.loads(self.user_db_path.read_text(encoding="utf-8"))
            origins = data.get("origins", {}) if isinstance(data, dict) else {}
            for host, entry in origins.items():
                # promote() writes {host: {"category": ..., "source": ...}};
                # tolerate plain-string values too.
                category = entry.get("category") if isinstance(entry, dict) else entry
                if category in CATEGORIES:
                    self._map[host.lower()] = category
        except Exception:
            pass

    def classify(self, host: str) -> Optional[str]:
        """Category for a host (exact or ``*.host`` suffix match), else None."""
        host = (host or "").lower().strip(".")
        if host in self._map:
            return self._map[host]
        labels = host.split(".")
        for i in range(1, len(labels)):
            suffix = ".".join(labels[i:])
            if suffix in self._map:
                return self._map[suffix]
        return None

    def is_known(self, host: str) -> bool:
        return self.classify(host) is not None

    def is_benign(self, host: str) -> bool:
        return (host or "").lower().strip(".") in KNOWN_BENIGN

    def entries(self) -> Dict[str, str]:
        return dict(sorted(self._map.items()))

    def promote(self, host: str, category: str, source: str = "", url: str = "") -> bool:
        """Validate a candidate and merge it into the operator user DB.

        Validation: category must be known, host must be a plausible bare host
        (no scheme/path), and the entry must not collide with a bundled entry
        under a DIFFERENT category. Returns True when merged.
        """
        host = (host or "").lower().strip(".")
        if not host or category not in CATEGORIES:
            return False
        if "/" in host or host.startswith(("http://", "https://")):
            return False
        bundled = self._map.get(host)
        if bundled and bundled != category:
            return False
        user: Dict[str, Any] = {"origins": {}}
        if self.user_db_path.exists():
            try:
                user = json.loads(self.user_db_path.read_text(encoding="utf-8"))
            except Exception:
                user = {"origins": {}}
            user.setdefault("origins", {})
        entry = {"category": category}
        if source:
            entry["source"] = source
        if url:
            entry["url"] = url
        user["origins"][host] = entry
        self.user_db_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.user_db_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(user, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.user_db_path)
        self._map[host] = category
        return True


class ObservedIntel:
    """Origins actually observed during a hostile pass (per-site, ephemeral)."""

    def __init__(self) -> None:
        self.origins: Dict[str, Dict[str, Any]] = {}

    def record(self, url: str, kind: str = "script", integrity: bool = True,
               cleartext: bool = False) -> None:
        host = origin_of(url)
        if not host:
            return
        entry = self.origins.setdefault(host, {
            "host": host,
            "kinds": set(),
            "count": 0,
            "cleartext": False,
            "sri_missing": False,
            "urls": [],
        })
        entry["kinds"].add(kind)
        entry["count"] += 1
        entry["cleartext"] = entry["cleartext"] or cleartext
        entry["sri_missing"] = entry["sri_missing"] or (not integrity)
        if url not in entry["urls"] and len(entry["urls"]) < 5:
            entry["urls"].append(url)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for host, e in sorted(self.origins.items()):
            out[host] = {
                "host": e["host"],
                "kinds": sorted(e["kinds"]),
                "count": e["count"],
                "cleartext": e["cleartext"],
                "sri_missing": e["sri_missing"],
                "urls": e["urls"],
            }
        return out

    def export(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return path


def domain_flux(prior: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, List[str]]:
    """Diff a previous scan's observed origins against the current set (M6).

    Streaming/piracy sites rotate ad domains; a host present last scan and
    gone now, or new now, is the flux signal.
    """
    prior_hosts = set((prior or {}).keys())
    current_hosts = set((current or {}).keys())
    return {
        "added": sorted(current_hosts - prior_hosts),
        "removed": sorted(prior_hosts - current_hosts),
    }
