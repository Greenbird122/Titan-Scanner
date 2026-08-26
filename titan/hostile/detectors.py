"""Track G hostile-content detectors — static signatures on page HTML/JS (M3).

Every detector is a pure string function returning typed signals:

    {"signal": str, "oracle": str, "severity": str, "confidence": float}

``oracle`` names the deterministic signature that backs the signal (the Track G
evidence discipline: reflection is never evidence, named signatures are). A
signal becomes a finding via ``titan.hostile.build_signal_finding``.

The zairaku.rest cloak is the reference case: F12 / ctrl+shift+I / ctrl+U /
context-menu blockers, an infinite ``constructor('debugger')`` loop and
devtools window-size detection — all deterministic JS text, all detectable
without executing anything.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

_CLOAK_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "F12 / devtools-keyboard blocker",
        "oracle": "cloak:keyboard-block",
        "regex": re.compile(
            r"keydown[^;]{0,300}(f12|key\s*===\s*['\"]f12['\"]|key\.toUpperCase\(\).{0,20}f12)",
            re.I,
        ),
        "severity": "info",
        "confidence": 0.85,
    },
    {
        "name": "view-source / ctrl+U blocker",
        "oracle": "cloak:view-source-block",
        "regex": re.compile(
            r"key\.toUpperCase\(\).{0,20}u.{0,80}preventDefault|preventDefault\(\).{0,120}(ctrlkey|key\.toUpperCase\(\).{0,20}u)",
            re.I,
        ),
        "severity": "info",
        "confidence": 0.8,
    },
    {
        "name": "context menu disabled",
        "oracle": "cloak:context-menu-block",
        "regex": re.compile(r"contextmenu[^;]{0,120}preventDefault", re.I),
        "severity": "info",
        "confidence": 0.9,
    },
    {
        "name": "infinite debugger loop",
        "oracle": "cloak:debugger-loop",
        "regex": re.compile(r"constructor\s*\(\s*['\"]debugger['\"]\s*\)", re.I),
        "severity": "low",
        "confidence": 0.95,
    },
    {
        "name": "devtools window-size detection (page hides itself)",
        "oracle": "cloak:devtools-size-detect",
        "regex": re.compile(
            r"outerWidth\s*-\s*(?:window\.)?innerWidth|outerHeight\s*-\s*(?:window\.)?innerHeight",
            re.I,
        ),
        "severity": "low",
        "confidence": 0.9,
    },
    {
        "name": "console silenced (anti-inspection)",
        "oracle": "cloak:console-noop",
        "regex": re.compile(r"console\[\s*[a-z]+\s*\]\s*=\s*(n|noop|function\s*\(\)\{\})", re.I),
        "severity": "info",
        "confidence": 0.85,
    },
]

_MINER_JS_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "browser-miner API calls (startMining/stopMining)",
        "oracle": "miner:js-api",
        "regex": re.compile(r"(startMining|stopMining|CoinHive|siteKey|authedmine|coinhive)", re.I),
        "severity": "high",
        "confidence": 0.9,
    },
    {
        "name": "crypto-hashing WASM loop (crypto.subtle + WebAssembly)",
        "oracle": "miner:wasm-hash-loop",
        "regex": re.compile(r"(crypto\.subtle|WebAssembly\.Module).{0,300}(hash|mine|pow)", re.I),
        "severity": "medium",
        "confidence": 0.7,
    },
]

_PUSH_JS_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "service-worker push registration",
        "oracle": "push:service-worker",
        "regex": re.compile(r"serviceWorker\.register\([^)]*sw[^)]*\.js", re.I),
        "severity": "low",
        "confidence": 0.8,
    },
    {
        "name": "push-permission request",
        "oracle": "push:request-permission",
        "regex": re.compile(r"Notification\.requestPermission", re.I),
        "severity": "low",
        "confidence": 0.9,
    },
    {
        "name": "push-subscribe call",
        "oracle": "push:subscribe",
        "regex": re.compile(r"pushManager\.subscribe", re.I),
        "severity": "low",
        "confidence": 0.9,
    },
]

_CLICKBAIT_MECHANICS: List[Dict[str, Any]] = [
    {
        "name": "countdown / fake-download timer",
        "oracle": "clickbait:countdown",
        "regex": re.compile(
            r"(your (download|file|video) (will|starts|begins)|download starts? in|"
            r"file is ready|creating download link|wait \d+ seconds|"
            r"your download will begin automatically|the download will start)",
            re.I,
        ),
        "severity": "low",
        "confidence": 0.85,
    },
    {
        "name": "prize / visitor-counter bait",
        "oracle": "clickbait:prize-bait",
        "regex": re.compile(
            r"(you are the [\d,]+(st|nd|rd|th) visitor|you have won|claim your prize|"
            r"congratulations[^.]{0,60}(win|prize)|1000(0)?000th visitor|your ip has been (selected|chosen))",
            re.I,
        ),
        "severity": "low",
        "confidence": 0.85,
    },
    {
        "name": "popunder window.open juggling",
        "oracle": "clickbait:popunder",
        "regex": re.compile(
            r"window\.open\([^)]*(width\s*=|height\s*=|left\s*=|top\s*=|location\s*=)", re.I
        ),
        "severity": "medium",
        "confidence": 0.8,
    },
    {
        "name": "auto-redirect on load",
        "oracle": "clickbait:auto-redirect",
        "regex": re.compile(r"(onload|DOMContentLoaded)[^;]{0,200}(location\.(replace|href)|top\.location)", re.I),
        "severity": "medium",
        "confidence": 0.8,
    },
    {
        "name": "fake play button overlay",
        "oracle": "clickbait:fake-play",
        "regex": re.compile(r"(play now|click (here|to) play|watch free)[^<]{0,80}onclick\s*=\s*['\"]window\.open", re.I),
        "severity": "low",
        "confidence": 0.7,
    },
]

# Sensational headline / thumbnail-bait words for the clickbait index.
_CLICKBAIT_WORDS = [
    "shocking", "you won't believe", "wont believe", "mind blown", "secret",
    "they don't want you", "dont want you", "click here", "must watch",
    "billion", "million", "free now", "limited time", "act now", "exposed",
    "leaked", "viral", "insane", "crazy", "never seen", "turns out", "what happens",
    "number 1", "top 10", "guaranteed", "miracle", "doctors hate", "this one trick",
]

_TERMINAL_KEYWORDS: Dict[str, List[str]] = {
    "phishing": ["verify", "secure-", "account-suspended", "unusual-login",
                 "update-payment", "confirm-identity", "myaccount", "login",
                 "password-reset", "restore-account"],
    "fake_download": ["download", ".exe", ".apk", "setup", "installer", ".zip",
                      "download.php", "get-file", "dl.php"],
    "adult": ["adult", "cam", "porn", "xxx", "hot-single", "meet-local"],
    "casino": ["casino", "jackpot", "slot", "bet", "poker", "roulette"],
    "sweepstakes": ["prize", "winner", "claim", "sweepstakes", "lucky"],
}


def _signals_from_patterns(html: str, patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    for p in patterns:
        try:
            if p["regex"].search(html or ""):
                found.append({
                    "signal": p["name"],
                    "oracle": p["oracle"],
                    "severity": p["severity"],
                    "confidence": p["confidence"],
                })
        except Exception:
            continue
    return found


def detect_cloaks(html: str) -> List[Dict[str, Any]]:
    """Anti-debug / anti-inspection cloaking signatures."""
    return _signals_from_patterns(html, _CLOAK_PATTERNS)


def detect_miners(html: str) -> List[Dict[str, Any]]:
    """Browser-miner / crypto-jacking signatures (hostname + JS behavior)."""
    found = _signals_from_patterns(html, _MINER_JS_PATTERNS)
    for host in ("coinhive.com", "authedmine.com", "coinimp.com", "cryptoloot.pro", "webminepool.com"):
        if re.search(re.escape(host), (html or ""), re.I) and not any(
            s["oracle"] == "miner:host:" + host for s in found
        ):
            found.append({
                "signal": f"known miner origin ({host})",
                "oracle": "miner:host:" + host,
                "severity": "high",
                "confidence": 0.95,
            })
    return found


def detect_push_notif(html: str) -> List[Dict[str, Any]]:
    """Service-worker / push-notification prompt patterns."""
    return _signals_from_patterns(html, _PUSH_JS_PATTERNS)


def detect_clickbait_mechanics(html: str) -> List[Dict[str, Any]]:
    """Ad-mechanics clickbait: countdowns, popunders, auto-redirects."""
    return _signals_from_patterns(html, _CLICKBAIT_MECHANICS)


def clickbait_index(html: str) -> Dict[str, Any]:
    """Per-page clickbait score 0-100 + the signals that produced it.

    Content scoring (operator decision): sensational headline words plus the
    mechanical signals. The score is a heuristic — never a vulnerability.
    """
    text = (html or "").lower()
    word_signals: List[str] = []
    for word in _CLICKBAIT_WORDS:
        if word in text and len(word_signals) < 8:
            word_signals.append(word)
    mech = detect_clickbait_mechanics(html)
    mech_names = [m["signal"] for m in mech]
    # Mechanic signal names are content evidence too ("prize / visitor-counter
    # bait", "countdown / fake-download timer", ...) — surface them alongside
    # the word hits so the index is auditable end-to-end.
    signals = word_signals + [n for n in mech_names if n not in word_signals][:6]
    score = min(100, len(signals) * 6 + len(mech) * 12)
    return {
        "score": score,
        "signals": signals,
        "mechanics": mech_names,
        "grade": "high" if score >= 50 else ("medium" if score >= 25 else "low"),
    }


def classify_terminal(url: str) -> Dict[str, Any]:
    """Classify a redirect-chain terminal URL by keyword (M5 evidence)."""
    low = (url or "").lower()
    for category, keywords in _TERMINAL_KEYWORDS.items():
        hits = [k for k in keywords if k in low]
        if hits:
            return {"category": category, "confidence": min(0.95, 0.5 + len(hits) * 0.15), "keywords": hits}
    return {"category": "unknown", "confidence": 0.2, "keywords": []}
