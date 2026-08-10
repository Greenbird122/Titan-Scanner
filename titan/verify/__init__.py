"""Verification subsystem for Titan Scanner."""

from __future__ import annotations

import hashlib
import json
import os
import re
import statistics
import time
from typing import Any, Dict, List, Optional, Tuple

from titan.core.models import Finding


class ConfirmationOracle:
    """Layered confirmation engine. Evidence ranks the label."""

    ORACLE_WEIGHTS = {
        "sanity_pair": 0.35,
        "error_class": 0.30,
        "structural_json": 0.25,
        "reflection": 0.20,
        "length_diff": 0.10,
        "status_change": 0.10,
        "content_hash": 0.05,
    }

    @classmethod
    def score(cls, diffs: List[str], attack_type: str, payload: str, baseline: str, test: str, status: int, baseline_status: int) -> Tuple[float, bool]:
        score = 0.0
        verified = False

        for diff in diffs:
            dl = diff.lower()
            if "sanity_pair:boolean_confirmed" in dl:
                score += cls.ORACLE_WEIGHTS["sanity_pair"]
            if "error_class:" in dl:
                score += cls.ORACLE_WEIGHTS["error_class"]
            if "json:" in dl:
                score += cls.ORACLE_WEIGHTS["structural_json"]
            if "payload_reflected" in dl:
                score += cls.ORACLE_WEIGHTS["reflection"]
            if "length_diff" in dl or "response_length" in dl:
                score += cls.ORACLE_WEIGHTS["length_diff"]
            if "header:" in dl:
                score += cls.ORACLE_WEIGHTS["status_change"]
            if "content_hash_changed" in dl:
                score += cls.ORACLE_WEIGHTS["content_hash"]

        # Strong evidence overrides
        if attack_type == "SQLi" and any(sig in test.lower() for sig in ["sql syntax", "mysql", "ora-", "postgresql", "syntax error"]):
            verified = True
            score = max(score, 0.9)
        elif attack_type == "XSS" and payload in test and ("<script>" in test.lower() or "onerror" in test.lower()):
            verified = True
            score = max(score, 0.85)
        elif attack_type == "LFI" and any(ind in test.lower() for ind in ["root:", "daemon:", "etc/passwd", "windows", "system32"]):
            verified = True
            score = max(score, 0.9)
        elif attack_type == "RCE" and any(ind in test.lower() for ind in ["root:", "uid=", "gid=", "directory of", "volume serial"]):
            verified = True
            score = max(score, 0.95)
        elif attack_type == "SSRF" and any(ind in test.lower() for ind in ["ami-id", "meta-data", "root:", "internal", "127.0.0.1"]):
            verified = True
            score = max(score, 0.95)
        elif attack_type == "IDOR" and "json:" in " ".join(diffs):
            verified = True
            score = max(score, 0.85)

        # Status change bonus
        if status != baseline_status and status in (401, 403, 500):
            score += 0.15

        return min(1.0, score), verified


class BaselineAnalyzer:
    @staticmethod
    def diff_responses(baseline: str, injected: str, payload: str) -> List[str]:
        diffs = []
        if not baseline:
            return diffs

        b_hash = hashlib.sha256(baseline.encode()).hexdigest()
        i_hash = hashlib.sha256(injected.encode()).hexdigest()
        if b_hash != i_hash:
            diffs.append("content_hash_changed")

        b_len = len(baseline)
        i_len = len(injected)
        if i_len > b_len * 1.5:
            diffs.append("response_length_increased")
        elif i_len < b_len * 0.5:
            diffs.append("response_length_decreased")

        b_lower = baseline.lower()
        i_lower = injected.lower()

        if payload.lower() in i_lower and payload.lower() not in b_lower:
            diffs.append("payload_reflected")

        error_signatures = [
            "sql syntax", "mysql_fetch_array", "ora-", "postgresql",
            "warning: mysql", "syntax error", "sqlstate", "odbc driver",
            "unclosed quotation mark", "quoted string not properly terminated",
        ]
        for sig in error_signatures:
            if sig in i_lower and sig not in b_lower:
                diffs.append(f"error:{sig}")
                break

        return diffs

    @staticmethod
    def diff_json(baseline: Any, injected: Any) -> List[str]:
        diffs = []
        if isinstance(baseline, dict) and isinstance(injected, dict):
            b_keys = set(baseline.keys())
            i_keys = set(injected.keys())
            if b_keys != i_keys:
                diffs.append("json:keys_changed")
            for key in b_keys & i_keys:
                if baseline[key] != injected[key]:
                    diffs.append(f"json:{key}")
        elif isinstance(baseline, list) and isinstance(injected, list):
            if len(baseline) != len(injected):
                diffs.append("json:length_changed")
        return diffs

    @staticmethod
    def diff_headers(baseline: Dict[str, str], injected: Dict[str, str]) -> List[str]:
        diffs = []
        b_keys = {k.lower(): k for k in baseline.keys()}
        i_keys = {k.lower(): k for k in injected.keys()}
        for key in set(b_keys) | set(i_keys):
            b_val = baseline.get(b_keys.get(key, key), "")
            i_val = injected.get(i_keys.get(key, key), "")
            if b_val != i_val:
                diffs.append(f"header:{key}")
        return diffs


class BlindDetector:
    # Set once per process: the first unexpected exception inside the timing
    # loop is printed instead of silently swallowed, so a bug like the
    # historical `cookies=` TypeError can never hide again.
    _warned_unexpected = False

    # Timing payloads declare their delay (SLEEP(3), pg_sleep(3), WAITFOR
    # DELAY '0:0:3'). The declared delay is the discriminator between a real
    # blind injection and mere server load variance.
    _DECLARED_DELAY = re.compile(
        r"(?:sleep\s*\(|pg_sleep\s*\(|waitfor\s+delay\s+['\"]0:0:)(\d+)",
        re.IGNORECASE,
    )

    @staticmethod
    def _declared_delay(payload: str) -> float:
        m = BlindDetector._DECLARED_DELAY.search(payload or "")
        return float(m.group(1)) if m else 0.0

    def __init__(self, samples: int = 5, confidence: float = 0.95):
        self.samples = samples
        self.confidence = confidence

    async def detect_time_based(
        self,
        context,
        url: str,
        method: str,
        params: Dict[str, str],
        data: Dict[str, str],
        headers: Dict[str, str],
        payload: str,
        location: str,
        baseline_times: List[float],
        param_name: Optional[str] = None,
    ) -> Tuple[bool, float]:
        injected_times = []
        # Time-based detection is statistical: it needs a minimum of 2 samples
        # (and ideally 3+) to be meaningful. Never let samples=1 silently kill it.
        sample_count = max(self.samples, 2)
        for _ in range(sample_count):
            start = time.monotonic()
            try:
                # NOTE: Playwright's APIRequestContext.get/post have NO `cookies`
                # kwarg (passing one raises TypeError, which a bare except used to
                # swallow — that is the historical bug that returned elapsed=0.0).
                # Session cookies are already in the shared BrowserContext cookie
                # jar, so auth is conveyed automatically.
                if location == "query":
                    inject_key = param_name or (next(iter(params), "q") if params else "q")
                    await context.request.get(url, params={**params, inject_key: payload}, headers=headers, timeout=10000)
                elif location == "body":
                    inject_key = param_name or (next(iter(data), "q") if data else "q")
                    await context.request.post(url, data={**data, inject_key: payload}, headers=headers, timeout=10000)
                else:
                    await context.request.get(url, headers=headers, timeout=10000)
                injected_times.append(time.monotonic() - start)
            except Exception as exc:
                elapsed = time.monotonic() - start
                if elapsed >= 1.0:
                    # A request that hangs long enough to blow the request
                    # timeout IS timing evidence (the server delayed). Record
                    # it as a sample instead of discarding the strongest signal.
                    injected_times.append(elapsed)
                else:
                    # Fast failure = transient error or a bug. Surface it once
                    # so silent failures (like the cookies= TypeError) can never
                    # hide again.
                    if not BlindDetector._warned_unexpected:
                        BlindDetector._warned_unexpected = True
                        print(f"      [!] BlindDetector unexpected error: {type(exc).__name__}: {exc}")
                    continue

        if len(injected_times) < 2:
            return False, 0.0

        baseline_mean = statistics.mean(baseline_times) if baseline_times else 0.5
        baseline_stdev = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0.1
        injected_mean = statistics.mean(injected_times)
        threshold = baseline_mean + (self.confidence * baseline_stdev)

        # Declared-sleep gate: a timing payload declares its delay (SLEEP(3)
        # -> ~3s). A genuine blind SQLi delays by roughly that much; a
        # slow/loaded endpoint merely adds load variance, which is typically
        # well under 75% of the declared delay. Without this gate, CDN/server
        # latency variance "confirmed" SLEEP(3) on clean production sites
        # (ctflearn /dashboard, recordedfuture at conf 0.60).
        declared = self._declared_delay(payload)
        delta = injected_mean - baseline_mean
        if declared and delta < declared * 0.75:
            return False, injected_mean

        if injected_mean > threshold and injected_mean > baseline_mean * 2:
            return True, injected_mean
        return False, injected_mean


class OOBDetector:
    def __init__(self, server: str = "https://interactsh.com"):
        self.server = server
        self.correlation_id = hashlib.sha256(os.urandom(16)).hexdigest()[:20]

    async def register(self) -> bool:
        try:
            import aiohttp
            url = f"{self.server}/register"
            payload = {"correlation-id": self.correlation_id, "format": "json"}
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=10) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def poll(self, timeout: int = 30) -> List[Dict[str, Any]]:
        try:
            import aiohttp
            url = f"{self.server}/poll?id={self.correlation_id}&format=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=timeout) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("data", {}).get("interactions", [])
        except Exception:
            pass
        return []

    def generate_oob_url(self, suffix: str = "test") -> str:
        return f"http://{self.correlation_id}.{suffix}.{self.server.replace('https://', '').replace('http://', '')}"
