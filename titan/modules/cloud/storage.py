"""Cloud storage public-listing probe (Track D).

A bucket referenced by the target (leaked URL, hardcoded key context, echoed
body, discovered API) may be publicly listable. This module extracts bucket
candidates from the scan's own evidence and probes each for PUBLIC LISTING —
the objective, non-destructive test: a GET to the bucket's provider-specific
listing endpoint returning 200 with object keys means anyone can
enumerate/read the contents.

Discipline:
- Bucket references come ONLY from findings the scan already collected
  (bodies, payloads, metadata) — the probe never guesses bucket names.
- Each extraction is provider-tagged (S3 / GCS / Azure / R2) and probed at
  that provider's OWN listing endpoint — a GCS bucket is never tested at an
  S3 URL (that would 404 and read as "private").
- A 403/404/redirect response is a private bucket: no finding.
- Max 3 buckets per scan, short per-bucket timeout, every failure degrades
  to nothing. Driver-independent (aiohttp), so a dead Playwright driver
  cannot block it.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from titan.core.models import AttackType, Finding, Severity

# Bucket reference shapes found inside scan evidence, tagged with provider.
# Each pattern's group(1) is the bucket name (or container name).
_BUCKET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("s3", re.compile(r"https?://([a-z0-9][a-z0-9.\-]*)\.s3[.\-]([a-z0-9\-]+\.)?amazonaws\.com", re.IGNORECASE)),
    ("gcs", re.compile(r"https?://storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]*)", re.IGNORECASE)),
    ("azure", re.compile(r"https?://([a-z0-9][a-z0-9.\-]*)\.blob\.core\.windows\.net", re.IGNORECASE)),
    ("r2", re.compile(r"https?://([a-z0-9][a-z0-9.\-]*)\.r2\.cloudflarestorage\.com", re.IGNORECASE)),
]

# Provider -> listing endpoint. S3-style XML listing with object keys covers
# S3, GCS (list-type=2) and R2; Azure blob containers answer with <Blob>.
def _listing_url(bucket: str, provider: str) -> str:
    if provider == "gcs":
        return f"https://storage.googleapis.com/{bucket}?list-type=2"
    if provider == "azure":
        return f"https://{bucket}.blob.core.windows.net/?restype=container&comp=list"
    if provider == "r2":
        return f"https://{bucket}.r2.cloudflarestorage.com/?list-type=2"
    return f"https://{bucket}.s3.amazonaws.com/?list-type=2"


_LISTING_MARKERS = ("<Contents>", "<Key>", "<Blob>", "<Name>")

_MAX_BUCKETS = 3
_TIMEOUT = 8


def extract_bucket_refs(findings: List[Finding]) -> List[Tuple[str, str]]:
    """(bucket, provider) references found inside scan evidence (bodies,
    payloads, metadata values). Deduped by bucket name, ordered by first
    appearance."""
    refs: List[Tuple[str, str]] = []
    seen = set()
    for f in findings:
        haystacks = [
            f.body or "",
            f.payload or "",
            f.baseline_body or "",
            f.verification_body or "",
        ]
        for v in (f.metadata or {}).values():
            if isinstance(v, str):
                haystacks.append(v)
        for text in haystacks:
            for provider, pat in _BUCKET_PATTERNS:
                for m in pat.finditer(text or ""):
                    bucket = m.group(1).strip().lower()
                    if bucket and bucket not in seen:
                        seen.add(bucket)
                        refs.append((bucket, provider))
    return refs


def _is_public_listing(status: int, body: str) -> bool:
    """200 + an XML listing body (object keys present) = publicly listable."""
    if status != 200:
        return False
    lowered = (body or "").lower()
    return any(m.lower() in lowered for m in _LISTING_MARKERS)


class StorageProbe:
    """Probe extracted buckets for public listing.

    ``fetcher`` is an injectable ``async (url) -> (status, text)`` — tests
    script it exactly like FakeLabContext scripts HTTP. Default is aiohttp.
    """

    def __init__(
        self,
        fetcher: Optional[Callable[[str], Any]] = None,
        max_buckets: int = _MAX_BUCKETS,
    ):
        self._fetcher = fetcher
        self.max_buckets = max_buckets

    async def _fetch(self, url: str) -> Tuple[int, str]:
        if self._fetcher is not None:
            return await self._fetcher(url)
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=_TIMEOUT) as resp:
                    body = await resp.text()
                    return resp.status, body
        except Exception:
            return 0, ""

    async def scan(self, target: str, findings: List[Finding]) -> List[Finding]:
        results: List[Finding] = []
        for bucket, provider in extract_bucket_refs(findings)[: self.max_buckets]:
            url = _listing_url(bucket, provider)
            status, body = await self._fetch(url)
            if _is_public_listing(status, body):
                results.append(self._finding(target, bucket, provider, url, status, body))
        return results

    def _finding(
        self,
        target: str,
        bucket: str,
        provider: str,
        listing_url: str,
        status: int,
        body: str,
    ) -> Finding:
        return Finding(
            target=target,
            url=listing_url,
            method="GET",
            param="list-type",
            location="query",
            payload=f"Publicly listable cloud storage bucket ({provider}): {bucket}",
            attack_type=AttackType.PUBLIC_STORAGE,
            severity=Severity.HIGH,
            verified=True,
            confidence=0.9,
            status=status,
            body=body[:2000],
            diffs=[f"storage:public_listing:{bucket}", "storage:object_keys_visible"],
            verification_body=body[:2000],
            verification_status=status,
            metadata={"bucket": bucket, "provider": provider, "listing_url": listing_url},
        )
