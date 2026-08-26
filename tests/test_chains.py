"""Track D — flow-typed chain analysis + cloud storage probe tests.

The chain analyzer joins findings whose FLOWS (capabilities) combine into
attack goals — it MUST run after apply_flows (the ordering is itself a test
here). The storage probe extracts bucket references from the scan's OWN
evidence and treats a 200 XML-listing response as the public-exposure oracle.

Assertions enforce the oracle semantics: >= 2 distinct findings whose
combined flows cover a goal's required set (with no passengers) form a
chain; unverified findings and single findings never chain; a bucket is
flagged only when its listing endpoint returns 200 with object keys.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from titan.core.models import AttackType, Finding, ScanResult, Severity
from titan.verify.chain_analyzer import ChainAnalyzer
from titan.verify.flows import apply_flows


def _mkf(
    attack_type,
    url="http://t/api",
    flows=None,
    verified=True,
    severity=Severity.HIGH,
    body="",
    payload="",
):
    f = Finding(
        target="http://t",
        url=url,
        method="GET",
        param="id",
        location="query",
        payload=payload,
        attack_type=attack_type,
        severity=severity,
        verified=verified,
        confidence=0.9,
        body=body,
    )
    if flows is not None:
        f.flows = list(flows)
    return f


# ─── Chain analyzer ─────────────────────────────────────────────────────────


class TestChainAnalyzer:
    def test_ssrf_metadata_plus_hardcoded_key_forms_cloud_chain(self):
        ssrf = _mkf(AttackType.SSRF, url="http://t/proxy", flows=["url_fetch", "creds"],
                    payload="http://169.254.169.254/latest/meta-data/")
        key = _mkf(AttackType.CRYPTO_WEAKNESS, url="http://t/config", flows=["creds"],
                   payload="hardcoded AWS key AKIA...")
        chains = ChainAnalyzer().detect([ssrf, key])
        names = [c.name for c in chains]
        assert "Cloud Credential Exposure" in names, f"expected cloud chain, got {names}"
        chain = next(c for c in chains if c.name == "Cloud Credential Exposure")
        assert len(chain.hops) == 2
        assert {f.url for f in chain.hops} == {"http://t/proxy", "http://t/config"}
        assert chain.severity == Severity.CRITICAL

    def test_auth_bypass_plus_data_leak_forms_cross_tenant_chain(self):
        nosqli = _mkf(AttackType.NO_SQLI, flows=["auth_bypass", "data_leak"])
        idor = _mkf(AttackType.IDOR, flows=["data_leak"])
        chains = ChainAnalyzer().detect([nosqli, idor])
        assert "Unauthorized Cross-Tenant Access" in [c.name for c in chains]

    def test_single_finding_with_all_flows_does_not_chain(self):
        # A lone SSRF-to-metadata carries url_fetch + creds but a chain needs
        # >= 2 distinct findings.
        ssrf = _mkf(AttackType.SSRF, flows=["url_fetch", "creds"])
        assert ChainAnalyzer().detect([ssrf]) == []

    def test_passenger_finding_does_not_chain(self):
        # An OOB-only finding provides no flow required by the cloud goal —
        # it must not ride along as a passenger.
        ssrf = _mkf(AttackType.SSRF, flows=["url_fetch", "creds"])
        oob = _mkf(AttackType.OOB, flows=["oob"])
        assert ChainAnalyzer().detect([ssrf, oob]) == []

    def test_unverified_findings_never_chain(self):
        ssrf = _mkf(AttackType.SSRF, flows=["url_fetch", "creds"], verified=False)
        key = _mkf(AttackType.CRYPTO_WEAKNESS, flows=["creds"], verified=False)
        assert ChainAnalyzer().detect([ssrf, key]) == []

    def test_analyzer_requires_flows_prepopulated(self):
        # The analyzer reads Finding.flows — with no apply_flows, nothing
        # chains (this pins the scan-end ordering dependency).
        ssrf = _mkf(AttackType.SSRF, flows=None, payload="http://169.254.169.254/x")
        key = _mkf(AttackType.CRYPTO_WEAKNESS, flows=None)
        assert ChainAnalyzer().detect([ssrf, key]) == []

    def test_hops_ordered_and_chain_field_populated(self):
        ssrf = _mkf(AttackType.SSRF, url="http://t/proxy", flows=["url_fetch", "creds"])
        key = _mkf(AttackType.CRYPTO_WEAKNESS, url="http://t/config", flows=["creds"])
        chains = ChainAnalyzer().detect([ssrf, key])
        chain = chains[0]
        assert chain.hops[0].url == "http://t/proxy"  # url_fetch enabler first
        for f in chain.hops:
            others = [h.url for h in chain.hops if h is not f]
            if others:
                f.chain = list(dict.fromkeys(others))
        assert ssrf.chain == ["http://t/config"]
        assert key.chain == ["http://t/proxy"]

    def test_chain_to_dict_shape(self):
        ssrf = _mkf(AttackType.SSRF, flows=["url_fetch", "creds"])
        key = _mkf(AttackType.CRYPTO_WEAKNESS, flows=["creds"])
        chain = ChainAnalyzer().detect([ssrf, key])[0]
        d = chain.to_dict()
        assert d["name"] == "Cloud Credential Exposure"
        assert d["severity"] == "critical"
        assert "creds" in d["capabilities"]
        assert len(d["hops"]) == 2
        assert d["hops"][0]["flows"]  # per-hop evidence serialized

    def test_public_storage_finding_chains_with_ssrf(self):
        bucket = _mkf(AttackType.PUBLIC_STORAGE, url="http://bucket.s3.amazonaws.com/",
                      flows=["data_leak"])
        ssrf = _mkf(AttackType.SSRF, flows=["url_fetch"])
        names = [c.name for c in ChainAnalyzer().detect([bucket, ssrf])]
        assert "Public Cloud Storage Exposure" in names

    def test_storage_chain_names_the_bucket_not_unrelated_leaks(self):
        # With other data_leak findings present (NoSQLi, IDOR), the storage
        # chain must still name the PUBLIC_STORAGE bucket finding — the
        # thematic tie-break picks the direct evidence.
        bucket = _mkf(AttackType.PUBLIC_STORAGE, url="http://bucket.s3.amazonaws.com/",
                      flows=["data_leak"])
        ssrf = _mkf(AttackType.SSRF, url="http://t/proxy", flows=["url_fetch"])
        nosqli = _mkf(AttackType.NO_SQLI, url="http://t/login", flows=["auth_bypass", "data_leak"])
        idor = _mkf(AttackType.IDOR, url="http://t/records", flows=["data_leak"])
        chains = ChainAnalyzer().detect([bucket, ssrf, nosqli, idor])
        storage = next(c for c in chains if c.name == "Public Cloud Storage Exposure")
        assert {f.url for f in storage.hops} == {"http://bucket.s3.amazonaws.com/", "http://t/proxy"}


# ─── Storage probe ──────────────────────────────────────────────────────────


class TestStorageProbe:
    def test_extract_bucket_refs_from_body(self):
        from titan.modules.cloud.storage import extract_bucket_refs
        f = _mkf(AttackType.INFO_LEAK, body="backup at https://myapp-data.s3.amazonaws.com/x.zip")
        assert extract_bucket_refs([f]) == [("myapp-data", "s3")]

    def test_extract_gcs_bucket(self):
        from titan.modules.cloud.storage import extract_bucket_refs
        f = _mkf(AttackType.INFO_LEAK, body="https://storage.googleapis.com/uploads/photo.png")
        assert extract_bucket_refs([f]) == [("uploads", "gcs")]

    def test_extract_dedupes(self):
        from titan.modules.cloud.storage import extract_bucket_refs
        f = _mkf(AttackType.INFO_LEAK, body="https://a.s3.amazonaws.com/x and https://a.s3.amazonaws.com/y")
        assert extract_bucket_refs([f]) == [("a", "s3")]

    def test_no_bucket_refs_yields_nothing(self):
        from titan.modules.cloud.storage import extract_bucket_refs
        f = _mkf(AttackType.INFO_LEAK, body="no cloud refs here")
        assert extract_bucket_refs([f]) == []

    async def test_public_bucket_is_flagged(self):
        from titan.modules.cloud.storage import StorageProbe
        async def fetcher(url):
            return 200, "<ListBucketResult><Contents><Key>secret.db</Key></Contents></ListBucketResult>"
        bucket = _mkf(AttackType.INFO_LEAK, body="https://open-bucket.s3.amazonaws.com/x")
        findings = await StorageProbe(fetcher=fetcher).scan("http://t", [bucket])
        assert findings, "publicly listable bucket must be flagged"
        f = findings[0]
        assert f.attack_type == AttackType.PUBLIC_STORAGE
        assert f.verified is True
        assert f.severity.value == "high"
        apply_flows([f])
        assert f.flows == ["data_leak"]

    async def test_gcs_bucket_probed_at_gcs_endpoint(self):
        """A GCS-extracted bucket must be probed at the GCS listing endpoint,
        NOT an S3 URL (which would 404 and read as private)."""
        from titan.modules.cloud.storage import StorageProbe
        fetched = []

        async def fetcher(url):
            fetched.append(url)
            return 200, "<ListBucketResult><Contents><Key>doc.pdf</Key></Contents></ListBucketResult>"
        bucket = _mkf(AttackType.INFO_LEAK, body="https://storage.googleapis.com/uploads/photo.png")
        findings = await StorageProbe(fetcher=fetcher).scan("http://t", [bucket])
        assert findings, "publicly listable GCS bucket must be flagged"
        assert fetched == ["https://storage.googleapis.com/uploads?list-type=2"], f"got {fetched}"

    async def test_private_bucket_403_is_not_flagged(self):
        from titan.modules.cloud.storage import StorageProbe
        async def fetcher(url):
            return 403, "<Error><Code>AccessDenied</Code></Error>"
        bucket = _mkf(AttackType.INFO_LEAK, body="https://private.s3.amazonaws.com/x")
        findings = await StorageProbe(fetcher=fetcher).scan("http://t", [bucket])
        assert findings == []

    async def test_bucket_404_is_not_flagged(self):
        from titan.modules.cloud.storage import StorageProbe
        async def fetcher(url):
            return 404, "NoSuchBucket"
        bucket = _mkf(AttackType.INFO_LEAK, body="https://gone.s3.amazonaws.com/x")
        findings = await StorageProbe(fetcher=fetcher).scan("http://t", [bucket])
        assert findings == []

    async def test_200_html_without_listing_is_not_flagged(self):
        from titan.modules.cloud.storage import StorageProbe
        async def fetcher(url):
            return 200, "<html><body>static site</body></html>"
        bucket = _mkf(AttackType.INFO_LEAK, body="https://site.s3.amazonaws.com/x")
        findings = await StorageProbe(fetcher=fetcher).scan("http://t", [bucket])
        assert findings == []

    async def test_bucket_refs_never_guessed(self):
        from titan.modules.cloud.storage import StorageProbe
        called = []

        async def fetcher(url):
            called.append(url)
            return 200, "<Contents>"
        clean = _mkf(AttackType.INFO_LEAK, body="nothing cloud-related")
        await StorageProbe(fetcher=fetcher).scan("http://t", [clean])
        assert called == [], "probe must never fetch when no bucket is referenced"


# ─── Engine wiring ──────────────────────────────────────────────────────────


class TestStorageEngineWiring:
    async def test_storage_probe_runs_through_engine(self):
        from titan.core.engine import TitanEngine
        cfg = {"governance": {"enabled": False}, "ai": {"enabled": False}}
        engine = TitanEngine(cfg)

        async def fetcher(url):
            return 200, "<ListBucketResult><Contents><Key>data.db</Key></Contents></ListBucketResult>"
        engine._storage_fetcher = fetcher

        result = ScanResult(target="http://t", started_at=0)
        result.findings.append(
            _mkf(AttackType.INFO_LEAK, body="https://engine-bucket.s3.amazonaws.com/x")
        )
        await engine._run_storage_probe("http://t", result)
        storage = [f for f in result.findings if f.attack_type == AttackType.PUBLIC_STORAGE]
        assert storage, f"storage probe must fire through the engine seam, got {result.findings}"

    async def test_disabled_storage_skips(self):
        from titan.core.engine import TitanEngine
        cfg = {"governance": {"enabled": False}, "ai": {"enabled": False},
               "cloud": {"storage": {"enabled": False}}}
        engine = TitanEngine(cfg)
        called = []

        async def fetcher(url):
            called.append(url)
            raise AssertionError("must not fetch when the storage probe is disabled")
        engine._storage_fetcher = fetcher

        result = ScanResult(target="http://t", started_at=0)
        result.findings.append(
            _mkf(AttackType.INFO_LEAK, body="https://secret-bucket.s3.amazonaws.com/x")
        )
        await engine._run_storage_probe("http://t", result)
        assert called == [], "disabled storage probe must never fetch"
        assert not [f for f in result.findings if f.attack_type == AttackType.PUBLIC_STORAGE]


# ─── Reporting ──────────────────────────────────────────────────────────────


class TestReportChains:
    def test_report_contains_attack_chains_section(self):
        from titan.reporting import SiteReportWriter
        ssrf = _mkf(AttackType.SSRF, url="http://t/proxy", flows=["url_fetch", "creds"],
                    payload="http://169.254.169.254/")
        key = _mkf(AttackType.CRYPTO_WEAKNESS, url="http://t/config", flows=["creds"])
        chains = ChainAnalyzer().detect([ssrf, key])
        result = ScanResult(target="http://t", started_at=0)
        result.findings = [ssrf, key]
        result.chains = [c.to_dict() for c in chains]

        md = SiteReportWriter()._markdown(result)
        assert "## Attack Chains" in md
        assert "Cloud Credential Exposure" in md
        assert "http://t/proxy" in md
        assert "http://t/config" in md
        assert "creds" in md

    def test_report_without_chains_has_no_section(self):
        from titan.reporting import SiteReportWriter
        result = ScanResult(target="http://t", started_at=0)
        result.findings = [_mkf(AttackType.INFO_LEAK)]
        md = SiteReportWriter()._markdown(result)
        assert "## Attack Chains" not in md
