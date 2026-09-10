"""Tests for titan.ai.waf_fingerprint — WAF identification and bypass mapping.

Pure logic: signature matching over probe responses, tier classification,
bypass payload generation, and learning-state updates. The async probe
path is exercised with a fake response function — no network.
"""


import pytest

from titan.ai.waf_fingerprint import WAFFingerprint, WAFFingerprinter


def _resp(status=200, body="", headers=None):
    async def _fn(url, payload, hdrs):
        return {"status": status, "body": body, "headers": headers or {}}

    return _fn


class TestDataclass:
    def test_fingerprint_defaults(self):
        fp = WAFFingerprint(name="cloudflare")
        assert fp.version is None
        assert fp.tier is None
        assert fp.rules == []
        assert fp.bypass_strategies == []
        assert fp.confidence == 0.0
        assert fp.scan_count == 0
        assert fp.block_rate == 0.0


class TestAnalyzeProbes:
    def test_no_probes_yields_unknown(self):
        fp = WAFFingerprinter()._analyze_probes([])
        assert fp.name == "unknown"
        assert fp.confidence == 0.0

    def test_header_match_identifies_cloudflare(self):
        # cf-cache-status is unique to the plain cloudflare signature set
        # (cf-ray alone also matches cloudflare_bot_management, which — being
        # last in WAF_SIGNATURES — wins; see test_last_match_wins below)
        probes = [{
            "probe": "sqli_probe",
            "status": 200,
            "body": "hello",
            "headers": {"CF-Cache-Status": "DYNAMIC"},
        }]
        fp = WAFFingerprinter()._analyze_probes(probes)
        assert fp.name == "cloudflare"
        assert fp.detection_method.startswith("header:cf")
        assert fp.confidence >= 0.9

    def test_last_match_wins_on_shared_signatures(self):
        # Documented quirk: probe analysis iterates all WAFs and later
        # matches overwrite earlier ones regardless of confidence.
        probes = [{
            "probe": "sqli_probe",
            "status": 200,
            "body": "hello",
            "headers": {"CF-Ray": "82e1a"},
        }]
        fp = WAFFingerprinter()._analyze_probes(probes)
        assert fp.name == "cloudflare_bot_management"

    def test_body_match_identifies_challenge_page(self):
        probes = [{
            "probe": "xss_probe",
            "status": 503,
            "body": "Please wait: Just a Moment while we verify...",
            "headers": {},
        }]
        fp = WAFFingerprinter()._analyze_probes(probes)
        assert fp.name == "cloudflare"
        assert fp.detection_method.startswith("body:")
        assert fp.confidence == 0.95

    def test_body_match_identifies_imperva(self):
        probes = [{
            "probe": "sqli_probe",
            "status": 403,
            "body": "Request blocked by Incapsula. Incident Id: 42",
            "headers": {},
        }]
        fp = WAFFingerprinter()._analyze_probes(probes)
        assert fp.name == "imperva"
        assert fp.confidence == 0.95

    def test_status_only_match_is_lower_confidence(self):
        # 403 with no WAF-specific headers/body: falls to status-code heuristics
        probes = [{"probe": "sqli_probe", "status": 403, "body": "nope", "headers": {}}]
        fp = WAFFingerprinter()._analyze_probes(probes)
        assert fp.name != "unknown"
        assert fp.detection_method.startswith("status:")
        assert fp.confidence == 0.7

    def test_body_match_outranks_earlier_header_match(self):
        probes = [
            {"probe": "p1", "status": 200, "body": "", "headers": {"CF-Ray": "x"}},
            {"probe": "p2", "status": 403, "body": "Incapsula incident id", "headers": {}},
        ]
        fp = WAFFingerprinter()._analyze_probes(probes)
        assert fp.name == "imperva"
        assert fp.confidence == 0.95


class TestClassifyTier:
    def test_cloudflare_free_tier(self):
        p = WAFFingerprinter()
        fp = WAFFingerprint(name="cloudflare")
        probes = [{
            "probe": "p",
            "status": 503,
            "body": "checking your browser",
            "headers": {"cf-ray": "8x"},
        }]
        assert p._classify_tier(fp, probes) == "free"

    def test_tierless_waf_gets_default(self):
        p = WAFFingerprinter()
        fp = WAFFingerprint(name="akamai")
        assert p._classify_tier(fp, []) == "default"

    def test_unknown_waf_returns_none(self):
        p = WAFFingerprinter()
        fp = WAFFingerprint(name="not-a-waf")
        assert p._classify_tier(fp, []) is None


class TestFingerprintWaf:
    @pytest.mark.asyncio
    async def test_full_pipeline_stores_fingerprint(self):
        # "Attention Required ... Cloudflare" matches ONLY the plain
        # cloudflare body signature — "checking your browser" bodies are
        # shadowed by cloudflare_bot_management (later dict entry, same
        # patterns), whose fingerprints classify as tier "default".
        p = WAFFingerprinter()
        rf = _resp(
            status=403,
            body="Attention Required! | Cloudflare Ray ID: 8a2b",
            headers={},
        )
        fp = await p.fingerprint_waf("http://t.example", rf)
        assert fp.name == "cloudflare"
        assert fp.tier == "default"
        # "default" is not a key in cloudflare's tier strategy table, so no
        # bypass strategies are attached on this path.
        assert fp.bypass_strategies == []
        assert p.get_fingerprint("http://t.example") is fp

    @pytest.mark.asyncio
    async def test_no_waf_fingerprint_is_unknown(self):
        p = WAFFingerprinter()
        rf = _resp(status=200, body="welcome", headers={})
        fp = await p.fingerprint_waf("http://t.example", rf)
        assert fp.name == "unknown"
        assert fp.tier is None

    @pytest.mark.asyncio
    async def test_probe_failures_are_tolerated(self):
        async def broken(url, payload, headers):
            raise ConnectionError("boom")

        p = WAFFingerprinter()
        fp = await p.fingerprint_waf("http://t.example", broken)
        assert fp.name == "unknown"


class TestBypassPayloads:
    def test_known_waf_and_tier(self):
        p = WAFFingerprinter()
        payloads = p.get_bypass_payloads("cloudflare", "sqli", tier="free")
        assert payloads  # non-empty
        assert all(isinstance(x, str) for x in payloads)
        # free tier includes unicode_normalization + null_byte strategies
        joined = " ".join(payloads)
        assert "UNI" in joined.upper()

    def test_default_tier_used_when_tier_omitted(self):
        p = WAFFingerprinter()
        assert p.get_bypass_payloads("akamai", "sqli")

    def test_unknown_waf_returns_empty(self):
        p = WAFFingerprinter()
        assert p.get_bypass_payloads("definitely-not-a-waf", "sqli") == []

    def test_enterprise_superset_includes_free_strategies(self):
        p = WAFFingerprinter()
        free = set(WAFFingerprinter.BYPASS_STRATEGIES["cloudflare"]["free"])
        ent = set(WAFFingerprinter.BYPASS_STRATEGIES["cloudflare"]["enterprise"])
        assert free <= ent
        ent_payloads = p.get_bypass_payloads("cloudflare", "sqli", tier="enterprise")
        assert len(ent_payloads) > len(p.get_bypass_payloads("cloudflare", "sqli", tier="free"))


class TestUpdateFromScan:
    def test_creates_and_updates_fingerprint(self):
        p = WAFFingerprinter()
        p.update_from_scan("cloudflare", blocked_patterns=["union select"],
                           successful_bypasses=["case_variation"])
        fp = p.fingerprints["cloudflare"]
        assert fp.scan_count == 1
        assert fp.blocked_patterns == ["union select"]
        assert fp.successful_bypasses == ["case_variation"]
        assert fp.block_rate == pytest.approx(0.5)

    def test_block_rate_reflects_ratio(self):
        p = WAFFingerprinter()
        p.update_from_scan("cloudflare",
                           blocked_patterns=["b1", "b2"],
                           successful_bypasses=["s1"])
        assert p.fingerprints["cloudflare"].block_rate == pytest.approx(2 / 3)

    def test_history_trimmed_to_100(self):
        p = WAFFingerprinter()
        p.update_from_scan("cloudflare", blocked_patterns=[f"p{i}" for i in range(150)],
                           successful_bypasses=[])
        fp = p.fingerprints["cloudflare"]
        assert len(fp.blocked_patterns) == 100
        assert fp.blocked_patterns[-1] == "p149"  # newest retained

    def test_get_fingerprint_missing_returns_none(self):
        assert WAFFingerprinter().get_fingerprint("http://nope") is None
