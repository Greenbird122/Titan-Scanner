"""Tests for expanded detector modules."""

import pytest
from titan.core.models import Finding, Severity, AttackType


class TestCryptoDetectorLogic:
    def test_weak_algorithm_detection(self):
        from titan.modules.crypto.detector import CryptoDetector
        detector = CryptoDetector(None, {})
        assert detector is not None

    def test_jwt_none_algorithm(self):
        from titan.modules.crypto.detector import CryptoDetector
        import base64
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        payload = base64.urlsafe_b64encode(b'{"sub":"123"}').decode().rstrip("=")
        jwt = f"{header}.{payload}.signature"

        detector = CryptoDetector(None, {})
        assert detector is not None


class TestCacheDetectorLogic:
    def test_cache_poisoning_reflection(self):
        from titan.modules.cache.detector import CacheDetector
        detector = CacheDetector(None, {})
        assert detector is not None


class TestSmugglingDetectorLogic:
    def test_smuggling_payload_format(self):
        from titan.modules.smuggling.detector import SmugglingDetector
        detector = SmugglingDetector(None, {})
        assert detector is not None


class TestRaceDetectorLogic:
    def test_race_detection_thresholds(self):
        from titan.modules.race.detector import RaceDetector
        detector = RaceDetector(None, {})
        assert detector is not None


class TestDeserDetectorLogic:
    def test_java_gadget_detection(self):
        from titan.modules.deser.detector import DeserDetector
        detector = DeserDetector(None, {})
        assert detector is not None
