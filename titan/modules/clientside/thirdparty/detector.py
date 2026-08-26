"""Third-party script / skimmer heuristic — browser-context module (Track A).

Magecart-style skimmers load a script from a third-party origin that reads
form fields (card numbers, passwords) and exfiltrates them. This module
enumerates external scripts, scores each for skimmer indicators, and reports
the risky ones. It is a HEURISTIC (no deterministic exploit): findings are
unverified by design and ranked by confidence.

Indicators:
- script origin differs from the page origin (external)
- the page collects sensitive form fields (input[name*=card|password|ssn])
- the script is not from a known-good CDN/analytics origin
- the script is tiny and self-contained (skimmers are usually small)
"""

from __future__ import annotations

import json
from typing import Any, Dict, List
from urllib.parse import urlparse

from titan.core.models import Finding, Severity, AttackType

# Well-known benign origins that frequently load page scripts. Ad networks,
# tag managers and analytics are deliberately included: their scripts sit on
# MILLIONS of clean pages, so "external + unlisted-origin" alone must never
# flag them (the weather.co.ke FP: adsbygoogle scored 2 indicators on a page
# with zero card fields).
KNOWN_GOOD_ORIGINS = {
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "code.jquery.com",
    "ajax.googleapis.com", "ajax.aspnetcdn.com", "cdn.tailwindcss.com",
    "polyfill.io", "polyfill-fastly.io", "www.googletagmanager.com",
    "www.google-analytics.com", "analytics.google.com", "static.cloudflareinsights.com",
    "platform.twitter.com", "connect.facebook.net", "www.gstatic.com",
    "use.typekit.net", "kit.fontawesome.com", "cdn.shopify.com",
    # Google AdSense / ad stack — present on virtually every ad-supported site.
    "pagead2.googlesyndication.com", "googleads.g.doubleclick.net",
    "securepubads.g.doubleclick.net", "adservice.google.com",
    "static.doubleclick.net", "tpc.googlesyndication.com",
}

SCRIPT_ENUM_JS = """
() => {
  const scripts = [];
  for (const s of document.querySelectorAll('script[src]')) {
    let src = '';
    try { src = s.src || ''; } catch (e) {}
    scripts.push({ src: src });
  }
  const inputs = [];
  for (const i of document.querySelectorAll('input, textarea')) {
    const name = (i.name || i.id || '').toLowerCase();
    if (/card|ccnum|password|passwd|ssn|pan|expiry|cvv|cvc|billing|iban|routing|account\\s*number/.test(name)) {
      inputs.push(name);
    }
  }
  return { scripts: scripts, sensitive_inputs: inputs, origin: window.location.origin };
}
"""

# Heuristic thresholds — a script is flagged only with 2+ indicators.
MIN_SCORE = 2


class ThirdPartyDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, page, target: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            try:
                await page.wait_for_load_state("networkidle", timeout=2500)
            except Exception:
                pass

            state = await page.evaluate(SCRIPT_ENUM_JS)
            if not isinstance(state, dict):
                return findings

            scripts = state.get("scripts") or []
            sensitive_inputs = state.get("sensitive_inputs") or []
            page_origin = state.get("origin") or ""

            # Skimmer gate: a skimmer needs something to skim. A third-party
            # script on a page with ZERO sensitive fields (card/password/ssn)
            # is at most a tracker — never a skimmer finding. The external+
            # unlisted-origin pair alone scored adsbygoogle a MEDIUM on every
            # ad-supported page (weather.co.ke FP).
            if not sensitive_inputs:
                return findings

            for script in scripts:
                src = script.get("src") or ""
                if not src:
                    continue
                score, reasons = self._score_script(src, page_origin, sensitive_inputs)
                if score >= MIN_SCORE:
                    findings.append(self._finding(target, str(page.url or url), src, score, reasons, len(sensitive_inputs)))
        except Exception:
            return findings
        return findings

    @staticmethod
    def _score_script(src: str, page_origin: str, sensitive_inputs: List[str]) -> tuple:
        score = 0
        reasons = []
        try:
            script_origin = f"{urlparse(src).scheme}://{urlparse(src).netloc}"
            page_host = urlparse(page_origin or "").netloc
            script_host = urlparse(src).netloc

            if page_host and script_host and script_host != page_host:
                score += 1
                reasons.append(f"external:{script_host}")
            elif not page_host:
                score += 1
                reasons.append("external:no-page-origin")

            if script_host not in KNOWN_GOOD_ORIGINS:
                score += 1
                reasons.append(f"unlisted-origin:{script_host or 'unknown'}")

            if sensitive_inputs:
                score += 1
                reasons.append(f"sensitive-inputs:{len(sensitive_inputs)}")

            if script_origin and script_origin == page_origin:
                score -= 1
        except Exception:
            pass
        return score, reasons

    def _finding(self, target, url, src, score, reasons, sensitive_count) -> Finding:
        return Finding(
            target=target,
            url=url,
            method="GET",
            param="script[src]",
            location="client",
            payload=f"Risky third-party script ({score} indicators): {src[:120]}",
            attack_type=AttackType.SKIMMER,
            severity=Severity.MEDIUM,
            verified=False,
            confidence=min(0.85, 0.3 + score * 0.15),
            status=200,
            body=src[:2000],
            diffs=[f"skimmer:{r}" for r in reasons],
            metadata={"score": score, "reasons": reasons, "sensitive_inputs": sensitive_count},
        )
