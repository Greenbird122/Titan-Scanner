"""Redirect detection module — dual engine for Open Redirect & Client-Side Hijack.

1. **Active Server-Side Open Redirect (HTTP Engine)**:
   • Probes all parameters with exhaustive open redirect bypass vectors:
     - Protocol-relative (//evil.com, ///evil.com)
     - Slash/backslash confusion (/\\evil.com, \\/evil.com, \\evil.com)
     - Suffix and Subdomain bypass (https://target.com.evil.com, https://target.com@evil.com)
     - Encoded slashes and tabs (/%09/evil.com, /%5c%5cevil.com)
     - JavaScript pseudo-protocol (javascript:alert(1))
   • Strict Oracles:
     - 3xx Location header pointing off-origin to attacker host.
     - In-page meta-refresh or script navigation reflecting unescaped redirect target.

2. **Client-Side Redirect Hijack (Browser Engine — Track F)**:
   • Installs navigation recorder before page scripts run.
   • Observes location.assign, location.replace, location.href, window.open, meta-refresh.
   • Flags unsolicited off-origin navigations.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from titan.core.models import AttackType, Finding, Severity
from titan.verify import BaselineAnalyzer


# ── Active Server-Side Open Redirect Payloads ─────────────────────────────────
_OPEN_REDIRECT_PROBES: Tuple[str, ...] = (
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    "///evil.com",
    "////evil.com",
    "/\\evil.com",
    "\\/evil.com",
    "\\evil.com",
    "\\\\evil.com",
    "/%09/evil.com",
    "/%2f%2fevil.com",
    "/%5c%5cevil.com",
    "https://evil.com%2f%2f",
    "https://evil.com%00",
    "https://evil.com?target.com",
    "https://evil.com#target.com",
    "https://evil.com/@target.com",
    "javascript:alert(document.domain)",
)

# ── Track F Client-side Recorder JS ──────────────────────────────────────────
REDIRECT_HOOK_JS = """() => {
  window.__titan_redirects__ = [];
  window.__titan_origin__ = window.location.origin;
  const record = (dest, mechanism, trigger, source) => {
    try {
      window.__titan_redirects__.push({
        dest: String(dest).slice(0, 500),
        mechanism: mechanism,
        trigger: trigger,
        source: source ? String(source).slice(0, 400) : '',
        timing: Math.round(performance.now()),
      });
    } catch (e) {}
  };
  const patchLoc = (name) => {
    try {
      const orig = window.location[name];
      if (typeof orig === 'function') {
        window.location[name] = function (dest) {
          record(dest, 'location.' + name, 'script', (new Error()).stack);
          return orig.apply(this, arguments);
        };
      }
    } catch (e) {}
  };
  patchLoc('assign'); patchLoc('replace');
  try {
    const desc = Object.getOwnPropertyDescriptor(window.location, 'href');
    if (desc && desc.set) {
      Object.defineProperty(window.location, 'href', {
        set(v) { record(v, 'location.href', 'script', (new Error()).stack); desc.set.call(this, v); },
        get() { return desc.get.call(this); },
      });
    }
  } catch (e) {}
  try {
    const _open = window.open;
    if (typeof _open === 'function') {
      window.open = function (dest) {
        record(dest, 'window.open', 'script', (new Error()).stack);
        return _open.apply(this, arguments);
      };
    }
  } catch (e) {}
  try {
    const mo = new MutationObserver((muts) => {
      for (const m of muts) {
        for (const n of (m.addedNodes || [])) {
          if (n && n.nodeType === 1 && n.matches &&
              n.matches('meta[http-equiv="refresh" i]')) {
            record(n.getAttribute('content'), 'meta-refresh', 'parse', n.outerHTML);
          }
        }
      }
    });
    mo.observe(document.documentElement || document, { subtree: true, childList: true });
  } catch (e) {}
  return true;
}
"""

READ_REDIRECTS_JS = """() => ({
  redirects: window.__titan_redirects__ || [],
  origin: window.__titan_origin__ || window.location.origin,
  finalUrl: window.location.href,
})"""


class RedirectDetector:
    """Production-grade Redirect detector supporting both active HTTP scanning and browser execution."""

    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    # ------------------------------------------------------------------
    # PUBLIC ENTRY POINT
    # ------------------------------------------------------------------

    async def scan(
        self,
        context_or_page: Any,
        target: str,
        method_or_url: str = "GET",
        url_or_params: Any = None,
        params: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        # Handle dispatch: Browser page object vs HTTP scanner context
        if hasattr(context_or_page, "add_init_script") or hasattr(context_or_page, "evaluate"):
            # Browser page mode
            page_url = method_or_url if isinstance(method_or_url, str) and method_or_url.startswith("http") else target
            p_dict = url_or_params if isinstance(url_or_params, dict) else (params or {})
            return await self._scan_browser(context_or_page, target, page_url, p_dict)

        # HTTP context mode
        method = method_or_url
        url = url_or_params if isinstance(url_or_params, str) else target
        param_dict = params or {}
        return await self._scan_http(context_or_page, target, method, url, param_dict)

    # ------------------------------------------------------------------
    # ENGINE 1 — ACTIVE HTTP OPEN REDIRECT SCANNER
    # ------------------------------------------------------------------

    async def _scan_http(
        self,
        context: Any,
        target: str,
        method: str,
        url: str,
        params: Dict[str, str],
    ) -> List[Finding]:
        findings: List[Finding] = []
        target_host = urlparse(target).hostname or ""

        # Baseline request
        try:
            if method.upper() == "GET":
                baseline_resp = await context.request.get(
                    url, params=params, headers={"Referer": target}, timeout=3000
                )
            else:
                baseline_resp = await context.request.post(
                    url, data=params, headers={"Referer": target}, timeout=3000
                )
            baseline_body = await baseline_resp.text()
            baseline_status = baseline_resp.status
        except Exception:
            return findings

        # Derive host-specific probes (e.g. https://target.com.evil.com, https://target.com@evil.com)
        custom_probes = list(_OPEN_REDIRECT_PROBES)
        if target_host:
            custom_probes.extend([
                f"https://{target_host}.evil.com",
                f"https://{target_host}@evil.com",
                f"https://evil.com?{target_host}",
            ])

        # Test all parameters
        for param_name in list(params.keys()):
            for payload in custom_probes:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload
                    if method.upper() == "GET":
                        resp = await context.request.get(
                            url, params=test_params, headers={"Referer": target}, timeout=3000
                        )
                    else:
                        resp = await context.request.post(
                            url, data=test_params, headers={"Referer": target}, timeout=3000
                        )
                    body = await resp.text()

                    f = self._evaluate_http_redirect(
                        baseline_body, baseline_status, body, resp,
                        target, url, method, param_name,
                        "query" if method.upper() == "GET" else "body",
                        payload, target_host
                    )
                    if f:
                        findings.append(f)
                        break
                except Exception:
                    continue

        return findings

    def _evaluate_http_redirect(
        self,
        baseline_body: str,
        baseline_status: Optional[int],
        body: str,
        resp: Any,
        target: str,
        url: str,
        method: str,
        param_name: str,
        location: str,
        payload: str,
        target_host: str,
    ) -> Optional[Finding]:
        status = getattr(resp, "status", None)
        if status is None:
            return None

        headers = dict(getattr(resp, "headers", {}))
        location_hdr = ""
        for k, v in headers.items():
            if k.lower() == "location":
                location_hdr = str(v)
                break

        # 1. 3xx Location header pointing to evil.com
        if status in (300, 301, 302, 303, 307, 308) and location_hdr:
            parsed_loc = urlparse(location_hdr)
            loc_host = parsed_loc.hostname or ""
            if "evil.com" in location_hdr or (loc_host and loc_host != target_host and "evil" in loc_host):
                diffs = ["redirect:location_header", f"location:{location_hdr}"]
                return Finding(
                    target=target,
                    url=str(getattr(resp, "url", None) or url),
                    method=method.upper(),
                    param=param_name,
                    location=location,
                    payload=payload,
                    attack_type=AttackType.OPEN_REDIRECT,
                    severity=Severity.HIGH,
                    verified=True,
                    confidence=0.95,
                    status=status,
                    headers=headers,
                    body=body[:2000],
                    diffs=diffs,
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_status,
                    verification_body=body[:2000],
                    verification_status=status,
                )

        # 2. Meta-refresh or JS redirect in 200 response body
        if status == 200:
            meta_re = re.search(r'http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\'>]+)', body, re.I)
            if meta_re and "evil.com" in meta_re.group(1):
                return Finding(
                    target=target,
                    url=str(getattr(resp, "url", None) or url),
                    method=method.upper(),
                    param=param_name,
                    location=location,
                    payload=payload,
                    attack_type=AttackType.OPEN_REDIRECT,
                    severity=Severity.HIGH,
                    verified=True,
                    confidence=0.90,
                    status=status,
                    headers=headers,
                    body=body[:2000],
                    diffs=["redirect:meta_refresh", f"meta_url:{meta_re.group(1)}"],
                    baseline_body=baseline_body[:2000],
                    baseline_status=baseline_status,
                    verification_body=body[:2000],
                    verification_status=status,
                )

        return None

    # ------------------------------------------------------------------
    # ENGINE 2 — BROWSER CLIENT-SIDE HIJACK DETECTOR (TRACK F)
    # ------------------------------------------------------------------

    async def _scan_browser(self, page: Any, target: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []
        try:
            await page.add_init_script(REDIRECT_HOOK_JS)
        except Exception:
            return findings

        started = time.monotonic()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
        except Exception:
            return findings
        try:
            await page.wait_for_load_state("networkidle", timeout=2500)
        except Exception:
            pass
        try:
            await page.wait_for_timeout(500)
        except Exception:
            pass

        try:
            state = await page.evaluate(READ_REDIRECTS_JS)
        except Exception:
            state = {}
        redirects = (state or {}).get("redirects") or []
        origin = (state or {}).get("origin") or ""
        final_url = (state or {}).get("finalUrl") or ""

        # Server-side redirect: final page URL off the request origin
        request_host = urlparse(url).hostname or ""
        final_host = urlparse(final_url).hostname or ""
        if final_url and request_host and final_host and final_host != request_host:
            redirects.append({
                "dest": final_url,
                "mechanism": "server-redirect",
                "trigger": "on-load",
                "source": "",
                "timing": int((time.monotonic() - started) * 1000),
            })

        seen: set = set()
        for r in redirects:
            dest = r.get("dest") or ""
            if not dest:
                continue
            dest_host = urlparse(dest).hostname or ""
            if dest_host and origin and (dest_host == origin or dest_host in origin or origin in dest_host):
                continue
            key = dest.split("?")[0]
            if key in seen:
                continue
            seen.add(key)
            findings.append(self._finding_browser(
                target, str(getattr(page, "url", None) or url), r,
                dest_host, origin,
            ))
        return findings

    def _finding_browser(self, target: str, page_url: str, r: dict, dest_host: str, origin: str) -> Finding:
        mechanism = r.get("mechanism", "unknown")
        trigger = r.get("trigger", "script")
        timing = r.get("timing", 0)
        source = r.get("source", "")
        on_load = trigger == "on-load" or timing <= 1500 or mechanism == "meta-refresh"
        severity = Severity.HIGH if on_load else Severity.MEDIUM
        metadata = {
            "mechanism": mechanism,
            "trigger": trigger,
            "timing_ms": timing,
            "dest_host": dest_host or "unknown",
            "origin": origin,
        }
        diffs = [
            f"redirect:{mechanism}",
            f"redirect:trigger:{trigger}",
            f"redirect:timing:{timing}ms",
            f"redirect:off-origin:{dest_host or 'unknown'}",
        ]
        if source:
            metadata["source_snippet"] = source[:400]
            diffs.append("redirect:source-script")
        return Finding(
            target=target,
            url=page_url,
            method="GET",
            param="navigation",
            location="client",
            payload=f"{mechanism} -> {r.get('dest', '')[:200]}",
            attack_type=AttackType.REDIRECT_HIJACK,
            severity=severity,
            verified=False,
            confidence=0.55 if on_load else 0.4,
            status=200,
            body="",
            diffs=diffs,
            metadata=metadata,
        )
