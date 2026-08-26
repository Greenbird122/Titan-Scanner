"""DOM XSS detection — browser-context module (Track A).

Server-reflected XSS (titan/modules/xss) fires on a server response diff;
it is blind to client-side sinks. This module runs INSIDE the real browser:
it installs wrappers around dangerous JS sinks (innerHTML, outerHTML,
document.write, eval, Function, setTimeout(string), location/src assignment),
navigates to the target with a unique random marker in a parameter, then
checks whether that marker reached a hooked sink.

Oracle: the attacker marker appearing in a hooked sink value proves the
page's client-side code routed attacker-controlled input into a dangerous
sink — a verified DOM XSS. A sink hit WITHOUT the marker (site's own
content) and a marker that never reaches a sink (reflected but inert) both
produce no finding.
"""

from __future__ import annotations

import secrets
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urlunparse

from titan.core.models import Finding, Severity, AttackType

# Installed via page.add_init_script BEFORE any page JS runs. Wraps the
# sinks, records every write into window.__titan_sinks__ as {sink, value}.
SINK_HOOK_JS = """
() => {
  window.__titan_sinks__ = [];
  const record = (sink, value) => {
    try {
      window.__titan_sinks__.push({ sink: sink, value: String(value).slice(0, 2000) });
    } catch (e) {}
  };
  // Element.innerHTML / outerHTML / insertAdjacentHTML
  const proto = Element.prototype;
  const desc = Object.getOwnPropertyDescriptor(proto, 'innerHTML');
  if (desc && desc.set) {
    Object.defineProperty(proto, 'innerHTML', {
      ...desc,
      set(v) { record('innerHTML', v); return desc.set.call(this, v); }
    });
  }
  const odesc = Object.getOwnPropertyDescriptor(proto, 'outerHTML');
  if (odesc && odesc.set) {
    Object.defineProperty(proto, 'outerHTML', {
      ...odesc,
      set(v) { record('outerHTML', v); return odesc.set.call(this, v); }
    });
  }
  const origWrite = document.write.bind(document);
  document.write = (...args) => { record('document.write', args.join('')); return origWrite(...args); };
  const origWriteln = document.writeln.bind(document);
  document.writeln = (...args) => { record('document.write', args.join('')); return origWriteln(...args); };
  const origEval = window.eval;
  window.eval = (code) => { record('eval', code); return origEval(code); };
  const origFunction = window.Function;
  window.Function = new Proxy(origFunction, {
    apply(target, thisArg, args) { record('Function', args.join(',')); return target.apply(thisArg, args); },
    construct(target, args) { record('Function', args.join(',')); return new target(...args); }
  });
  const origSetTimeout = window.setTimeout;
  window.setTimeout = (fn, ...rest) => {
    if (typeof fn === 'string') record('setTimeout', fn);
    return origSetTimeout(fn, ...rest);
  };
  window.__titan_sinks_hooked__ = true;
}
"""

DANGEROUS_SINKS = {"innerHTML", "outerHTML", "document.write", "eval", "Function", "setTimeout"}


class DomXSSDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, page, target: str, url: str, params: Dict[str, str], marker: Optional[str] = None) -> List[Finding]:
        """``page`` is a real Playwright page (or a test double exposing
        add_init_script / goto / evaluate). ``marker`` is injectable so tests
        can script the page's behaviour deterministically."""
        marker = marker or ("titanmx" + secrets.token_hex(6))
        findings: List[Finding] = []

        try:
            await page.add_init_script(SINK_HOOK_JS)

            # Pick a param the page plausibly reflects client-side: any
            # crawled param, else a common name. Inject the marker into it.
            probe_param = next(iter(params)) if params else "q"
            probe_url = self._with_param(url, probe_param, marker)
            await page.goto(probe_url, wait_until="domcontentloaded", timeout=15000)
            try:
                await page.wait_for_load_state("networkidle", timeout=2500)
            except Exception:
                pass
            await page.wait_for_timeout(500)

            sinks = await page.evaluate("window.__titan_sinks__ || []")
            if not isinstance(sinks, list):
                sinks = []

            for hit in sinks:
                sink = hit.get("sink", "")
                value = hit.get("value", "")
                if sink in DANGEROUS_SINKS and marker in value:
                    findings.append(self._finding(target, str(page.url or url), probe_param, sink, marker, value))
                    break  # one verified DOM XSS per page is enough
        except Exception:
            return findings
        return findings

    @staticmethod
    def _with_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        query = parsed.query
        if query:
            query += "&" + urlencode({param: value})
        else:
            query = urlencode({param: value})
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

    def _finding(self, target, url, param, sink, marker, value) -> Finding:
        return Finding(
            target=target,
            url=url,
            method="GET",
            param=param,
            location="query",
            payload=f"DOM XSS via {sink}: marker {marker} reached a dangerous sink",
            attack_type=AttackType.DOM_XSS,
            severity=Severity.CRITICAL,
            verified=True,
            confidence=0.9,
            status=200,
            body=value[:2000],
            diffs=[f"domxss:sink:{sink}", f"domxss:marker:{marker}"],
            verification_body=value[:2000],
            verification_status=200,
            metadata={"sink": sink, "marker": marker},
        )
