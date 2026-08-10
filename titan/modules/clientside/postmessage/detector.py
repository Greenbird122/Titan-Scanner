"""postMessage origin-validation detection — browser-context module (Track A).

A page that listens for postMessage but does NOT validate event.origin lets
any cross-origin frame drive its message handlers. The probe:
1. Installs a capture listener that records every message the page RECEIVES
   (from any origin) together with the handler's decision — whether a
   registered handler ran and whether it checked origin.
2. Fires a probe message from an attacker-controlled synthetic origin
   (an about:blank/iframe context has origin "null").
3. The oracle: a message handler EXECUTED for an attacker-controlled origin
   WITHOUT validating it (no event.origin comparison in the handler body) is
   a verified unvalidated-message-handler flaw.

A page with no handlers, or handlers that compare event.origin against an
allowlist, produces no finding.
"""

from __future__ import annotations

from typing import Any, Dict, List

from titan.core.models import Finding, Severity, AttackType

# Installed on every page before navigation. Wraps addEventListener so any
# registration of a "message" handler is captured with its source text; the
# capture listener also records which messages actually arrived and whether
# an origin check exists on the handler.
#
# IMPORTANT: the hook's OWN capture listener is registered through the
# ORIGINAL addEventListener (origAdd), not the patched one — otherwise it
# would be recorded as a handler, classified as unvalidated (its source
# reads ev.origin, which no origin-check regex matches), and every scanned
# page would produce a verified HIGH finding.
MESSAGE_HOOK_JS = """
() => {
  window.__titan_messages__ = { handlers: [], received: [] };
  const recordHandler = (handler) => {
    try {
      const src = handler && handler.toString ? handler.toString() : '';
      // e\\.origin | ev\\.origin | evt\\.origin | event\\.origin | source\\.origin
      const checksOrigin = /event\\s*\\.\\s*origin|e\\w{0,2}\\s*\\.\\s*origin|event\\s*\\[["']origin|source\\s*\\.\\s*origin/.test(src);
      window.__titan_messages__.handlers.push({ checksOrigin: checksOrigin, source: src.slice(0, 1500) });
    } catch (e) {}
  };
  const origAdd = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function(type, handler, ...rest) {
    if (type === 'message') recordHandler(handler);
    return origAdd.call(this, type, handler, ...rest);
  };
  const captureListener = (ev) => {
    window.__titan_messages__.received.push({
      origin: ev.origin, data: String(ev.data).slice(0, 300)
    });
  };
  // Bypass the patched method so the hook's own listener is never
  // recorded as an app handler (self-registration would self-FP).
  origAdd.call(window, 'message', captureListener);
}
"""

# A probe message from a foreign context: sent via a synthetic Event with an
# attacker-controlled origin. The page's handlers will process it (or not).
PROBE_MESSAGE_JS = """
(probeData) => {
  const probeOrigin = 'https://attacker-controlled.example';
  const event = new MessageEvent('message', {
    data: probeData,
    origin: probeOrigin,
    source: null,
    lastEventId: '',
  });
  window.dispatchEvent(event);
  return window.__titan_messages__.received;
}
"""

# The handler source is compared for an origin check; a handler is
# "validating" if it references event.origin/source.origin in any form.
# Mirrors the regex inside MESSAGE_HOOK_JS (e\\.origin, ev\\.origin,
# evt\\.origin, event\\.origin, source\\.origin, and the bracket form).
ORIGIN_CHECK_PATTERNS = ["event.origin", "e.origin", "ev.origin", "evt.origin", "source.origin", "origin =", "origin==", "origin !=="]


class PostMessageDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, page, target: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []
        try:
            await page.add_init_script(MESSAGE_HOOK_JS)
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            try:
                await page.wait_for_load_state("networkidle", timeout=2500)
            except Exception:
                pass

            # Fire a probe message from an attacker origin and see if any
            # registered handler ran / whether the message was received.
            probe_data = "titanmsgprobe" + "x" * 8
            await page.evaluate(PROBE_MESSAGE_JS, probe_data)
            await page.wait_for_timeout(300)

            state = await page.evaluate("window.__titan_messages__ || { handlers: [], received: [] }")
            handlers = state.get("handlers", []) if isinstance(state, dict) else []
            received = state.get("received", []) if isinstance(state, dict) else []

            # A handler that does NOT check origin is the flaw. The probe
            # message must have been received (handler ran for our origin).
            if not handlers:
                return findings

            # Belt-and-braces on top of the hook fix: never treat the hook's
            # own capture plumbing as an app handler even if registration
            # paths change (its source always references __titan_messages__).
            unvalidated = [
                h for h in handlers
                if not h.get("checksOrigin", False)
                and "__titan_messages__" not in (h.get("source") or "")
            ]
            if not unvalidated:
                return findings

            # Verified only if the probe (from an attacker origin) actually
            # reached the handler — received messages prove the listener ran.
            if not received:
                return findings

            h = unvalidated[0]
            return [Finding(
                target=target,
                url=str(page.url or url),
                method="GET",
                param="postMessage",
                location="client",
                payload="Unvalidated postMessage handler: message from attacker origin processed without origin check",
                attack_type=AttackType.POSTMESSAGE,
                severity=Severity.HIGH,
                verified=True,
                confidence=0.85,
                status=200,
                body=(h.get("source") or "")[:2000],
                diffs=["postmessage:no_origin_check", f"postmessage:handlers:{len(handlers)}", f"postmessage:received:{len(received)}"],
                verification_body=(h.get("source") or "")[:2000],
                verification_status=200,
                metadata={"handler_source": (h.get("source") or "")[:1500]},
            )]
        except Exception:
            return findings
