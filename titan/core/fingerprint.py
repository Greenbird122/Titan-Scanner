"""Zero-footprint fingerprinting for target reconnaissance."""

from __future__ import annotations

import re
from typing import Any

from titan.core.fingerprint_signatures import (
    BASE_FINGERPRINT,
    BODY_SIGNATURES,
    COOKIE_SIGNATURES,
    HEADER_SIGNATURES,
    URL_SIGNATURES,
)


class TechFingerprinter:
    def __init__(self):
        self.fingerprint: dict[str, Any] = dict(BASE_FINGERPRINT)

    # PUSH-TO-100 B2 — strong, grounded markers checked BEFORE the generic
    # keyword table. These are real framework signatures (SPA manifests,
    # framework globals, distinctive attributes), not English words — so a
    # page can never inherit a framework from a substring coincidence.
    STRONG_BODY_MARKERS = [
        (r"ng-version=", "Angular"),              # Angular attribute
        (r"<app-root", "Angular"),                # Angular shell element
        (r"_nghost-", "Angular"),                 # Angular host binding
        (r"data-reactroot", "React"),             # React 16+ mount marker
        (r"_reactRootContainer", "React"),        # React 15 mount marker
        (r"__NEXT_DATA__", "Next.js"),            # Next.js data blob
        (r"/_next/static/", "Next.js"),           # Next.js asset path
        (r"__NUXT__", "Nuxt.js"),                 # Nuxt.js data blob
        (r"data-v-[0-9a-f]{6,}", "Vue"),          # Vue scoped-style attr
        (r"__VUE_DEVTOOLS_GLOBAL_HOOK__", "Vue"),
        (r"__SAPPER__", "Sapper"),
        (r"__sveltekit", "SvelteKit"),
        (r"__gatsby", "Gatsby"),
        (r"window\.__remixContext", "Remix"),
        (r"window\.__astro_", "Astro"),
        (r"svelte\.[a-z]+\.js", "Svelte"),
        (r"ember\.(min\.)?js", "Ember"),
        (r"backbone\.(min\.)?js", "Backbone"),
        (r"jquery[.-][0-9]+", "jQuery"),
        (r"wp-content/", "WordPress"),
        (r"drupalSettings", "Drupal"),
        (r"Joomla!", "Joomla"),
        (r"Django\s*[0-9.]*\s*\)?", "Django"),  # Django version banner
        (r"{{ csrf_token }}", "Django"),
        (r"__django__", "Django"),
        (r"laravel_session", "Laravel"),
        (r"csrfmiddlewaretoken", "Django"),
    ]

    # Words too generic to fingerprint anything from a body: they appear in
    # ordinary English prose and in every framework's docs/meta, so even a
    # WORD-BOUNDARY match is not evidence ("play" on a video site, "rest"
    # in "rest of the page", "spring" as a season, "express" as a courier,
    # "react" in marketing copy, "vue"/"slim"/"spark"/"unity" in product
    # names). The unlisted table words ARE allowed to match — word-boundary
    # matching already prevents the "display" -> "play" substring class, and
    # distinctive words ("django", "wordpress", "drupal", "php", "json")
    # are genuine signals when they stand alone. Only the STRONG markers may
    # claim the denied frameworks.
    GENERIC_BODY_WORDS = {
        "play", "rest", "express", "vue", "react", "spring", "slim",
        "spark", "unity", "foundation", "project", "workspace", "status",
    }

    async def analyze(self, response_headers: dict[str, str], body: str, url: str) -> dict[str, Any]:
        self.fingerprint["headers"] = {k.lower(): v for k, v in response_headers.items()}
        # B2 — reset accumulated lists so repeated analyze() calls can't grow
        # stale/duplicate entries (a fingerprinter instance is reused across
        # scans in the engine).
        for key in ("technologies", "frameworks", "languages", "servers",
                    "js_libraries", "api_types"):
            self.fingerprint[key] = []
        self._detect_headers()
        self._detect_cookies(response_headers)
        self._detect_body(body)
        self._detect_url(url)
        # B2 — dedupe while preserving order (headers + body + url can name the
        # same technology several times; the scorecard must read clean).
        for key in ("technologies", "frameworks", "languages", "servers",
                    "js_libraries", "api_types"):
            self.fingerprint[key] = list(dict.fromkeys(self.fingerprint[key]))
        return self.fingerprint

    def _detect_headers(self):
        headers = self.fingerprint["headers"]
        header_map = HEADER_SIGNATURES
        for header, key in header_map.items():
            if header in headers:
                self.fingerprint[key] = headers[header]
                self.fingerprint["technologies"].append(headers[header])

    def _detect_cookies(self, headers: dict[str, str]):
        cookie_header = headers.get("set-cookie", "")
        if not cookie_header:
            return
        cookies = [c.strip().split("=")[0] for c in cookie_header.split(";") if "=" in c]
        self.fingerprint["cookies"] = cookies
        cookie_indicators = COOKIE_SIGNATURES
        for cookie_name, tech in cookie_indicators.items():
            if any(cookie_name in c for c in cookies):
                self.fingerprint["technologies"].append(tech)
                self.fingerprint["frameworks"].append(tech)

    def _detect_body(self, body: str):
        body_lower = body.lower()

        # B2 — strong markers first: real framework signatures win even if a
        # generic word also appears (an Angular app that mentions "react" in
        # its copy must stay Angular, not flip to React). Patterns are matched
        # against the lowercased body, so they are lowercased too.
        for pattern, tech in self.STRONG_BODY_MARKERS:
            if re.search(pattern.lower(), body_lower):
                self.fingerprint["technologies"].append(tech)
                self.fingerprint["frameworks"].append(tech)

        tech_indicators = BODY_SIGNATURES
        for indicator, tech in tech_indicators.items():
            # B2 — generic English words can never claim a framework from a
            # substring ("display" must not yield "Play Framework"). Only the
            # strong markers above may name those technologies.
            if indicator in self.GENERIC_BODY_WORDS:
                continue
            # B2 — word-boundary matching: "play" only matches standalone
            # "play", never inside "display"/"player"/"deploy". Indicators
            # with a leading/trailing dot (e.g. ".htaccess") fall back to
            # substring containment (word boundaries don't apply to dots).
            if indicator[0].isalnum() and indicator[-1].isalnum():
                if re.search(rf"\b{re.escape(indicator)}\b", body_lower):
                    self.fingerprint["technologies"].append(tech)
                    self.fingerprint["frameworks"].append(tech)
            elif indicator in body_lower:
                self.fingerprint["technologies"].append(tech)
                self.fingerprint["frameworks"].append(tech)

    def _detect_url(self, url: str):
        url_lower = url.lower()
        # B2 — URLs carry the same substring trap as bodies ("rest" inside
        # "restaurant", "log" inside "blog", "test" inside "latest"). Match
        # on word boundaries and never let a generic word claim an API type.
        indicators = URL_SIGNATURES
        for indicator, tech in indicators.items():
            if indicator in self.GENERIC_BODY_WORDS:
                continue
            hit = False
            if indicator[0].isalnum() and indicator[-1].isalnum():
                hit = re.search(rf"\b{re.escape(indicator)}\b", url_lower) is not None
            else:
                hit = indicator in url_lower
            if hit:
                self.fingerprint["technologies"].append(tech)
                self.fingerprint["api_types"].append(tech)
