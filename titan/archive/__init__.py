"""S6 — site archiver: full mirror + endpoint map + explorer index.

Consent-gated read-only mirroring (any valid consent for the target — the same
stance as sqli-extraction / ssrf-pivot). Crawls the target within scope, saves
every HTML page and in-scope asset, records a complete endpoint map (every URL
with status + content-type — the "invisible" surface the browser never shows),
and renders a local explorer ``index.html`` so the operator can browse
everything the site exposes without touching the live target again.

    archive/
      pages/            mirrored HTML pages (clickable via the explorer)
      assets/           in-scope CSS/JS/images/fonts
      endpoints.json    the full endpoint map
      index.html        local explorer (self-contained, searchable)

Entry point: ``python titan_exploit_cli.py archive <target>``
"""

from .archiver import ArchiveError, SiteArchiver, archive_site

__all__ = ["ArchiveError", "SiteArchiver", "archive_site"]
