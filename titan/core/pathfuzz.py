"""Response-driven path fuzzer for Titan Scanner.

Discovers deeper API endpoints by brute-forcing path segments OFF a seed
surface (the crawl's discovered APIs). The filter is **response-driven, not
list-driven**: for each seed a random-marker 404 *control* request teaches the
fuzzer what "not found" looks like for that exact path, and a candidate is kept
only when its (status, body-signature) response differs from the control — so
soft-404 HTML, framework catch-alls and WAF walls are filtered by the server's
own answer rather than a static blocklist.

Design goals (matching the engine's other discovery seams):
- **Bounded**: max_seeds, max_depth, max_words_per_seed, max_requests,
  concurrency, plus a wall-clock budget at the engine call site.
- **Non-destructive**: GET-only probes, no payloads, no state changes.
- **Degrades quietly**: any probe failure yields an empty result for that word;
  a wedged request never hangs the scan.
- **In-scope**: every hit is filtered through the engine's scope predicate.
"""

from __future__ import annotations

import asyncio
import random
import re
import string
from typing import Any, Callable, Dict, List, Optional

# Soft-404 copy: an HTML/JSON error body served with HTTP 200 for ANY unknown
# path. Mirrors the engine's SOFT_404_MARKERS so the fuzzer and the module
# matrix agree on what a dead route looks like.
SOFT_404_MARKERS = (
    "page not found",
    "was not found",
    "not found on this server",
    "requested url was not found",
    "couldn't find",
    "does not exist",
    "no longer exists",
    "no such file",
    "error 404",
)

# Challenge-wall fingerprints (same semantics as the engine's checkpoint
# detection): a fuzz hit behind a wall is a WAF artifact, not an endpoint.
CHECKPOINT_MARKERS = (
    "just a moment",
    "checking your browser",
    "ray id:",
    "cf-ray",
    "cf-mitigated",
    "access denied",
    "security check",
    "captcha",
    "vercel security checkpoint",
)

# Common deeper-path segments. The first ``max_words_per_seed`` are used per
# seed; users can extend via ``crawl.fuzz.wordlist``.
DEFAULT_WORDS = [
    # admin / debug / ops
    "admin", "administrator", "manager", "panel", "console", "dashboard",
    "debug", "dev", "test", "staging", "internal", "private", "hidden",
    "config", "configuration", "settings", "preferences", "profile",
    "status", "health", "healthz", "ready", "live", "metrics", "version",
    "info", "about", "usage", "stats", "statistics", "summary", "overview",
    # files / data
    "file", "files", "document", "documents", "download", "upload", "export",
    "import", "backup", "bak", "dump", "csv", "json", "xml", "pdf", "xlsx",
    "raw", "data", "metadata", "meta", "schema", "definitions", "assets",
    # identity / auth
    "users", "user", "me", "account", "accounts", "profile", "profiles",
    "login", "logout", "register", "signup", "signin", "auth", "session",
    "sessions", "token", "tokens", "refresh", "verify", "otp", "password",
    "reset", "forgot", "keys", "apikey", "api_key", "credentials",
    # resources
    "posts", "post", "comments", "comment", "messages", "message", "chat",
    "conversations", "conversation", "threads", "thread", "feed", "stories",
    "likes", "followers", "following", "friends", "groups", "teams", "team",
    "members", "memberships", "roles", "permissions", "invites", "invitations",
    # commerce
    "orders", "order", "carts", "cart", "checkout", "payments", "payment",
    "invoice", "invoices", "receipts", "transactions", "transaction",
    "balance", "wallet", "subscriptions", "subscribe", "plans", "billing",
    # notifications / webhooks
    "notifications", "notification", "webhooks", "webhook", "hooks", "hooks",
    "callback", "callbacks", "events", "event", "streams", "subscribe",
    # reports / analytics
    "reports", "report", "analytics", "statistics", "dashboard", "charts",
    "graphql", "graphiql", "swagger", "openapi", "api-docs", "docs",
    # generic crud
    "list", "all", "create", "new", "add", "edit", "update", "delete",
    "remove", "get", "find", "search", "query", "filter", "sort", "page",
    "count", "total", "active", "pending", "archived", "trash", "recycle",
]

STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".map", ".txt", ".html",
)


class _RequestCounter:
    """Global per-scan request budget shared across fuzz levels."""

    def __init__(self, limit: int):
        self.limit = limit
        self.count = 0

    def take(self) -> bool:
        if self.count >= self.limit:
            return False
        self.count += 1
        return True


class PathFuzzer:
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        in_scope: Optional[Callable[[str], bool]] = None,
        stealth: Any = None,
    ):
        cfg = config or {}
        self.enabled = cfg.get("enabled", True)
        self.words = list(DEFAULT_WORDS)
        for w in cfg.get("wordlist", []) or []:
            if w and w not in self.words:
                self.words.append(w)
        self.max_seeds = int(cfg.get("max_seeds", 5))
        self.max_depth = int(cfg.get("max_depth", 2))
        self.max_words_per_seed = int(cfg.get("max_words_per_seed", 60))
        self.max_requests = int(cfg.get("max_requests", 250))
        self.concurrency = int(cfg.get("concurrency", 8))
        self.timeout = int(cfg.get("timeout", 5000))
        self.delay_enabled = bool(cfg.get("delay", False))
        self.in_scope = in_scope or (lambda url: True)
        self.stealth = stealth
        self.soft_404 = SOFT_404_MARKERS
        self.checkpoints = CHECKPOINT_MARKERS

    # -- plumbing ---------------------------------------------------------

    async def _probe(self, context, url: str) -> tuple:
        """GET a URL; return (status, body, location). Never raises."""
        try:
            if self.delay_enabled and self.stealth is not None:
                await self.stealth.delay()
            resp = await context.request.get(url, timeout=self.timeout)
            body = await resp.text()
            return resp.status, body or "", (resp.headers or {}).get("location", "")
        except Exception:
            return None, "", ""

    @staticmethod
    def _sig(body: str) -> str:
        """Whitespace-normalised body signature (stable across formatting)."""
        return re.sub(r"\s+", " ", body or "").strip()[:2000]

    def _is_soft_404(self, body: str) -> bool:
        low = (body or "").lower()
        return any(m in low for m in self.soft_404)

    def _is_checkpoint(self, body: str) -> bool:
        low = (body or "").lower()[:4000]
        return any(m in low for m in self.checkpoints)

    @staticmethod
    def _is_static(seed: str) -> bool:
        seg = seed.rstrip("/").rsplit("/", 1)[-1].split("?")[0]
        return any(seg.endswith(ext) for ext in STATIC_EXTENSIONS)

    @staticmethod
    def _normalize_seed(seed: str) -> str:
        return seed.split("?")[0].split("#")[0].rstrip("/")

    # -- classifier -------------------------------------------------------

    def _is_hit(
        self,
        status,
        body: str,
        location: str,
        ctl_status,
        ctl_body: str,
        ctl_location: str,
    ) -> bool:
        if status is None or status in (404, 405, 501):
            return False
        if self._is_soft_404(body):
            return False
        if self._is_checkpoint(body):
            return False
        # Redirects first: a redirect to a DIFFERENT target than the control is
        # a hit (the dead-route signature is "redirects to the same place"); a
        # redirect to the same target is the dead-route behaviour.
        if status in (301, 302, 303, 307, 308):
            return bool(location) and location != ctl_location
        # Identical (status + body signature) to the 404 control == dead route.
        if status == ctl_status and self._sig(body) == self._sig(ctl_body):
            return False
        return True

    # -- main entry -------------------------------------------------------

    async def fuzz(self, context, seeds: List[str]) -> List[str]:
        """Return discovered deeper URLs (strings), ordered, deduped.

        ``seeds`` is the crawl's discovered API surface. Hits are returned
        verbatim so the engine can feed them into the module matrix.
        """
        if not self.enabled or not seeds:
            return []
        normalized = [self._normalize_seed(s) for s in seeds if s]
        normalized = [s for s in dict.fromkeys(normalized) if self.in_scope(s) and not self._is_static(s)]
        if not normalized:
            return []
        counter = _RequestCounter(self.max_requests)
        found: List[str] = []
        await self._fuzz_level(context, normalized[: self.max_seeds], 1, counter, found)
        seed_set = set(normalized)
        out: List[str] = []
        for u in found:
            if u not in seed_set and u not in out:
                out.append(u)
        return out

    async def _fuzz_level(
        self,
        context,
        level_seeds: List[str],
        depth: int,
        counter: _RequestCounter,
        found: List[str],
    ) -> None:
        if depth > self.max_depth or not level_seeds or counter.count >= counter.limit:
            return
        next_level: List[str] = []
        for seed in level_seeds[: self.max_seeds]:
            if counter.count >= counter.limit:
                break
            # 404 control for THIS seed: a random marker that cannot exist.
            marker = "__titan_404_" + "".join(
                random.choices(string.ascii_lowercase + string.digits, k=10)
            )
            if not counter.take():
                break
            ctl_status, ctl_body, ctl_location = await self._probe(context, seed + "/" + marker)

            words = self.words[: self.max_words_per_seed]
            sem = asyncio.Semaphore(self.concurrency)

            async def probe_one(word: str):
                async with sem:
                    if not counter.take():
                        return word, None, "", ""
                    return (word,) + await self._probe(context, seed.rstrip("/") + "/" + word)

            results = await asyncio.gather(*[probe_one(w) for w in words])
            for word, status, body, location in results:
                if status is None:
                    continue
                url = seed.rstrip("/") + "/" + word
                if not self.in_scope(url):
                    continue
                if self._is_hit(status, body, location, ctl_status, ctl_body, ctl_location):
                    if url not in found:
                        found.append(url)
                    next_level.append(url)
                    # A redirect to a different in-scope target is itself a
                    # discovery worth keeping.
                    if location and self.in_scope(location) and location not in found:
                        found.append(location.split("?")[0])

        await self._fuzz_level(context, next_level, depth + 1, counter, found)
