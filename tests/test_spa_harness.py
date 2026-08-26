"""PUSH-TO-100 B1 — SPA/JS-rendered harness (pure helper logic).

The engine wraps these pure functions with Playwright orchestration (route
hydration + walk + capture); these tests pin the URL logic the harness relies
on: WebSocket -> http probe conversion, runtime API selection (dedupe, scope,
relative resolution), and route-table candidate extraction from the JSON-safe
blob the page ships back.
"""

from titan.core.spa import (
    route_table_candidates,
    select_runtime_apis,
    strip_fragment,
    ws_to_http,
)


# ---------------------------------------------------------------------------
# ws -> http
# ---------------------------------------------------------------------------

def test_ws_to_http():
    assert ws_to_http("ws://juice.local/rest/chat") == "http://juice.local/rest/chat"
    assert ws_to_http("wss://api.example.com/socket") == "https://api.example.com/socket"
    assert ws_to_http("https://x.example.com/api") == "https://x.example.com/api"
    assert ws_to_http("") == ""


# ---------------------------------------------------------------------------
# runtime API selection
# ---------------------------------------------------------------------------

def test_select_runtime_apis_dedupes_and_scopes():
    captured = [
        "http://juice.local/rest/products/search?q=x",
        "http://juice.local/rest/products/search?q=x",  # dup
        "http://evil.example.com/exfil",                 # out of scope
    ]
    ws = ["ws://juice.local/rest/chat", "wss://juice.local/socket"]
    out = select_runtime_apis(captured, ws_urls=ws, base_url="http://juice.local",
                              scope_host="juice.local")
    # ws converted to http (wss -> https); evil.example.com dropped; stable order
    assert out == [
        "http://juice.local/rest/chat",
        "http://juice.local/rest/products/search?q=x",
        "https://juice.local/socket",
    ]


def test_select_runtime_apis_resolves_relative_and_subdomains():
    out = select_runtime_apis(
        ["/rest/products"], base_url="http://juice.local", scope_host="juice.local"
    )
    assert out == ["http://juice.local/rest/products"]
    # a subdomain of the scope host is in scope
    out2 = select_runtime_apis(
        ["http://api.juice.local/v1/x"], scope_host="juice.local"
    )
    assert out2 == ["http://api.juice.local/v1/x"]


def test_select_runtime_apis_filters_non_http_and_empty():
    assert select_runtime_apis(["javascript:alert(1)", ""], scope_host="x") == []


# ---------------------------------------------------------------------------
# route-table candidates
# ---------------------------------------------------------------------------

def test_route_table_framework_globals_and_children():
    blob = {
        "routes": ["/login", "/register", {"path": "/admin", "children": [{"path": "/admin/users"}]}],
        "router": {"routes": [{"pathname": "/profile"}]},
        "hash_links": ["http://juice.local/#/cart"],
        "path_links": ["http://juice.local/about"],
        "data_routes": ["http://juice.local/#/settings"],
    }
    out = route_table_candidates(blob, base_url="http://juice.local")
    # relative routes are resolved to absolute against base_url
    assert "http://juice.local/login" in out
    assert "http://juice.local/register" in out
    assert "http://juice.local/admin" in out
    assert "http://juice.local/admin/users" in out
    assert "http://juice.local/profile" in out
    assert "http://juice.local/#/cart" in out
    assert "http://juice.local/about" in out
    assert "http://juice.local/#/settings" in out
    # sorted, deduped
    assert out == sorted(set(out))


def test_route_table_resolves_relative_and_dedupes():
    blob = {"routes": ["/a", "/a", {"path": "/b"}]}
    out = route_table_candidates(blob, base_url="http://juice.local")
    assert out == ["http://juice.local/a", "http://juice.local/b"]


def test_route_table_empty_blob_and_max_routes():
    assert route_table_candidates({}) == []
    blob = {"routes": [f"/r{i}" for i in range(100)]}
    out = route_table_candidates(blob, base_url="http://juice.local", max_routes=10)
    assert len(out) == 10


# ---------------------------------------------------------------------------
# fragment strip
# ---------------------------------------------------------------------------

def test_strip_fragment():
    assert strip_fragment("http://juice.local/#/cart") == "http://juice.local/"
    assert strip_fragment("http://juice.local/rest/x") == "http://juice.local/rest/x"
    assert strip_fragment("") == ""


# ---------------------------------------------------------------------------
# config wiring (engine reads crawl.spa)
# ---------------------------------------------------------------------------

def test_spa_config_defaults_in_engine():
    """The engine's SPA harness reads crawl.spa.* with sensible defaults; a
    config without the section must not break the engine construction."""
    from titan.core.engine import TitanEngine

    cfg = {
        "crawl": {"profile": "fast"},
        "modules": {},
        "ai": {},
        "stealth": {},
        "auth": {},
        "proxy": {},
        "exploit": {},
    }
    eng = TitanEngine(cfg)
    spa = eng.config.get("crawl", {}).get("spa", {})
    # harness enabled by default; budgets bounded
    assert spa.get("enabled", True) is True
    assert float(spa.get("hydrate_budget", 10)) > 0
    assert int(spa.get("max_routes", 6)) > 0
