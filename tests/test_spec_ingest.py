"""Tests for titan.core.spec_ingest — API spec parsing and semantic payloads.

Covers OpenAPI 3.x / Swagger 2.0 / GraphQL SDL parsing, format detection
fallbacks, and semantic attack-payload generation. The network fetch path
(ingest) is exercised through the parse methods directly — no network.
"""

import json

import pytest

from titan.core.spec_ingest import (
    ApiEndpoint,
    AttackSurface,
    AuthType,
    SpecIngestor,
)

OPENAPI3 = {
    "openapi": "3.0.1",
    "info": {"title": "Payments API", "version": "2.1.0"},
    "servers": [{"url": "https://api.t.example/v2"}],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
        },
        "schemas": {
            "User": {
                "properties": {"id": {"type": "integer"}, "role": {"type": "string"}},
                "required": ["id"],
            },
        },
    },
    "paths": {
        "/users/{id}": {
            "get": {
                "summary": "Fetch user",
                "parameters": [
                    {"name": "id", "in": "path", "required": True},
                    {"name": "verbose", "in": "query"},
                ],
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "ok"}},
            },
            "delete": {"security": [{"bearerAuth": []}], "responses": {}},
        },
        "/users": {
            "post": {
                "summary": "Create user",
                "requestBody": {"content": {"application/json": {}}},
                "responses": {},
            },
        },
    },
}

SWAGGER2 = {
    "swagger": "2.0",
    "info": {"title": "Legacy API", "version": "1.0"},
    "host": "legacy.t.example",
    "basePath": "/api",
    "schemes": ["https"],
    "definitions": {
        "Order": {"properties": {"amount": {"type": "number"}}, "required": []},
    },
    "paths": {
        "/orders": {"get": {"summary": "List orders", "responses": {}}},
    },
}

GRAPHQL_SDL = """
type User {
  id: ID!
  role: String
}

type Query {
  user(id: ID!): User
  health: Boolean
}

type Mutation {
  updateUser(role: String): User
}
"""


@pytest.fixture()
def ingestor() -> SpecIngestor:
    return SpecIngestor()


class TestOpenApi3:
    def test_parses_meta_and_base_url(self, ingestor):
        s = ingestor._parse_openapi3(OPENAPI3, "src")
        assert s.title == "Payments API"
        assert s.version == "2.1.0"
        assert s.base_url == "https://api.t.example/v2"

    def test_parses_endpoints(self, ingestor):
        s = ingestor._parse_openapi3(OPENAPI3, "src")
        methods = {(e.method, e.path) for e in s.endpoints}
        assert ("GET", "/users/{id}") in methods
        assert ("DELETE", "/users/{id}") in methods
        assert ("POST", "/users") in methods

    def test_auth_scheme_detected(self, ingestor):
        s = ingestor._parse_openapi3(OPENAPI3, "src")
        assert s.auth_type == AuthType.BEARER
        assert s.auth_flows[0]["name"] == "bearerAuth"
        # operations declaring security are flagged auth_required
        get_ep = next(e for e in s.endpoints if e.method == "GET")
        assert get_ep.auth_required is True

    def test_schemas_and_params(self, ingestor):
        s = ingestor._parse_openapi3(OPENAPI3, "src")
        assert s.schemas[0].name == "User"
        assert s.schemas[0].required == ["id"]
        get_ep = next(e for e in s.endpoints if e.method == "GET")
        names = {p["name"] for p in get_ep.parameters}
        assert names == {"id", "verbose"}


class TestSwagger2:
    def test_base_url_composition(self, ingestor):
        s = ingestor._parse_openapi2(SWAGGER2, "src")
        assert s.base_url == "https://legacy.t.example/api"
        assert s.title == "Legacy API"

    def test_definitions_become_schemas(self, ingestor):
        s = ingestor._parse_openapi2(SWAGGER2, "src")
        assert s.schemas[0].name == "Order"
        assert "amount" in s.schemas[0].properties

    def test_endpoints_parsed(self, ingestor):
        s = ingestor._parse_openapi2(SWAGGER2, "src")
        assert any(e.method == "GET" and e.path == "/orders" for e in s.endpoints)


class TestGraphQl:
    def test_types_and_operations(self, ingestor):
        s = ingestor._parse_graphql(GRAPHQL_SDL, "src")
        type_names = {sc.name for sc in s.schemas}
        assert {"User", "Query", "Mutation"} <= type_names
        query_ops = [e for e in s.endpoints if e.method == "GET"]
        mutation_ops = [e for e in s.endpoints if e.method == "POST"]
        assert {e.path for e in query_ops} == {"/graphql#user", "/graphql#health"}
        assert {e.path for e in mutation_ops} == {"/graphql#updateUser"}

    def test_user_type_fields_parsed(self, ingestor):
        s = ingestor._parse_graphql(GRAPHQL_SDL, "src")
        user = next(sc for sc in s.schemas if sc.name == "User")
        assert set(user.properties) == {"id", "role"}
        assert user.properties["id"]["type"] == "ID!"


class TestSemanticPayloads:
    def test_mass_assignment_on_matching_schema(self, ingestor):
        surface = AttackSurface(
            base_url="https://api.t.example",
            schemas=[__import__(
                "titan.core.spec_ingest", fromlist=["ApiSchema"]
            ).ApiSchema(name="users", properties={"role": {}})],
            endpoints=[ApiEndpoint(method="POST", path="/users")],
        )
        payloads = ingestor.generate_semantic_payloads(surface)
        ma = [p for p in payloads if p.metadata["attack_type"] == "mass_assignment"]
        assert ma, "expected mass_assignment payload"
        body = json.loads(ma[0].body)
        assert body["role"] == "admin"  # semantic value from field name

    def test_idor_substitutes_path_ids(self, ingestor):
        surface = AttackSurface(
            base_url="https://api.t.example",
            endpoints=[ApiEndpoint(method="GET", path="/users/{id}")],
        )
        payloads = ingestor.generate_semantic_payloads(surface)
        idor = [p for p in payloads if p.metadata["attack_type"] == "idor"]
        urls = {p.url for p in idor}
        assert "https://api.t.example/users/1" in urls
        assert "https://api.t.example/users/999" in urls
        assert "https://api.t.example/users/admin" in urls

    def test_auth_bypass_on_secured_endpoint(self, ingestor):
        surface = AttackSurface(
            base_url="https://api.t.example",
            endpoints=[ApiEndpoint(method="GET", path="/admin", auth_required=True)],
        )
        payloads = ingestor.generate_semantic_payloads(surface)
        ab = [p for p in payloads if p.metadata["attack_type"] == "auth_bypass"]
        assert len(ab) == 1
        assert ab[0].url == "https://api.t.example/admin"

    def test_contract_violation_on_post(self, ingestor):
        surface = AttackSurface(
            base_url="https://api.t.example",
            endpoints=[ApiEndpoint(method="POST", path="/things")],
        )
        payloads = ingestor.generate_semantic_payloads(surface)
        cv = [p for p in payloads if p.metadata["attack_type"] == "contract_violation"]
        assert len(cv) == 1
        body = json.loads(cv[0].body)
        assert body["string_field"] == 999999  # wrong type on purpose

    def test_sqli_on_query_params(self, ingestor):
        surface = AttackSurface(
            base_url="https://api.t.example",
            endpoints=[ApiEndpoint(
                method="GET",
                path="/search",
                parameters=[{"name": "q", "in": "query"}],
            )],
        )
        payloads = ingestor.generate_semantic_payloads(surface)
        sqli = [p for p in payloads if p.metadata.get("attack_type") == "sqli"]
        assert len(sqli) == 3  # three canned SQLi probes per query param
        assert all(p.params["q"] for p in sqli)

    def test_value_generation_rules(self, ingestor):
        gen = ingestor._generate_value
        assert gen("role") == "admin"
        assert gen("is_admin") == "admin"
        assert gen("price") == -1
        assert gen("user_id") == 1
        assert gen("verified") is True
        assert gen("color") == "test_value"
