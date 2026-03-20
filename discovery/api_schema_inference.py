"""API schema inference — builds a synthetic OpenAPI spec from recorded traffic.

Analyzes discovered endpoints and constructs an OpenAPI 3.0.0 specification
by grouping endpoints by path patterns, detecting CRUD operations, and
inferring parameter schemas.
"""

import json
import os
import re
from collections import defaultdict
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from engine.scan_state import ScanState, Endpoint


def _normalize_path(path: str) -> str:
    """Extract path component from full URL."""
    parsed = urlparse(path)
    return parsed.path or "/"


def _is_numeric(segment: str) -> bool:
    """Check if a segment is purely numeric."""
    return bool(segment) and segment.isdigit()


def _is_uuid(segment: str) -> bool:
    """Check if a segment matches UUID v4 pattern."""
    uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    return bool(re.match(uuid_pattern, segment, re.IGNORECASE))


def _is_email(segment: str) -> bool:
    """Check if a segment looks like an email address."""
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(email_pattern, segment))


def _infer_param_name(segment: str, position: int) -> str:
    """Infer appropriate parameter name based on segment type and position."""
    if _is_uuid(segment):
        return "{uuid}"
    elif _is_numeric(segment):
        # Use 'id' for first numeric segment, or 'id' for consistency
        return "{id}"
    elif _is_email(segment):
        return "{email}"
    else:
        # Unknown segment type - treat as named parameter
        return "{param}"


def _normalize_paths(endpoints: List[Endpoint]) -> Dict[str, List[Endpoint]]:
    """
    Group endpoints by normalized path pattern.

    Replaces variable segments (IDs, UUIDs, etc.) with placeholders:
    - /api/users/42 → /api/users/{id}
    - /api/docs/550e8400-e29b-41d4-a716-446655440000 → /api/docs/{uuid}

    Returns dict: {normalized_path: [endpoints]}
    """
    path_groups: Dict[str, List[Endpoint]] = defaultdict(list)

    for endpoint in endpoints:
        base_path = _normalize_path(endpoint.url)

        # Split path into segments
        segments = [s for s in base_path.split("/") if s]

        # Normalize each segment
        normalized_segments = []
        for segment in segments:
            if _is_uuid(segment):
                normalized_segments.append("{uuid}")
            elif _is_numeric(segment):
                normalized_segments.append("{id}")
            elif _is_email(segment):
                normalized_segments.append("{email}")
            else:
                normalized_segments.append(segment)

        # Reconstruct normalized path
        normalized_path = "/" + "/".join(normalized_segments) if normalized_segments else "/"

        path_groups[normalized_path].append(endpoint)

    return path_groups


def _detect_crud_operation(method: str, has_id: bool, path: str) -> str:
    """
    Detect CRUD operation type based on HTTP method and URL pattern.

    Returns: "list", "read", "create", "update", "delete", or "other"
    """
    method_upper = method.upper()

    if method_upper == "GET":
        return "read" if has_id else "list"
    elif method_upper == "POST":
        return "create"
    elif method_upper in ("PUT", "PATCH"):
        return "update" if has_id else "other"
    elif method_upper == "DELETE":
        return "delete" if has_id else "other"
    else:
        return "other"


def _extract_query_params(endpoint: Endpoint) -> List[Dict]:
    """Extract query parameters from endpoint URL."""
    parsed = urlparse(endpoint.url)
    params = []

    if parsed.query:
        for key in parsed.query.split("&"):
            if "=" in key:
                param_name = key.split("=")[0]
            else:
                param_name = key

            params.append({
                "name": param_name,
                "in": "query",
                "required": False,
                "schema": {"type": "string"}
            })

    return params


def _extract_path_params(normalized_path: str) -> List[Dict]:
    """Extract path parameters from normalized path pattern."""
    params = []

    # Find all {param} placeholders
    param_pattern = r"\{([^}]+)\}"
    for match in re.finditer(param_pattern, normalized_path):
        param_name = match.group(1)
        params.append({
            "name": param_name,
            "in": "path",
            "required": True,
            "schema": {
                "type": "string" if param_name != "id" else "integer"
            }
        })

    return params


def _build_request_body_schema(endpoints: List[Endpoint], operation: str) -> Dict:
    """
    Build request body schema from endpoints with the given operation.

    Aggregates body_fields from all endpoints with matching operation.
    """
    properties = {}
    required = []

    # Collect body fields from all endpoints with this operation
    for endpoint in endpoints:
        if endpoint.body_fields:
            for field in endpoint.body_fields:
                if isinstance(field, str):
                    field_name = field
                    field_type = "string"
                elif isinstance(field, dict):
                    field_name = field.get("name", field)
                    field_type = field.get("type", "string")
                else:
                    continue

                if field_name not in properties:
                    properties[field_name] = {"type": field_type}
                    # Assume fields are required if they appear consistently
                    if field_name not in required:
                        required.append(field_name)

    if not properties:
        return {}

    return {
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": properties,
                    "required": required
                }
            }
        }
    }


def _build_response_schema(endpoints: List[Endpoint]) -> Dict:
    """Build response schema from endpoint response data."""
    # Extract common response structure from endpoints
    properties = {}

    for endpoint in endpoints:
        # Use response_headers as a simple proxy for response structure
        if endpoint.response_headers:
            if "content-type" in endpoint.response_headers:
                content_type = endpoint.response_headers.get("content-type", "")
                if "json" in content_type:
                    properties["data"] = {"type": "object"}
                    break

    if not properties:
        properties["data"] = {"type": "object"}

    return {
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": properties
                }
            }
        }
    }


def _build_operation_object(
    endpoints: List[Endpoint],
    normalized_path: str,
    method: str,
    operation_type: str
) -> Dict:
    """
    Build an OpenAPI operation object for a specific HTTP method.

    Combines parameters, request body, and response schema.
    """
    operation_obj = {
        "description": operation_type.capitalize(),
        "operationId": f"{operation_type}_{normalized_path.replace('/', '_')}",
    }

    # Collect parameters
    params = []
    params.extend(_extract_path_params(normalized_path))

    # Add query params from first endpoint as representative
    if endpoints:
        params.extend(_extract_query_params(endpoints[0]))

    if params:
        operation_obj["parameters"] = params

    # Add request body if applicable
    if method.upper() in ("POST", "PUT", "PATCH"):
        body = _build_request_body_schema(endpoints, operation_type)
        if body:
            operation_obj["requestBody"] = body

    # Add response
    operation_obj["responses"] = {
        "200": {
            "description": "Success",
            **_build_response_schema(endpoints)
        },
        "4XX": {
            "description": "Client error"
        },
        "5XX": {
            "description": "Server error"
        }
    }

    return operation_obj


def infer_api_schema(state: ScanState) -> dict:
    """
    Infer OpenAPI 3.0.0 schema from recorded traffic.

    Analyzes endpoints in ScanState:
    1. Groups by normalized path pattern (replacing IDs with {id}, UUIDs with {uuid})
    2. Detects CRUD operations (list, read, create, update, delete)
    3. Extracts parameters and request/response schemas
    4. Produces OpenAPI-compliant specification

    Args:
        state: ScanState with populated endpoints list

    Returns:
        dict: OpenAPI 3.0.0 specification with structure:
            {
                "openapi": "3.0.0",
                "info": {...},
                "paths": {...},
                "total_endpoints": N,
                "total_paths": N,
                "crud_coverage": {...}
            }
    """
    if not state.endpoints:
        return {
            "openapi": "3.0.0",
            "info": {
                "title": "Inferred API",
                "version": "1.0",
                "description": "No endpoints discovered"
            },
            "paths": {},
            "total_endpoints": 0,
            "total_paths": 0,
            "crud_coverage": {
                "list": 0,
                "read": 0,
                "create": 0,
                "update": 0,
                "delete": 0
            }
        }

    # Step 1: Normalize paths
    path_groups = _normalize_paths(state.endpoints)

    # Step 2 & 3: Build paths object and track CRUD coverage
    paths_obj: Dict[str, Dict] = {}
    crud_coverage = {
        "list": 0,
        "read": 0,
        "create": 0,
        "update": 0,
        "delete": 0
    }

    for normalized_path, endpoints_in_group in path_groups.items():
        path_obj: Dict[str, Dict] = {}

        # Group by method
        methods_in_path: Dict[str, List[Endpoint]] = defaultdict(list)
        for endpoint in endpoints_in_group:
            methods_in_path[endpoint.method.upper()].append(endpoint)

        # Check if path contains ID parameters
        has_id = "{id}" in normalized_path or "{uuid}" in normalized_path

        # Build operation objects for each method
        for method, method_endpoints in methods_in_path.items():
            operation_type = _detect_crud_operation(method, has_id, normalized_path)

            operation_obj = _build_operation_object(
                method_endpoints,
                normalized_path,
                method,
                operation_type
            )

            path_obj[method.lower()] = operation_obj

            # Track CRUD coverage
            if operation_type in crud_coverage:
                crud_coverage[operation_type] += 1

        paths_obj[normalized_path] = path_obj

    # Step 4: Build complete OpenAPI schema
    schema = {
        "openapi": "3.0.0",
        "info": {
            "title": "Inferred API",
            "version": "1.0",
            "description": "Automatically inferred from traffic analysis"
        },
        "paths": paths_obj,
        "total_endpoints": len(state.endpoints),
        "total_paths": len(path_groups),
        "crud_coverage": crud_coverage
    }

    return schema


def save_inferred_schema(schema: dict, output_dir: str = "reports") -> str:
    """
    Save inferred API schema to JSON file.

    Args:
        schema: OpenAPI schema dict
        output_dir: Directory to save schema to

    Returns:
        str: Path to saved file
    """
    os.makedirs(output_dir, exist_ok=True)

    output_path = os.path.join(output_dir, "inferred_api.json")

    with open(output_path, "w") as f:
        json.dump(schema, f, indent=2)

    return output_path
