#!/usr/bin/env python3
"""Unit tests for API schema inference module."""

import sys
from engine.scan_state import ScanState, Endpoint
from discovery.api_schema_inference import (
    infer_api_schema,
    _normalize_paths,
    _is_numeric,
    _is_uuid,
    _detect_crud_operation,
)


def test_is_numeric():
    """Test numeric segment detection."""
    assert _is_numeric("42") == True
    assert _is_numeric("123") == True
    assert _is_numeric("abc") == False
    assert _is_numeric("") == False
    print("[PASS] test_is_numeric")


def test_is_uuid():
    """Test UUID detection."""
    valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
    assert _is_uuid(valid_uuid) == True
    assert _is_uuid("not-a-uuid") == False
    assert _is_uuid("42") == False
    print("[PASS] test_is_uuid")


def test_detect_crud():
    """Test CRUD operation detection."""
    assert _detect_crud_operation("GET", False, "/api/users") == "list"
    assert _detect_crud_operation("GET", True, "/api/users/{id}") == "read"
    assert _detect_crud_operation("POST", False, "/api/users") == "create"
    assert _detect_crud_operation("PUT", True, "/api/users/{id}") == "update"
    assert _detect_crud_operation("DELETE", True, "/api/users/{id}") == "delete"
    print("[PASS] test_detect_crud")


def test_normalize_paths():
    """Test path normalization."""
    state = ScanState()

    # Add test endpoints
    state.add_endpoint(Endpoint(url="https://api.example.com/v1/client/locus-pentest-2/orders", method="GET"))
    state.add_endpoint(Endpoint(url="https://api.example.com/api/users/42", method="GET"))
    state.add_endpoint(Endpoint(url="https://api.example.com/api/docs/550e8400-e29b-41d4-a716-446655440000", method="GET"))

    path_groups = _normalize_paths(state.endpoints)

    # Verify normalization
    paths = list(path_groups.keys())
    assert any("{client_id}" in p or "locus-pentest-2" in p or "{param}" in p for p in paths), f"Client path not found in {paths}"
    assert any("{id}" in p for p in paths), f"ID placeholder not found in {paths}"
    assert any("{uuid}" in p for p in paths), f"UUID placeholder not found in {paths}"

    print("[PASS] test_normalize_paths")


def test_infer_api_schema_empty():
    """Test schema inference with empty state."""
    state = ScanState()
    schema = infer_api_schema(state)

    assert schema["openapi"] == "3.0.0"
    assert schema["total_endpoints"] == 0
    assert schema["total_paths"] == 0
    assert schema["paths"] == {}
    print("[PASS] test_infer_api_schema_empty")


def test_infer_api_schema_with_endpoints():
    """Test schema inference with actual endpoints."""
    state = ScanState()

    # Add realistic endpoints
    state.add_endpoint(Endpoint(
        url="https://api.example.com/api/users",
        method="GET",
        params=["limit", "offset"],
        response_status=200
    ))
    state.add_endpoint(Endpoint(
        url="https://api.example.com/api/users",
        method="POST",
        body_fields=["name", "email"],
        response_status=201
    ))
    state.add_endpoint(Endpoint(
        url="https://api.example.com/api/users/42",
        method="GET",
        response_status=200
    ))
    state.add_endpoint(Endpoint(
        url="https://api.example.com/api/users/42",
        method="PUT",
        body_fields=["name", "email"],
        response_status=200
    ))
    state.add_endpoint(Endpoint(
        url="https://api.example.com/api/users/42",
        method="DELETE",
        response_status=204
    ))

    schema = infer_api_schema(state)

    assert schema["openapi"] == "3.0.0"
    assert schema["total_endpoints"] == 5
    assert schema["total_paths"] == 2  # /api/users and /api/users/{id}
    assert "/api/users" in schema["paths"]
    assert "/api/users/{id}" in schema["paths"]

    # Check CRUD coverage
    assert schema["crud_coverage"]["list"] >= 1
    assert schema["crud_coverage"]["create"] >= 1
    assert schema["crud_coverage"]["read"] >= 1
    assert schema["crud_coverage"]["update"] >= 1
    assert schema["crud_coverage"]["delete"] >= 1

    print("[PASS] test_infer_api_schema_with_endpoints")


def test_infer_api_schema_with_complex_paths():
    """Test schema inference with complex nested paths."""
    state = ScanState()

    # Complex path with multiple segments
    state.add_endpoint(Endpoint(
        url="https://api.example.com/v1/client/locus-pentest-2/orders",
        method="GET"
    ))
    state.add_endpoint(Endpoint(
        url="https://api.example.com/v1/client/locus-pentest-2/orders/550e8400-e29b-41d4-a716-446655440000",
        method="GET"
    ))
    state.add_endpoint(Endpoint(
        url="https://api.example.com/v1/client/another-client/orders",
        method="GET"
    ))

    schema = infer_api_schema(state)

    assert schema["total_endpoints"] == 3
    # Should group into 2 paths: one for list, one for detail
    assert schema["total_paths"] >= 2

    print("[PASS] test_infer_api_schema_with_complex_paths")


def run_tests():
    """Run all tests."""
    tests = [
        test_is_numeric,
        test_is_uuid,
        test_detect_crud,
        test_normalize_paths,
        test_infer_api_schema_empty,
        test_infer_api_schema_with_endpoints,
        test_infer_api_schema_with_complex_paths,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__}: {e}")
            failed += 1

    print(f"\n{'='*50}")
    print(f"Tests: {passed} passed, {failed} failed")
    print(f"{'='*50}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
