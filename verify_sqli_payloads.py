#!/usr/bin/env python3
"""
Verification script for SQL injection payload library.
This script demonstrates that the payload library is working correctly.
"""

import sys
from exploit.payload_library.sqli import (
    get_payloads,
    ERROR_BASED,
    BOOLEAN_BLIND,
    TIME_BASED,
    UNION_BASED,
    OOB,
    WAF_BYPASS,
)


def main():
    """Verify the SQL injection payload library."""
    print("="*70)
    print("SQL Injection Payload Library Verification")
    print("="*70)

    # Count payloads in each technique
    print("\n1. Payload Count by Technique:")
    print("-" * 70)

    error_count = (
        len(ERROR_BASED.get("generic", [])) +
        sum(len(ERROR_BASED.get(db, [])) for db in ["mysql", "postgresql", "mssql", "oracle", "sqlite"])
    )
    print(f"   Error-based: {error_count} payloads")

    boolean_count = (
        len(BOOLEAN_BLIND.get("true_conditions", [])) +
        len(BOOLEAN_BLIND.get("false_conditions", []))
    )
    print(f"   Boolean-blind: {boolean_count} payloads")

    time_count = sum(len(TIME_BASED.get(db, [])) for db in ["mysql", "postgresql", "mssql", "sqlite", "generic"])
    print(f"   Time-based: {time_count} payloads")

    union_count = (
        len(UNION_BASED.get("column_detection", [])) +
        sum(len(UNION_BASED.get("data_extraction", {}).get(db, [])) for db in ["mysql", "postgresql", "mssql"])
    )
    print(f"   UNION-based: {union_count} payloads")

    oob_count = sum(len(OOB.get(db, [])) for db in ["mysql", "mssql", "postgresql"])
    print(f"   Out-of-band: {oob_count} payloads")

    waf_count = len(WAF_BYPASS)
    print(f"   WAF bypass: {waf_count} payloads")

    total_raw = error_count + boolean_count + time_count + union_count + oob_count + waf_count
    print(f"   Total raw payloads: {total_raw}")

    # Test Case 1: All MySQL payloads with WAF bypass
    print("\n2. Test Case 1: get_payloads('all', 'mysql', waf_bypass=True, delay=5)")
    print("-" * 70)
    p_all = get_payloads("all", "mysql", waf_bypass=True, delay=5)
    print(f"   Result: {len(p_all)} unique payloads")
    print(f"   Requirement: 50+ payloads")
    print(f"   Status: {'PASS' if len(p_all) > 50 else 'FAIL'} ✓")

    # Test Case 2: Time-based generic with delay=3
    print("\n3. Test Case 2: get_payloads('time', 'generic', delay=3)")
    print("-" * 70)
    p_time = get_payloads("time", "generic", delay=3)
    print(f"   Result: {len(p_time)} payloads")
    has_sleep3 = any("SLEEP(3)" in p for p in p_time)
    print(f"   Contains SLEEP(3): {has_sleep3}")
    print(f"   Status: {'PASS' if has_sleep3 else 'FAIL'} ✓")

    # Test Case 3: Error-based MySQL
    print("\n4. Test Case 3: get_payloads('error', 'mysql')")
    print("-" * 70)
    p_error = get_payloads("error", "mysql")
    print(f"   Result: {len(p_error)} payloads")

    # Test Case 4: Boolean-based
    print("\n5. Test Case 4: get_payloads('boolean')")
    print("-" * 70)
    p_bool = get_payloads("boolean")
    print(f"   Result: {len(p_bool)} payloads")

    # Test Case 5: OOB with callback
    print("\n6. Test Case 5: get_payloads('oob', 'mssql', callback='attacker.com')")
    print("-" * 70)
    p_oob = get_payloads("oob", "mssql", callback="attacker.com")
    print(f"   Result: {len(p_oob)} payloads")
    has_callback = any("attacker.com" in p for p in p_oob)
    print(f"   Callback replaced: {has_callback}")
    print(f"   Status: {'PASS' if has_callback else 'FAIL'} ✓")

    # Sample payloads
    print("\n7. Sample Payloads (first 5 from MySQL all techniques):")
    print("-" * 70)
    for i, payload in enumerate(p_all[:5], 1):
        print(f"   {i}. {payload[:60]}{'...' if len(payload) > 60 else ''}")

    # Final verification
    print("\n" + "="*70)
    if len(p_all) > 50 and has_sleep3 and has_callback:
        print("VERIFICATION PASSED: Payload library working correctly")
        print("="*70)
        return 0
    else:
        print("VERIFICATION FAILED: Payload library has issues")
        print("="*70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
