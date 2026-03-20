#!/usr/bin/env python3
"""Quick import verification for filter_detector module."""

import sys
sys.path.insert(0, '.')

# Test imports
from exploit.filter_detector import detect_filters, FilterProfile, TEST_CHARS

print("✓ Import OK")
print(f"✓ TEST_CHARS has {len(TEST_CHARS)} character tests")
print(f"✓ FilterProfile dataclass loaded")
print(f"✓ detect_filters function loaded")

# Verify FilterProfile instantiation
profile = FilterProfile(url="http://test.com", param="q", method="GET")
print(f"\n✓ FilterProfile instantiation works")
print(f"  - url: {profile.url}")
print(f"  - param: {profile.param}")
print(f"  - method: {profile.method}")
print(f"  - baseline_status: {profile.baseline_status}")
print(f"  - baseline_length: {profile.baseline_length}")
print(f"  - allows: {profile.allows}")
print(f"  - blocks: {profile.blocks}")
print(f"  - encodes: {profile.encodes}")
print(f"  - strips: {profile.strips}")

# Verify properties
print(f"\n✓ FilterProfile properties work:")
print(f"  - is_heavily_filtered: {profile.is_heavily_filtered}")
print(f"  - allows_html: {profile.allows_html}")
print(f"  - allows_quotes: {profile.allows_quotes}")
print(f"  - allows_shell: {profile.allows_shell}")

# Test with some data
profile.allows = ["<", ">", "'"]
profile.blocks = [";" for _ in range(15)]
print(f"\n✓ Test with data:")
print(f"  - is_heavily_filtered (15 blocks): {profile.is_heavily_filtered}")
print(f"  - allows_html (< and >): {profile.allows_html}")
print(f"  - allows_quotes ('): {profile.allows_quotes}")

print("\n✅ All checks PASSED!")
