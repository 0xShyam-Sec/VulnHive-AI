#!/usr/bin/env python3
"""Test context analyzer implementation."""

import sys
sys.path.insert(0, '/Users/shyamk/Documents/pentest-agent')

from exploit.context_analyzer import analyze_reflection, CONTEXTS

# Test 1: Check contexts defined
print(f'{len(CONTEXTS)} context types defined')
for name, desc in sorted(CONTEXTS.items()):
    print(f"  - {name}: {desc}")

# Test 2: Test reflection on httpbin
print("\nTesting reflection analysis on httpbin.org...")
result = analyze_reflection('https://httpbin.org/get', 'test', 'GET')
print(f'Reflected: {result.reflected}')
print(f'Contexts found: {result.contexts}')
print(f'Response status: {result.response_status}')
print(f'Response length: {result.response_length}')
print(f'Canary: {result.canary}')
print(f'Positions found: {len(result.raw_positions)}')

print("\nContext analyzer OK")
