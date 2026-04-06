#!/usr/bin/env python3
"""Verification script for CMDI payload library."""

from exploit.payload_library.cmdi import get_payloads

# Test Unix all payloads with blind=True (the critical requirement)
p = get_payloads('unix', 'all', blind=True, delay=5)
print(f'Unix all blind payloads: {len(p)}')
assert len(p) >= 50, f'Expected 50+, got {len(p)}'
print('✓ Unix blind payloads >= 50')

# Test Windows all payloads
pw = get_payloads('windows', 'all', delay=5)
print(f'Windows all payloads: {len(pw)}')
print('✓ Windows payloads generated')

# Test various configurations
sep = get_payloads('unix', 'separators')
print(f'Unix separators: {len(sep)}')

blind_time = get_payloads('unix', 'blind_time', delay=5)
print(f'Unix blind_time: {len(blind_time)}')

blind_dns = get_payloads('unix', 'blind_dns', callback='attacker.com')
print(f'Unix blind_dns: {len(blind_dns)}')

blind_file = get_payloads('unix', 'blind_file', canary='marker123')
print(f'Unix blind_file: {len(blind_file)}')

# Test placeholder replacement
p_with_params = get_payloads('unix', 'blind_time', delay=10)
assert '10' in p_with_params[0], 'Delay placeholder not replaced'
print('✓ Placeholder replacement works')

# Test deduplication
all_payloads = get_payloads('unix', 'all', blind=True, delay=5)
unique_payloads = set(all_payloads)
assert len(all_payloads) == len(unique_payloads), 'Deduplication failed'
print(f'✓ Deduplication verified: {len(all_payloads)} unique payloads')

print('\nAll verification tests passed!')
