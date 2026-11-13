#!/usr/bin/env python3
"""Fail unless every generated arm has a distinct optimized, sancov-instrumented body."""
import re
import subprocess
import struct
import tempfile
from pathlib import Path
import sys
from generate_sparse_buckets import arms


def verify(binary):
    symbols = subprocess.check_output(['objdump', '-tC', str(binary)], text=True)
    assert 'antithesis_sparse_branch_shape' not in symbols, 'Removed encoder ABI retained'
    found = {}
    for line in symbols.splitlines():
        match = re.match(r'([0-9a-f]+)\s+\w+\s+F\s+(\S+)\s+([0-9a-f]+) .*::coverage_(\w+)(?:::h[0-9a-f]+)?$', line)
        if match:
            address, section, size, name = match.groups()
            # Legacy demanglers retain the Rust symbol hash as a suffix.
            name = re.sub(r'::h[0-9a-f]+$', '', name)
            assert name not in found, f'duplicate function {name}'
            found[name] = (int(address, 16), int(size, 16), section)
    # Reject any retained combined-bank body, even if it is no longer dispatched.
    assert all(name.startswith('local_') or name in ('proof_no_parent', 'invalid_proof')
               for name in found), f'Removed coverage family retained: {set(found) - {name for name, _ in arms()}}'
    expected = {name for name, _ in arms()}
    assert set(found) == expected, (expected - set(found), set(found) - expected)
    assert len({(address, section) for address, _, section in found.values()}) == len(expected), 'folded coverage functions'
    start = min(address for address, _, _ in found.values())
    end = max(address + size for address, size, _ in found.values())
    disassembly = subprocess.check_output(['objdump', '-drC', f'--start-address={start}', f'--stop-address={end}', str(binary)], text=True)
    blocks = re.split(r'\n(?=[0-9a-f]+ <)', disassembly)
    instrumented = set()
    entry_guards = set()
    linked = "REL (Relocatable file)" not in subprocess.check_output(["readelf", "-h", str(binary)], text=True)
    for block in blocks:
        header = block.splitlines()[0] if block else ''
        match = re.search(r'::coverage_(\w+?)(?:::h[0-9a-f]+)?>:', header)
        if not match or match[1] not in expected:
            continue
        name = match[1]
        assert '__sanitizer_cov_trace_pc_guard' in block, f'Uninstrumented arm: {name}'
        instrumented.add(name)
        if linked:
            entry = block.split('__sanitizer_cov_trace_pc_guard', 1)[0]
            guards = re.findall(r'lea\s+[^\n#]*,%rdi\s*#\s*([0-9a-f]+)', entry)
            assert guards, f'Missing entry guard address: {name}'
            guard = int(guards[-1], 16)
            assert guard not in entry_guards, f'Shared entry guard: {name}'
            entry_guards.add(guard)
    assert instrumented == expected, f'Missing disassembly: {expected - instrumented}'
    if linked:
        # Every function entry must also be present in the runtime PC table, with
        # the function-entry flag. This checks the linked artifact, not just IR.
        with tempfile.TemporaryDirectory() as temporary:
            table = Path(temporary) / 'pcs'
            subprocess.run(['objcopy', '--dump-section', f'__sancov_pcs={table}', str(binary)], check=True)
            data = table.read_bytes()
        assert len(data) % 16 == 0, 'Expected x86_64 PC/flags pairs'
        sections = subprocess.check_output(['objdump', '-h', str(binary)], text=True)
        section = re.search(r'\d+\s+__sancov_pcs\s+[0-9a-f]+\s+([0-9a-f]+)', sections)
        assert section, 'Missing PC table section'
        base = int(section[1], 16)
        # PIE stores the PCs as dynamic RELATIVE relocations rather than file bytes.
        relocations = subprocess.check_output(['readelf', '-rW', str(binary)], text=True)
        relative = {int(offset, 16): int(addend, 16) for offset, addend in re.findall(
            r'([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)', relocations)}
        entries = {relative.get(base + index * 16, pc)
                   for index, (pc, flags) in enumerate(struct.iter_unpack('<QQ', data)) if flags & 1}
        assert all(address in entries for address, _, _ in found.values()), 'Missing arm PC table entry'
        assert len(entry_guards) == len(expected)
        print(f'Verified {len(expected)} unique entry guards and function-entry PCs')
    print(f'Verified {len(expected)} distinct optimized coverage bodies, each with a sancov guard')


if __name__ == '__main__':
    verify(sys.argv[1])
