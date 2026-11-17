#!/usr/bin/env python3
"""Check SDK completion and bounded first-hit evidence from an immutable workload."""
import json
import re
import sys
from generate_sparse_buckets import arms, families, triples

TRIPLE_RANK = {triple: rank for rank, triple in enumerate(triples())}
LOCAL_START = 544
SANDWICH_START = LOCAL_START + 28672
NO_PARENT = SANDWICH_START + 15680


def expected_ids(depth, root, state, revealed, leaf):
    assert 0 <= depth < 64 and root == (depth == 0), 'invalid branch path/root'
    assert all(0 <= m <= 65535 for m in (state, revealed, leaf)), 'invalid mask width'
    assert revealed & ~state == 0 and leaf & ~revealed == 0, 'invalid runtime mask subsets'
    masks = [state, revealed, leaf, state & ~revealed, revealed & ~leaf]
    counts = [next(i for i, maximum in enumerate((0, 1, 4, 8, 16)) if m.bit_count() <= maximum) for m in masks]
    shapes = []
    for mask in masks:
        positions = [i for i in range(16) if mask & (1 << i)]
        shapes.append(0 if not positions else 4 if len(positions) == 16 else 1 if len(positions) == 1
                      else 2 if positions[-1] - positions[0] + 1 == len(positions) else 3)
    depth = next(i for i, maximum in enumerate((0, 1, 4, 8, 16, 32, 63)) if depth <= maximum)
    values = {'depth': depth, 'root': int(root)}
    values.update({f'counts[{i}]': value for i, value in enumerate(counts)})
    values.update({f'shapes[{i}]': value for i, value in enumerate(shapes)})
    result = set()
    offset = 0
    for _, expressions, keys in families():
        key = tuple(values[e] for e in expressions)
        result.add(offset + keys.index(key))
        offset += len(keys)
    return result


def expected_proof_ids(depth, parent, target, state, revealed, leaf):
    if not parent:
        assert (depth, target, state, revealed, leaf) == (0, 0, 0, 0, 0), 'invalid parentless target'
        return {NO_PARENT}
    assert 0 <= target < 16, 'invalid target nibble'
    expected_ids(depth, depth == 0, state, revealed, leaf)
    assert state & (1 << target) and not revealed & (1 << target), 'target must be blinded'
    depth = next(i for i, maximum in enumerate((0, 1, 4, 8, 16, 32, 63)) if depth <= maximum)
    pattern = 0
    for slot, position in enumerate((target - 2, target - 1, target + 1, target + 2)):
        kind = 0
        if 0 <= position < 16 and state & (1 << position):
            kind = 1 if not revealed & (1 << position) else 3 if leaf & (1 << position) else 2
        pattern += kind * 4 ** slot
    result = {LOCAL_START + (depth * 16 + target) * 256 + pattern}
    for j in range(16):
        for k in range(16):
            if revealed & (1 << j) and state & ~revealed & (1 << k) and (target, j, k) in TRIPLE_RANK:
                result.add(SANDWICH_START + (depth * 1120 + TRIPLE_RANK[target, j, k]) * 2 + bool(leaf & (1 << j)))
    return result


def validate(events, diagnostics):
    setup = completed = False
    for line in events:
        event = json.loads(line)
        setup |= event.get('antithesis_setup', {}).get('status') == 'complete'
        assertion = event.get('antithesis_assert', {})
        if assertion.get('hit'):
            assert not (assertion.get('display_type') == 'Unreachable' or
                        (assertion.get('assert_type') == 'reachability' and assertion.get('must_hit') is False)), assertion
            if assertion.get('assert_type') == 'always':
                assert assertion['condition'], assertion
            if assertion.get('message') == 'Trie workload completes a round':
                completed |= assertion.get('condition', False)
        assert event.get('antithesis_guidance', {}).get('message') != 'Sparse trie branch shape', 'JSON guidance must not be emitted'
    seen = set()
    observations = []
    pattern = re.compile(r'sparse_bucket_v1 id=(\d+) depth=(\d+) root=([01]) state=(\d+) revealed=(\d+) leaf=(\d+)')
    for line in diagnostics:
        if 'sparse_proof_bucket_v1' in line:
            match = re.fullmatch(r'sparse_proof_bucket_v1 id=(\d+) depth=(\d+) target=(\d+) parent=([01]) state=(\d+) revealed=(\d+) leaf=(\d+)\s*', line)
            assert match, line
            index, depth, target, parent, state, revealed, leaf = map(int, match.groups())
            assert index not in seen, f'repeated first hit: {index}'
            assert index in expected_proof_ids(depth, bool(parent), target, state, revealed, leaf), line
            seen.add(index)
        elif 'sparse_bucket_v1' in line:
            match = pattern.fullmatch(line.strip())
            assert match, line
            index, depth, root, state, revealed, leaf = map(int, match.groups())
            assert index not in seen, f'repeated first hit: {index}'
            assert index in expected_ids(depth, bool(root), state, revealed, leaf), line
            seen.add(index)
        elif 'sparse_observations_v1' in line:
            match = re.fullmatch(r'sparse_observations_v1 count=(\d+)\s*', line)
            assert match, line
            value = int(match[1])
            assert value > 0 and value & (value - 1) == 0, line
            observations.append(value)
    assert setup and completed, 'Workload did not complete setup and a verified round'
    assert seen and len(seen) < len(arms()), 'No valid runtime sparse coverage hits'
    offset = 0
    for name, _, keys in families():
        assert seen.intersection(range(offset, offset + len(keys))), f'Missing runtime coverage family: {name}'
        offset += len(keys)
    assert seen.intersection(range(LOCAL_START, SANDWICH_START)), 'Missing runtime coverage family: local'
    # Random short smoke runs need a real proof hook hit, not a particular sandwich.
    # Exact sandwich directions/leaf states are covered deterministically by callback tests.
    assert observations and len(set(observations)) == len(observations) <= 64, 'Missing/bad observation counter'
    print(f'Verified {len(seen)} first-hit buckets; at least {max(observations)} runtime branches observed')


if __name__ == '__main__':
    with open(sys.argv[1], encoding='utf-8') as events, open(sys.argv[2], encoding='utf-8') as diagnostics:
        validate(events, diagnostics)
