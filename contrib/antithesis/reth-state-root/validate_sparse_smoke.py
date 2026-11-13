#!/usr/bin/env python3
"""Check SDK completion and bounded first-hit evidence from an immutable workload."""
import json
import re
import sys
from generate_sparse_buckets import LOCAL_COUNT, arms

NO_PARENT = LOCAL_COUNT


def expected_proof_ids(depth, parent, target, state, revealed, leaf):
    if not parent:
        assert (depth, target, state, revealed, leaf) == (0, 0, 0, 0, 0), 'invalid parentless target'
        return {NO_PARENT}
    assert 0 <= target < 16, 'invalid target nibble'
    assert 0 <= depth < 64, 'invalid branch depth'
    assert all(0 <= m <= 65535 for m in (state, revealed, leaf)), 'invalid mask width'
    assert revealed & ~state == 0 and leaf & ~revealed == 0, 'invalid runtime mask subsets'
    assert state & (1 << target) and not revealed & (1 << target), 'target must be blinded'
    depth = next(i for i, maximum in enumerate((0, 1, 4, 8, 16, 32, 63)) if depth <= maximum)
    pattern = 0
    for slot, position in enumerate((target - 2, target - 1, target + 1, target + 2)):
        kind = 0
        if 0 <= position < 16 and state & (1 << position):
            kind = 1 if not revealed & (1 << position) else 3 if leaf & (1 << position) else 2
        pattern += kind * 4 ** slot
    return {(depth * 16 + target) * 256 + pattern}


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
    for line in diagnostics:
        if 'sparse_proof_bucket_v1' in line:
            match = re.fullmatch(r'sparse_proof_bucket_v1 id=(\d+) depth=(\d+) target=(\d+) parent=([01]) state=(\d+) revealed=(\d+) leaf=(\d+)\s*', line)
            assert match, line
            index, depth, target, parent, state, revealed, leaf = map(int, match.groups())
            assert index not in seen, f'repeated first hit: {index}'
            assert index in expected_proof_ids(depth, bool(parent), target, state, revealed, leaf), line
            seen.add(index)
        else:
            assert not any(marker in line for marker in (
                'sparse_bucket_v1', 'sparse_observations_v1', 'coverage_sandwich_',
                'sparse_encoder_', 'sparse_sandwich_')), f'Removed guidance family emitted: {line}'
    assert setup and completed, 'Workload did not complete setup and a verified round'
    assert seen and len(seen) <= len(arms()), 'No valid runtime sparse coverage hits'
    assert seen.intersection(range(LOCAL_COUNT)), 'Missing runtime coverage family: local'
    print(f'Verified {len(seen)} local-only first-hit buckets')


if __name__ == '__main__':
    with open(sys.argv[1], encoding='utf-8') as events, open(sys.argv[2], encoding='utf-8') as diagnostics:
        validate(events, diagnostics)
