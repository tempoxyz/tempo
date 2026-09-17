import copy
import io
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import capacity_election as election

SHA = 'a' * 40
BINDING = dict(workflow_sha=SHA, run_id=35197245767, run_attempt=2)


def report(root=70000, workspace=70000):
    rows = []
    for index, role in enumerate(election.ROLES):
        if index < 2:
            rows.append(dict(role=role, exists=True, filesystem=index + 1,
                             total_bytes=100000 * election.MIB,
                             free_bytes=(root if index == 0 else workspace) * election.MIB,
                             read_only=False, writable=True, write_tested=True, status='writable'))
        else:
            rows.append(dict(role=role, exists=False, filesystem=None,
                             total_bytes=None, free_bytes=None, read_only=None,
                             writable=None, write_tested=False, status='unset'))
    return dict(schema=1, locations=rows)


def receipt(slot, **capacity):
    return dict(schema=1, **BINDING, slot=slot, capacity=report(**capacity))


class ElectionTests(unittest.TestCase):
    def rejected(self, pair, slots=2):
        with self.assertRaises(election.InvalidReceipt):
            election.elect(pair, **BINDING, slots=slots)

    def test_three_slots_complete_order_independent_winner_and_ties(self):
        receipts = [receipt(1, root=65535), receipt(2), receipt(3, root=80000, workspace=79000)]
        snapshot = copy.deepcopy(receipts)
        for order in itertools.permutations(receipts):
            self.assertEqual(election.elect(list(order), **BINDING, slots=3),
                             dict(schema=1, status=0, selected_slot=3,
                                  root_free_mib=80000, workspace_free_mib=79000, minimum_free_mib=79000))
        self.assertEqual(receipts, snapshot)
        for order in itertools.permutations([receipt(1), receipt(2), receipt(3)]):
            self.assertEqual(election.elect(list(order), **BINDING, slots=3)['selected_slot'], 1)
        tied = [receipt(1, root=1), receipt(3), receipt(2)]
        self.assertEqual(election.elect(tied, **BINDING, slots=3)['selected_slot'], 2)
        for row in tied[1]['capacity']['locations'][:2]:
            row['free_bytes'] += 1
        self.assertEqual(election.elect(tied, **BINDING, slots=3)['selected_slot'], 3)

    def test_three_slots_missing_duplicate_foreign_and_policy_types_reject(self):
        for receipts in ([], [receipt(3)], [receipt(1), receipt(2)],
                         [receipt(1), receipt(2), receipt(2)],
                         [receipt(1), receipt(2), receipt(4)],
                         [receipt(1), receipt(2), receipt(3), receipt(4)]):
            self.rejected(receipts, slots=3)
        for field, bad in [('workflow_sha', 'b'*40), ('run_id', BINDING['run_id']+1),
                           ('run_attempt', 1), ('slot', True), ('slot', 3.0), ('slot', '3')]:
            receipts = [receipt(1), receipt(2), receipt(3)]
            receipts[2][field] = bad
            self.rejected(receipts, slots=3)
        for bad in (None, True, False, 1, 4, 2.0, 3.0, '3', election.MAX_INTEGER+1):
            self.rejected([receipt(1), receipt(2), receipt(3)], slots=bad)
        self.rejected([receipt(1), receipt(2), receipt(3)])
        for depth in ('receipt', 'capacity', 'row'):
            receipts = [receipt(1), receipt(2), receipt(3)]
            target = receipts[2] if depth == 'receipt' else receipts[2]['capacity']
            if depth == 'row': target = target['locations'][0]
            target['runner_name'] = 'PRIVATE_IDENTIFIER'
            self.rejected(receipts, slots=3)

    def test_three_slots_ineligible_failure_has_no_fallback(self):
        receipts = [receipt(1, root=65535), receipt(2, workspace=65535), receipt(3)]
        receipts[2]['capacity']['locations'][0].update(
            status='read_only', read_only=True, writable=False, write_tested=False)
        self.assertEqual(election.elect(receipts, **BINDING, slots=3),
                         dict(schema=1, status=2, selected_slot=0,
                              root_free_mib=0, workspace_free_mib=0, minimum_free_mib=0))
        # A malformed third receipt disqualifies the invocation even if slot 1 is eligible.
        receipts[0] = receipt(1)
        receipts[2]['capacity']['locations'][1]['free_bytes'] = True
        self.rejected(receipts, slots=3)

    def test_pair_order_and_minimum_capacity_election(self):
        pair = [receipt(1, root=80000, workspace=66000), receipt(2, root=70000, workspace=71000)]
        winner = election.elect(pair, **BINDING)
        self.assertEqual(winner, election.elect(pair[::-1], **BINDING))
        self.assertEqual(winner, dict(schema=1, status=0, selected_slot=2,
                                     root_free_mib=70000, workspace_free_mib=71000, minimum_free_mib=70000))
        self.assertTrue(all(type(value) is int for value in winner.values()))

    def test_tie_uses_lower_slot_and_compares_bytes(self):
        pair = [receipt(2), receipt(1)]
        self.assertEqual(election.elect(pair, **BINDING)['selected_slot'], 1)
        for row in pair[0]['capacity']['locations'][:2]:
            row['free_bytes'] += 1
        self.assertEqual(election.elect(pair, **BINDING)['selected_slot'], 2)

    def test_boundary_and_explicit_no_eligible(self):
        pair = [receipt(1, root=65536, workspace=65536), receipt(2, workspace=65535)]
        self.assertEqual(election.elect(pair, **BINDING)['selected_slot'], 1)
        pair[0]['capacity']['locations'][0]['free_bytes'] -= 1
        self.assertEqual(election.elect(pair, **BINDING)['status'], 2)
        self.assertEqual(election.elect(pair, **BINDING)['selected_slot'], 0)
        pair = [receipt(1), receipt(2, root=65535)]
        pair[0]['capacity']['locations'][1].update(writable=False, write_tested=False, status='access_denied')
        self.assertEqual(election.elect(pair, **BINDING)['status'], 2)

    def test_failed_root_observation_is_never_eligible(self):
        for status, read_only, writable, tested in (
            ('read_only', True, False, False),
            ('unavailable', False, None, False),
            ('write_failed', False, False, True),
        ):
            pair = [receipt(1), receipt(2, root=1)]
            pair[0]['capacity']['locations'][0].update(
                status=status, read_only=read_only, writable=writable, write_tested=tested)
            self.assertEqual(election.elect(pair, **BINDING)['status'], 2)
        pair = [receipt(1), receipt(2, root=1)]
        pair[0]['capacity']['locations'][0].update(
            status='access_denied', read_only=False, writable=False, write_tested=False)
        self.assertEqual(election.elect(pair, **BINDING)['selected_slot'], 1)

    def test_foreign_stale_duplicate_and_missing(self):
        for field, bad in [('workflow_sha', 'b' * 40), ('run_id', BINDING['run_id'] + 1),
                           ('run_attempt', 1), ('slot', 1)]:
            pair = [receipt(1), receipt(2)]
            pair[1][field] = bad
            self.rejected(pair)
        for pair in ([], [receipt(1)], [receipt(1), receipt(2), receipt(2)]):
            self.rejected(pair)

    def test_numeric_types_ranges_and_closed_fields(self):
        for field in ('schema', 'run_id', 'run_attempt', 'slot'):
            for bad in (True, False, 1.0, '1', -1, election.MAX_INTEGER + 1):
                with self.subTest(field=field, bad=bad):
                    pair = [receipt(1), receipt(2)]
                    pair[0][field] = bad
                    self.rejected(pair)
        for field in ('filesystem', 'total_bytes', 'free_bytes'):
            for bad in (True, -1, 1.5, '65536', election.MAX_INTEGER + 1):
                pair = [receipt(1), receipt(2)]
                pair[0]['capacity']['locations'][0][field] = bad
                self.rejected(pair)
        for depth in ('receipt', 'capacity', 'row'):
            pair = [receipt(1), receipt(2)]
            target = pair[0] if depth == 'receipt' else pair[0]['capacity']
            if depth == 'row': target = target['locations'][0]
            target['runner_name'] = 'PRIVATE_IDENTIFIER'
            self.rejected(pair)

    def test_exact_probe_roles_states_and_ordinals(self):
        for mutate in (
            lambda rows: rows.reverse(),
            lambda rows: rows.pop(),
            lambda rows: rows[0].update(status='private_status'),
            lambda rows: rows[0].update(free_bytes=rows[0]['total_bytes'] + 1),
            lambda rows: rows[0].update(filesystem=4),
            lambda rows: rows[0].update(exists=1),
            lambda rows: rows[1].update(writable=1),
            lambda rows: rows[1].update(status='writable', write_tested=False),
            lambda rows: rows[2].update(status='cleanup_failed', exists=True, filesystem=3,
                                      total_bytes=100, free_bytes=10, read_only=False,
                                      writable=None, write_tested=True),
        ):
            pair = [receipt(1), receipt(2)]
            mutate(pair[0]['capacity']['locations'])
            self.rejected(pair)
        pair = [receipt(1), receipt(2)]
        pair[0]['capacity']['locations'][1]['filesystem'] = 1
        self.assertEqual(election.elect(pair, **BINDING)['status'], 0)
        pair[0]['capacity']['locations'][2]['status'] = 'missing'
        self.assertEqual(election.elect(pair, **BINDING)['status'], 0)

    def test_json_duplicate_nan_and_input_bounds(self):
        for data in (b'{"schema":1,"schema":1}', b'[NaN]', b'[Infinity]', b' ' * (election.MAX_BYTES + 1)):
            with self.assertRaises((election.InvalidReceipt, ValueError)):
                election.parse(data)
        original = [receipt(1), receipt(2)]
        snapshot = copy.deepcopy(original)
        election.elect(original, **BINDING)
        self.assertEqual(original, snapshot)

    def cli(self, data, *extra, code=0, use_source=False):
        source = Path(election.__file__).read_text()
        command = [sys.executable, '-I'] + (['-c', source] if use_source else [election.__file__])
        command += ['--workflow-sha', SHA, '--run-id', str(BINDING['run_id']), '--run-attempt', '2', *extra]
        result = subprocess.run(command, input=data, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertEqual(result.stderr, b'')
        self.assertNotIn(b'PRIVATE', result.stdout)
        parsed = json.loads(result.stdout)
        self.assertTrue(all(type(value) is int for value in parsed.values()))
        return parsed

    def test_exact_isolated_source_cli_and_private_failure_output(self):
        pair = [receipt(1), receipt(2)]
        self.assertEqual(self.cli(json.dumps(pair).encode(), use_source=True)['selected_slot'], 1)
        self.assertEqual(self.cli(json.dumps([receipt(1, root=1), receipt(2, root=1)]).encode(), code=3)['status'], 2)
        for data in (b'PRIVATE', b' ' * (election.MAX_BYTES + 1), b'[' * 1500 + b']' * 1500):
            self.assertEqual(self.cli(data, code=2)['status'], 1)
        self.cli(b'[]', '--PRIVATE-ARG', code=2)
        self.cli(b'[]', '--run-id', '1.0', code=2)
        self.cli(b'[]', '--run-id', str(election.MAX_INTEGER + 1), code=2)

    def test_two_paths_and_combined_size_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / 'PRIVATE_A.json', Path(directory) / 'PRIVATE_B.json']
            for slot, path in enumerate(paths, 1): path.write_text(json.dumps(receipt(slot)))
            self.assertEqual(self.cli(b'', *map(str, paths))['selected_slot'], 1)
            self.cli(b'', str(paths[0]), code=2)
            paths[1].write_bytes(b' ' * election.MAX_BYTES)
            self.cli(b'', *map(str, paths), code=2)
            paths[1].unlink()
            self.cli(b'', *map(str, paths), code=2)

    def test_three_slot_isolated_cli_complete_stdin_and_paths(self):
        receipts = [receipt(1, root=1), receipt(2, root=1), receipt(3)]
        self.assertEqual(self.cli(json.dumps(receipts).encode(), '--slots', '3', use_source=True)['selected_slot'], 3)
        self.cli(json.dumps(receipts).encode(), code=2)
        self.cli(json.dumps(receipts[:2]).encode(), '--slots', '3', code=2)
        self.cli(json.dumps([receipt(i, root=1) for i in (1,2,3)]).encode(), '--slots', '3', code=3)
        for value in ('1', '4', '3.0', 'true', 'PRIVATE'):
            self.cli(json.dumps(receipts).encode(), '--slots', value, code=2)
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory)/f'PRIVATE_{i}.json' for i in (1,2,3)]
            for path, data in zip(paths, receipts):path.write_text(json.dumps(data))
            self.assertEqual(self.cli(b'', '--slots', '3', *map(str, paths))['selected_slot'], 3)
            self.cli(b'', '--slots', '3', *map(str, paths[:2]), code=2)
            paths[2].write_bytes(b' ' * election.MAX_BYTES)
            self.cli(b'', '--slots', '3', *map(str, paths), code=2)
            paths[2].write_text(json.dumps(receipts[2]))
            paths[1].unlink()
            self.cli(b'', '--slots', '3', *map(str, paths), code=2)


if __name__ == '__main__':
    unittest.main()
