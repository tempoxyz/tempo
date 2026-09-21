import copy
import base64
import io
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import capacity_election as election
import prebuilt
from test_prebuilt import encoded as encoded_prebuilt, fixture as prebuilt_fixture

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

    def test_single_diagnostic_requires_one_prebuilt_receipt_without_setup_fallback(self):
        plan, _ = prebuilt_fixture()
        raw = encoded_prebuilt(plan)
        proof = prebuilt.budget(raw)
        value = receipt(1)
        value['prebuilt'] = proof
        elected = election.elect(
            [value], **BINDING, slots=1, policy=election.SINGLE_DIAGNOSTIC_POLICY,
            prebuilt_plan=raw.decode())
        self.assertEqual(elected['selected_slot'], 1)

        prebuilt_source = Path(prebuilt.__file__).read_bytes()
        election_source = Path(election.__file__).read_text()
        bootstrap = (
            "import base64,types,sys\n"
            "m=types.ModuleType('prebuilt')\n"
            f"exec(base64.b64decode('{base64.b64encode(prebuilt_source).decode()}'),m.__dict__)\n"
            "sys.modules['prebuilt']=m\n" + election_source)
        args = [sys.executable, '-I', '-c', bootstrap, '--workflow-sha', SHA,
                '--run-id', str(BINDING['run_id']), '--run-attempt', '2', '--slots', '1',
                '--policy', election.SINGLE_DIAGNOSTIC_POLICY,
                '--binary-mode', 'prebuilt_v1']
        envelope = dict(schema=3, receipts=[value], prebuilt_plan=raw.decode())
        result = subprocess.run(args, input=json.dumps(envelope).encode(), capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['selected_slot'], 1)
        for mutation in (
                {**envelope, 'schema': 2},
                {**envelope, 'setup_failed_slots': []},
                {'schema': 3, 'receipts': [value]}):
            result = subprocess.run(args, input=json.dumps(mutation).encode(), capture_output=True)
            self.assertEqual(result.returncode, 2, result.stderr)

        for policy, slots, failures, plan_value in (
                (election.SINGLE_DIAGNOSTIC_POLICY, 2, None, raw.decode()),
                (election.SINGLE_DIAGNOSTIC_POLICY, 1, [], raw.decode()),
                (election.SINGLE_DIAGNOSTIC_POLICY, 1, None, None),
                ('strict_v1', 1, None, None)):
            with self.assertRaises(election.InvalidReceipt):
                election.elect([value], **BINDING, slots=slots, policy=policy,
                               setup_failed_slots=failures, prebuilt_plan=plan_value)

    def test_five_slots_all_120_orders_ties_and_exact_accounted_union(self):
        for capacities, winner in [([70000]*5, 1), ([1,70000,71000,72000,80000], 5)]:
            receipts = [receipt(i+1, root=n, workspace=n) for i,n in enumerate(capacities)]
            snapshot = copy.deepcopy(receipts)
            for order in itertools.permutations(receipts):
                self.assertEqual(election.elect(list(order), **BINDING, slots=5,
                                 setup_failed_slots=[])['selected_slot'], winner)
            self.assertEqual(receipts, snapshot)
        for absent in range(1, 6):
            receipts = [receipt(i) for i in range(1, 6) if i != absent]
            for order in itertools.permutations(receipts):
                self.assertEqual(election.elect(list(order), **BINDING, slots=5,
                                 setup_failed_slots=[absent])['selected_slot'], min(set(range(1, 6))-{absent}))
        for winner in range(1, 6):
            self.assertEqual(election.elect([receipt(winner)], **BINDING, slots=5,
                             setup_failed_slots=[i for i in range(1,6) if i!=winner])['selected_slot'], winner)
        receipts = [receipt(i) for i in range(1, 6)]
        for row in receipts[4]['capacity']['locations'][:2]: row['free_bytes'] += 1
        self.assertEqual(election.elect(receipts, **BINDING, slots=5,
                         setup_failed_slots=[])['selected_slot'], 5)

    def test_five_slot_omissions_conflicts_types_and_no_eligible_reject(self):
        for receipts, failed in [([receipt(i) for i in range(1,5)], []),
                                 ([receipt(i) for i in range(1,5)], [4]),
                                 ([receipt(i) for i in range(1,5)], [5,5]),
                                 ([receipt(i) for i in range(1,5)], [6]),
                                 ([], list(range(1,6))),
                                 ([receipt(5)], [1,2,3,True]),
                                 ([receipt(5)], [1,2,3,4.0])]:
            with self.assertRaises(election.InvalidReceipt):
                election.elect(receipts, **BINDING, slots=5, setup_failed_slots=failed)
        for slots in (True, 5.0, '5', 6):
            with self.assertRaises(election.InvalidReceipt):
                election.elect([receipt(i) for i in range(1,6)], **BINDING, slots=slots, setup_failed_slots=[])
        for key,value in [('run_attempt',99),('slot',True),('slot',4),('slot',6),('workflow_sha','b'*40)]:
            receipts=[receipt(i) for i in range(1,6)];receipts[-1][key]=value
            with self.assertRaises(election.InvalidReceipt):
                election.elect(receipts, **BINDING, slots=5, setup_failed_slots=[])
        self.assertEqual(election.elect([receipt(5, root=65535)], **BINDING,
                         slots=5, setup_failed_slots=[1,2,3,4])['status'],2)

    def test_setup_accounting_exact_disjoint_union_and_eligible_winner(self):
        for failed in ([1], [2], [3], [4], [1, 2, 3]):
            receipts = [receipt(i) for i in range(1, 5) if i not in failed]
            for order in itertools.permutations(receipts):
                value = election.elect(list(order), **BINDING, slots=4, setup_failed_slots=failed)
                self.assertEqual(value['selected_slot'], min(set(range(1, 5))-set(failed)))
        for failed in (None, '1', [True], [1.0], [0], [5], [1, 1], [1, 2, 3, 4], [1, 2]):
            with self.assertRaises(election.InvalidReceipt):
                election.elect([receipt(2), receipt(3), receipt(4)], **BINDING, slots=4, setup_failed_slots=failed)
        for receipts, failed in [([receipt(1), receipt(2), receipt(3)], [1]),
                                 ([receipt(1), receipt(2)], [4]),
                                 ([receipt(1), receipt(2), receipt(3), receipt(4)], [4])]:
            with self.assertRaises(election.InvalidReceipt):
                election.elect(receipts, **BINDING, slots=4, setup_failed_slots=failed)
        self.assertEqual(election.elect([receipt(4, root=65535)], **BINDING,
                         slots=4, setup_failed_slots=[1, 2, 3])['status'], 2)
        with self.assertRaises(election.InvalidReceipt):
            election.elect([receipt(1)], **BINDING, slots=2, setup_failed_slots=[2])

    def test_four_slots_all_permutations_ties_and_byte_precision(self):
        for free, winner in [([70000, 71000, 72000, 80000], 4),
                             ([80000, 71000, 72000, 70000], 1),
                             ([70000]*4, 1), ([1, 70000, 70000, 1], 2)]:
            receipts = [receipt(i+1, root=value, workspace=value) for i, value in enumerate(free)]
            before = copy.deepcopy(receipts)
            for order in itertools.permutations(receipts):
                self.assertEqual(election.elect(list(order), **BINDING, slots=4)['selected_slot'], winner)
            self.assertEqual(before, receipts)
        receipts = [receipt(i) for i in range(1, 5)]
        for row in receipts[3]['capacity']['locations'][:2]: row['free_bytes'] += 1
        self.assertEqual(election.elect(receipts, **BINDING, slots=4)['selected_slot'], 4)

    def test_four_slots_requires_exact_complete_bound_closed_receipts(self):
        receipts = [receipt(i) for i in range(1, 5)]
        for missing in range(4): self.rejected(receipts[:missing]+receipts[missing+1:], slots=4)
        self.rejected(receipts+[receipt(5)], slots=4)
        for field, bad in [('slot', 3), ('slot', 5), ('slot', True), ('slot', 4.0),
                           ('run_id', BINDING['run_id']+1), ('run_attempt', 1),
                           ('workflow_sha', 'b'*40), ('slots', 4)]:
            mutated = copy.deepcopy(receipts); mutated[3][field] = bad
            self.rejected(mutated, slots=4)
        for slots in (None, True, 1, 5, '4', 4.0, 2, 3):
            self.rejected(receipts, slots=slots)
        for depth in ('receipt', 'capacity', 'row'):
            mutated = copy.deepcopy(receipts)
            target = mutated[3] if depth == 'receipt' else mutated[3]['capacity']
            if depth == 'row': target = target['locations'][0]
            target['runner_name'] = 'PRIVATE_IDENTIFIER'
            self.rejected(mutated, slots=4)
        for missing in range(4):
            mutated = copy.deepcopy(receipts)
            mutated[missing]['capacity']['locations'][0]['free_bytes'] = True
            self.rejected(mutated, slots=4)
        none = [receipt(i, root=65535) for i in range(1, 5)]
        self.assertEqual(election.elect(none, **BINDING, slots=4)['status'], 2)

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

    def test_five_slot_cli_requires_declared_count_and_closed_envelope(self):
        envelope=dict(schema=2,receipts=[receipt(5)],setup_failed_slots=[1,2,3,4])
        encoded=json.dumps(envelope).encode()
        args=('--slots','5','--policy',election.SETUP_FAILURE_POLICY)
        self.assertEqual(self.cli(encoded,*args,use_source=True)['selected_slot'],5)
        for count in ('4','6','05','5.0'):
            self.cli(encoded,'--slots',count,'--policy',election.SETUP_FAILURE_POLICY,code=2)
        self.cli(encoded,'--slots','5',code=2)

    def test_setup_accounting_cli_is_explicit_closed_and_preserves_legacy(self):
        envelope = dict(schema=2, receipts=[receipt(1), receipt(2), receipt(3)], setup_failed_slots=[4])
        args = ('--slots', '4', '--policy', election.SETUP_FAILURE_POLICY)
        self.assertEqual(self.cli(json.dumps(envelope).encode(), *args, use_source=True)['selected_slot'], 1)
        self.cli(json.dumps(envelope).encode(), '--slots', '4', code=2)
        self.cli(json.dumps(envelope['receipts']).encode(), *args, code=2)
        for key, value in [('schema', True), ('schema', 1), ('setup_failed_slots', [3]),
                           ('setup_failed_slots', [4, 4]), ('untrusted_job', {})]:
            mutated = dict(envelope); mutated[key] = value
            self.cli(json.dumps(mutated).encode(), *args, code=2)
        self.cli(json.dumps(envelope).encode().replace(b'"schema": 2',b'"schema":2,"schema":2'), *args, code=2)
        self.cli(json.dumps(envelope).encode(), '--slots', '3', '--policy', election.SETUP_FAILURE_POLICY, code=2)

    def test_four_slot_isolated_cli_complete_stdin_paths_and_budget(self):
        receipts = [receipt(i, root=1 if i < 4 else 70000) for i in range(1, 5)]
        self.assertEqual(self.cli(json.dumps(receipts).encode(), '--slots', '4', use_source=True)['selected_slot'], 4)
        for slots in ('2', '3', '5', '04', '4.0'):
            self.cli(json.dumps(receipts).encode(), '--slots', slots, code=2)
        self.cli(json.dumps(receipts[:3]).encode(), '--slots', '4', code=2)
        self.cli(json.dumps([receipt(i, root=1) for i in range(1, 5)]).encode(), '--slots', '4', code=3)
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory)/f'PRIVATE_{i}.json' for i in range(4)]
            for path, data in zip(paths, receipts): path.write_text(json.dumps(data))
            self.assertEqual(self.cli(b'', '--slots', '4', *map(str, paths))['selected_slot'], 4)
            self.cli(b'', '--slots', '4', *map(str, paths[:3]), code=2)
            paths[3].write_bytes(b' ' * election.MAX_BYTES)
            self.cli(b'', '--slots', '4', *map(str, paths), code=2)
            paths[3].unlink()
            self.cli(b'', '--slots', '4', *map(str, paths), code=2)

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
