import unittest
from diagnostic import decode


def stream(events, cutoff=50, count=None):
    rows = [f'E,{ts},{thread},{kind},{state}' for ts, thread, kind, state in events]
    return '\n'.join(rows + [f'C,{cutoff}', f'@emitted: {len(events)+1 if count is None else count}', '@emitted: 0'])


def fixture():
    # Main, a blocked worker, and a preempted/migrated worker. Endpoints after
    # cutoff are observed privately, then intersected; no raw post data survives.
    return [(1,1,0,0), (2,2,0,0), (3,3,0,0), (10,2,1,1),
            (12,3,1,256), (15,3,5,0), (20,2,3,0), (30,2,2,0),
            (60,3,2,0), (65,2,4,0), (66,3,4,0), (70,1,4,0)]


class DiagnosticTests(unittest.TestCase):
    def test_packed_switches_preserve_edges_cutoff_and_migration(self):
        rows = fixture()
        text = stream(rows)
        packed = text.replace('E,10,2,1,1', '').replace('E,30,2,2,0', 'P,10,30,2,1')
        packed = packed.replace('E,12,3,1,256', '').replace('E,60,3,2,0', 'P,12,60,3,256')
        for cutoff in (10, 12, 20, 30, 50, 60, 71):
            with self.subTest(cutoff=cutoff):
                expected = decode(text.replace('C,50', f'C,{cutoff}'), '', 0, 0)
                actual = decode(packed.replace('C,50', f'C,{cutoff}'), '', 0, 0)
                self.assertEqual(actual, expected)
                self.assertEqual(decode('\n'.join(list(reversed(packed.replace('C,50', f'C,{cutoff}').splitlines()[:-2])) + packed.splitlines()[-2:]), '', 0, 0), expected)

    def test_packed_edges_still_require_each_source_edge_in_footer(self):
        text = stream([(1,1,0,0), (10,1,1,0), (20,1,2,0), (30,1,4,0)])
        packed = text.replace('E,10,1,1,0', '').replace('E,20,1,2,0', 'P,10,20,1,0')
        self.assertEqual(decode(text, '', 0, 0, expected_threads={1}),
                         decode(packed, '', 0, 0, expected_threads={1}))
        for invalid in (packed.replace('@emitted: 5', '@emitted: 4'),
                        packed.replace('P,10,20', 'P,20,10'),
                        packed.replace('P,10,20,1,0', 'P,10,20,1,512'),
                        packed.replace('P,10,20,1,0', 'P,10,20,0,0'),
                        packed + '\nLost 1 events'):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    decode(invalid, '', 0, 0, expected_threads={1})

    def test_packed_missing_or_duplicate_edges_remain_invalid(self):
        for middle in ('E,5,1,1,0\nP,10,20,1,0', 'P,10,20,1,0\nE,25,1,2,0'):
            with self.assertRaisesRegex(ValueError, 'missing switch'):
                decode(f'E,1,1,0,0\n{middle}\nE,30,1,4,0\nC,40\n@emitted: 6',
                       '', 0, 0, expected_threads={1})

    def test_sleep_runnable_migration_and_strict_cutoff(self):
        capture = decode(stream(fixture()), '', 0, 0)
        self.assertTrue(capture['registered_window_edges_complete'])
        self.assertTrue(all(r['ts'] < 50 for r in capture['records']))
        self.assertTrue(all(r['end'] < 50 for r in capture['intervals']))
        self.assertIn({'thread':3,'start':12,'end':49,'kind':'runnable_off_cpu','right_censored':True}, capture['intervals'])
        self.assertEqual({r['kind'] for r in capture['intervals']},
                         {'scheduled_on_cpu','blocked_before_wakeup','runnable_after_wakeup','runnable_off_cpu'})

    def test_cutoff_equality_pruned(self):
        result = decode(stream(fixture(), cutoff=20), '', 0, 0)
        self.assertNotIn('wakeup', [r['kind'] for r in result['records']])
        self.assertTrue(all(r['end'] < 20 for r in result['intervals']))

    def test_missing_wakeup_is_unsplit_not_blocked(self):
        rows = [r for r in fixture() if r[2] != 3]
        result = decode(stream(rows), '', 0, 0)
        self.assertFalse(result['registered_window_edges_complete'])
        self.assertEqual(result['quality']['unclassified_off_cpu_intervals'], 1)
        self.assertIn('off_cpu_unsplit', [r['kind'] for r in result['intervals']])

    def test_unclosed_interval_not_extended(self):
        rows = [r for r in fixture() if not (r[1] == 3 and r[2] == 2)]
        result = decode(stream(rows), '', 0, 0)
        self.assertFalse(result['registered_window_edges_complete'])
        self.assertEqual(result['quality']['unclosed_intervals_excluded'], 1)
        self.assertFalse(any(r['thread'] == 3 and r['start'] >= 12 for r in result['intervals']))

    def test_lost_event_footer_mismatch(self):
        rows = fixture()
        with self.assertRaisesRegex(ValueError, 'loss'):
            decode(stream(rows[:-1], count=len(rows)+1), '', 0, 0)

    def test_registration_missing_even_with_matching_footer(self):
        rows = [r for r in fixture() if not (r[1] == 2 and r[2] == 0)]
        with self.assertRaisesRegex(ValueError, 'registration'):
            decode(stream(rows), '', 0, 0)

    def test_reused_ordinal_rejected(self):
        rows = fixture() + [(71,2,0,0)]
        with self.assertRaisesRegex(ValueError, 'reused'):
            decode(stream(rows), '', 0, 0)

    def test_event_after_exit_rejected(self):
        rows = fixture() + [(71,2,1,0)]
        with self.assertRaisesRegex(ValueError, 'exit'):
            decode(stream(rows), '', 0, 0)

    def test_missing_exit_rejected(self):
        with self.assertRaisesRegex(ValueError, 'coverage'):
            decode(stream(fixture()[:-1]), '', 0, 0)

    def test_attach_gap_rejected(self):
        rows = [(0,2,1,0)] + fixture()
        with self.assertRaisesRegex(ValueError, 'registration'):
            decode(stream(rows), '', 0, 0)

    def test_native_output_never_echoed(self):
        for stdout, stderr, status in [('PRIVATE_NATIVE_ID', '', 0), (stream(fixture()), 'lost PRIVATE_NATIVE_ID', 0), ('', '', 1)]:
            with self.assertRaises(ValueError) as error:
                decode(stdout, stderr, status, 0)
            self.assertNotIn('PRIVATE_NATIVE_ID', str(error.exception))

    def test_clock_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, 'clock'):
            decode(stream(fixture()), '', 0, 5)

    def test_unknown_state_rejected(self):
        with self.assertRaisesRegex(ValueError, 'state'):
            decode(stream(fixture() + [(4,1,1,512)]), '', 0, 0)

    def test_cpu_ring_delivery_order_is_sorted(self):
        self.assertEqual(decode(stream(fixture()), '', 0, 0),
                         decode(stream(list(reversed(fixture()))), '', 0, 0))


if __name__ == '__main__':
    unittest.main()
