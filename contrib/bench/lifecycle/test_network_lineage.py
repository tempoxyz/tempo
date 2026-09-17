import copy
import json
from pathlib import Path
import tempfile
import unittest

from network_lineage import build_lineage
from report import build
from report_package import write_package
from perfetto import trace_events
from test_report import fixture
from test_package import embedded

A, B = 'Validator A', 'Validator B'


def event(stage, ts, node=A, block=None, span=1, **fields):
    return dict(node=node, ts=ts, id=span, block=block, fields=dict(stage=stage, **fields))


class NetworkLineageTests(unittest.TestCase):
    def test_distinct_batch_origins_and_fanout_keep_exact_frames(self):
        events = [event('message_origin', 0, block='a', message_id=1),
                  event('message_origin', 1, block='b', message_id=2)]
        for i, source in enumerate([1, 2, 1], 1):
            events += [event('frame_send', i*10, message_id=source, frame_hash=str(i), bytes=20),
                       event('frame_receive', i*10+1, B, receive_id=i, frame_hash=str(i)),
                       event('frame_authenticated', i*10+2, B, receive_id=i),
                       event('message_decode_result', i*10+3, B, receive_id=i, accepted=1)]
        transfers, rows, messages = build_lineage(events, [], {'a':11, 'b':22}, 0)
        self.assertEqual([t['source_blocks'] for t in transfers], [[11], [22], [11]])
        self.assertEqual([t['receive_id'] for t in transfers], [1, 2, 3])
        self.assertTrue(all(t['authentication_observed'] and t['decode_result'] for t in transfers))
        self.assertEqual([m['frame_count'] for m in messages], [2, 1])
        self.assertEqual(next(e for e in rows if e['stage'] == 'message_origin' and e['message_id'] == 1)['frames'], [1, 3])

    def test_fanout_receive_scopes_do_not_leak_into_other_frame_milestones(self):
        events = [event('message_origin', 0, message_id=1)]
        for i, block in [(1, 'a'), (2, 'b')]:
            events += [event('frame_send', i*10, message_id=1, frame_hash=str(i)),
                       event('frame_receive', i*10+1, B, receive_id=i, frame_hash=str(i)),
                       event('message_decode', i*10+2, B, span=i+10, receive_id=i, block=block)]
        transfers, rows, _ = build_lineage(events, [], {'a':11, 'b':22}, 0)
        self.assertEqual([t['blocks'] for t in transfers], [[11], [22]])
        for stage in ['frame_send', 'frame_receive', 'message_decode']:
            self.assertEqual([e['blocks'] for e in rows if e['stage'] == stage], [[11], [22]])
        self.assertEqual(rows[0]['blocks'], [11, 22])

    def test_control_ambiguous_rejected_and_unmatched_are_preserved(self):
        events = [event('message_origin', 0, message_id=1, block='a'),
                  event('message_router_queue', 1, message_id=1, accepted=0),
                  event('message_origin', 2, message_id=2, block='a'),
                  event('message_origin', 3, message_id=2, block='b'),
                  event('frame_send', 4, message_id=2, frame_hash='ambiguous'),
                  event('frame_receive', 5, B, frame_hash='ambiguous'),
                  event('frame_send', 6, message_id=0, frame_hash='control'),
                  event('frame_receive', 7, B, frame_hash='control'),
                  event('frame_send', 8, frame_hash='unmatched')]
        transfers, rows, messages = build_lineage(events, [], {'a':11, 'b':22}, 0)
        self.assertEqual(len(rows), len(events))
        self.assertEqual([t['blocks'] for t in transfers], [[], []])
        self.assertIsNone(transfers[0]['decode_result'])
        self.assertFalse(transfers[0]['authentication_observed'])
        self.assertEqual(messages[0]['rejected_submissions'], 1)
        self.assertEqual(messages[0]['status'], 'no frame observed in retained capture')
        self.assertFalse(messages[1]['unique_origin'])

    def test_decode_descendants_keep_multiple_blocks_and_node_local_ids(self):
        events = [event('frame_send', 1, frame_hash='f'),
                  event('frame_receive', 2, B, frame_hash='f', receive_id=1),
                  event('message_decode', 3, B, span=7, receive_id=1),
                  event('message_decode_result', 4, B, span=7, receive_id=1, accepted=0),
                  event('message_decode_result', 5, A, span=7, receive_id=1, accepted=1)]
        spans = [dict(node=B, id=7, parent=None, name='network.codec.decode', block=None),
                 dict(node=B, id=8, parent=7, name='block.read_cfg', block='a'),
                 dict(node=B, id=9, parent=7, name='block.read_cfg', block='b')]
        transfers, _, _ = build_lineage(events, spans, {'a':11, 'b':22}, 0)
        self.assertEqual(transfers[0]['decode_scope_blocks'], [11, 22])
        self.assertEqual(transfers[0]['source_blocks'], [])
        self.assertFalse(transfers[0]['decode_result'])

    def test_duplicate_receiver_ordinal_does_not_join_distinct_frames(self):
        events = []
        for i in [1, 2]:
            events += [event('frame_send', i*10, frame_hash=str(i)),
                       event('frame_receive', i*10+1, B, frame_hash=str(i), receive_id=1)]
        events += [event('message_decode', 30, B, block='a', receive_id=1),
                   event('message_decode_result', 31, B, receive_id=1, accepted=1)]
        transfers, rows, _ = build_lineage(events, [], {'a':11}, 0)
        self.assertEqual([t['blocks'] for t in transfers], [[], []])
        self.assertTrue(all(t['decode_result'] is None for t in transfers))
        self.assertEqual(len(rows), len(events))

    def test_focused_page_includes_linked_shared_network_scope_without_relabeling(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'; fixture(path)
            data = build([path]); source = data['spans'][0]
            shared = dict(source, id=9001, parent=None, block=None, attempt=None,
                          name='network.encrypted.send_many', start=0, end=110_000)
            data['spans'].append(shared)
            data['network_events'] = [dict(node=A, span=9001, stage='frame_send', ts=2,
                message_id=1, blocks=[source['block']])]
            out = Path(directory)/'report'; write_package(data, out)
            view = embedded(out/f"block-{source['block']}.html")
            included = next(s for s in view['spans'] if s['id'] == 9001)
            self.assertIsNone(included['block'])
            self.assertIn('may include other messages', included['context_reason'])
            self.assertNotIn('context_reason', shared)

    def test_strict_cutoff_and_bounded_package_keep_all_lineage_events(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'; fixture(path)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            start = 1_000_000_000
            stages = [('message_origin', 10, dict(message_id=1)),
                      ('frame_send', 20, dict(message_id=1, frame_hash='1'*24)),
                      ('frame_receive', 30, dict(receive_id=1, frame_hash='1'*24)),
                      ('message_decode', 40, dict(receive_id=1)),
                      ('message_decode_result', 41, dict(receive_id=1, accepted=1))]
            records[-1:-1] = [dict(type='event', id=1, ts=start+offset, fields=dict(stage=stage, **fields)) for stage, offset, fields in stages]
            path.write_text('\n'.join(json.dumps(e) for e in records))
            data = build([path], window={'backpressure':dict(ts=start+40, node=A)})
            self.assertEqual([e['stage'] for e in data['network_events']], ['message_origin', 'frame_send', 'frame_receive'])
            original = copy.deepcopy(data)
            out = Path(directory)/'report'
            manifest = write_package(data, out, chunk_intervals=2)
            self.assertEqual(data, original)
            self.assertEqual(manifest['counts']['network_events'], 3)
            self.assertEqual(sum(c['network_events'] for c in manifest['chunks']), 3)
            full_events = [e for e in trace_events(data) if e.get('cat') == 'network' and e['ph'] == 'i']
            chunk_events = [e for c in manifest['chunks'] for e in json.loads((out/c['file']).read_text())['traceEvents'] if e.get('cat') == 'network' and e['ph'] == 'i']
            self.assertEqual(sorted(e['name'] for e in full_events), sorted(e['name'] for e in chunk_events))
            self.assertEqual(json.loads((out/'network-lineage.json').read_text())['network_events'], data['network_events'])
            self.assertIn('network-lineage.json', (out/'index.html').read_text())

    def test_submission_envelope_and_post_pop_observation_bounds(self):
        for outcome, expected_lower in [(20, 10/1e6), (40, 0)]:
            events = [event('message_inbound_queue_start', 10, B, receive_id=1, queue_id=7),
                      event('message_inbound_queue', outcome, B, receive_id=1, queue_id=7, accepted=1),
                      event('message_dequeued', 30, B, receive_id=1)]
            _, rows, _ = build_lineage(events, [], {}, 0)
            queue = rows[0]['queue']
            self.assertAlmostEqual(queue['submission_ms'], (outcome-10)/1e6)
            self.assertEqual(queue['residence_lower_ms'], 0)
            self.assertAlmostEqual(queue['residence_upper_ms'], 20/1e6)
            self.assertAlmostEqual(queue['insertion_to_observation_lower_ms'], expected_lower)
            self.assertEqual(queue['residence_status'], 'bounded')

    def test_queue_fanout_rejection_and_incomplete_endpoints_do_not_guess(self):
        events = [event('message_peer_queue_start', 10, message_id=1, queue_id=1),
                  event('message_peer_queue_start', 11, message_id=1, queue_id=2),
                  event('message_peer_queue', 12, message_id=1, queue_id=2, accepted=0),
                  event('message_peer_queue', 13, message_id=1, queue_id=1, accepted=1),
                  event('message_decoded_queue_start', 14, B, receive_id=1, queue_id=1),
                  event('message_decoded_queue', 15, B, receive_id=1, queue_id=1, accepted=1),
                  event('message_inbound_queue_start', 16, B, receive_id=2, queue_id=2),
                  event('message_delivered', 20, B, receive_id=1)]
        _, rows, _ = build_lineage(events, [], {}, 0)
        self.assertAlmostEqual(rows[0]['queue']['submission_ms'], 3/1e6)
        self.assertEqual(rows[0]['queue']['residence_status'], 'unknown')
        self.assertEqual(rows[1]['queue']['residence_status'], 'not admitted')
        self.assertEqual(rows[4]['queue']['residence_status'], 'bounded')
        self.assertEqual(rows[6]['queue']['status'], 'incomplete or ambiguous submission')
        for added in [event('message_decoded_queue', 16, B, receive_id=1, queue_id=1, accepted=1),
                      event('message_delivered', 21, B, receive_id=1),
                      event('message_decoded_queue_start', 17, B, receive_id=1, queue_id=3)]:
            _, changed, _ = build_lineage(events+[added], [], {}, 0)
            self.assertEqual(changed[4]['queue']['residence_status'], 'unknown')

    def test_queue_mismatched_identity_and_reversed_start_stay_unknown(self):
        for identity, outcome in [(2, 20), (1, 5)]:
            _, rows, _ = build_lineage([
                event('message_inbound_queue_start', 10, B, receive_id=1, queue_id=1),
                event('message_inbound_queue', outcome, B, receive_id=identity, queue_id=1, accepted=1),
                event('message_dequeued', 30, B, receive_id=1)], [], {}, 0)
            self.assertEqual(rows[0]['queue']['residence_status'], 'unknown')
            self.assertNotIn('submission_ms', rows[0]['queue'])

    def test_queue_missing_start_or_consumer_and_early_consumer_are_unknown(self):
        start = event('message_decoded_queue_start', 10, B, receive_id=1, queue_id=1)
        outcome = event('message_decoded_queue', 20, B, receive_id=1, queue_id=1, accepted=1)
        for events in [[outcome], [start, outcome],
                       [start, outcome, event('message_delivered', 5, B, receive_id=1)]]:
            _, rows, _ = build_lineage(events, [], {}, 0)
            self.assertEqual(rows[0]['queue']['residence_status'], 'unknown')
            self.assertNotIn('residence_upper_ms', rows[0]['queue'])

    def test_queue_outcome_at_cutoff_cannot_complete_pre_cutoff_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'; fixture(path)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            start = 1_000_000_000
            records[-1:-1] = [dict(type='event', id=1, ts=start+offset,
                fields=dict(stage=stage, receive_id=1, queue_id=1, **fields))
                for stage, offset, fields in [
                    ('message_inbound_queue_start', 10, {}),
                    ('message_inbound_queue', 20, {'accepted':1}),
                    ('message_dequeued', 21, {})]]
            path.write_text('\n'.join(json.dumps(e) for e in records))
            data = build([path], window={'backpressure':dict(ts=start+20, node=A)})
            self.assertEqual(len(data['network_events']), 1)
            self.assertEqual(data['network_events'][0]['queue']['status'], 'incomplete or ambiguous submission')
            out = Path(directory)/'report'; manifest = write_package(data, out, chunk_intervals=2)
            self.assertEqual(manifest['counts']['network_events'], 1)
            self.assertEqual(sum(c['network_events'] for c in manifest['chunks']), 1)
            self.assertNotIn('submission_end', json.loads((out/'network-lineage.json').read_text())['network_events'][0]['queue'])


if __name__ == '__main__': unittest.main()
