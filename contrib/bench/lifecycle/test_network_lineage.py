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


if __name__ == '__main__': unittest.main()
