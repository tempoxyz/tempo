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
    def test_proposal_and_body_codec_membership_is_message_local(self):
        spans = [dict(node=A, id=1, parent=None, name='batch', block=None)]
        events = []
        for i, blocks in [(10, ['a', 'b']), (20, ['c'])]:
            spans.append(dict(node=A, id=i, parent=1, name='network.codec.send_ref', block=None))
            events += [event('message_origin', i, span=i, message_id=i),
                       event('frame_send', i+1, frame_hash=str(i), message_id=i),
                       event('frame_receive', i+2, B, frame_hash=str(i), receive_id=i),
                       event('message_decode', i+3, B, span=i, receive_id=i),
                       event('message_decode_result', i+4, B, span=i, receive_id=i, accepted=int(i == 10))]
            spans.append(dict(node=B, id=i, parent=None, name='network.codec.recv', block=None))
            for j, block in enumerate(blocks, 1):
                spans += [dict(node=A, id=i+j, parent=i, name='simplex.proposal.write' if i == 10 else 'block.write', block=block, fields={'block_hash':block}),
                          dict(node=B, id=i+j, parent=i, name='simplex.proposal.read' if i == 10 else 'block.read_cfg', block=block, fields={'block_hash':block})]
        # Unrelated journal/codec work shares a batch ancestor but no per-message codec.
        spans += [dict(node=A, id=90, parent=1, name='simplex.proposal.write', block='d', fields={'block_hash':'d'}),
                  dict(node=B, id=90, parent=None, name='simplex.proposal.read', block='d', fields={'block_hash':'d'})]
        transfers, _, messages = build_lineage(events, spans, dict(a=1, b=2, c=3, d=4), 0)
        self.assertEqual([t['encode_scope_blocks'] for t in transfers], [[1, 2], [3]])
        self.assertEqual([t['decode_scope_blocks'] for t in transfers], [[1, 2], [3]])
        self.assertEqual([t['source_blocks'] for t in transfers], [[], []])
        self.assertEqual([t['decode_result'] for t in transfers], [True, False])
        self.assertEqual([m['encode_membership'] for m in messages], ['observed', 'observed'])

    def test_ambiguous_codec_origins_and_decode_scopes_remain_unknown(self):
        for duplicate_id in [False, True]:
            spans = [dict(node=A, id=1, parent=None, name='network.codec.send_ref', block=None),
                     dict(node=A, id=2, parent=1, name='simplex.proposal.write', block='a', fields={'block_hash':'a'}),
                     dict(node=B, id=1, parent=None, name='network.codec.recv', block=None),
                     dict(node=B, id=2, parent=1, name='simplex.proposal.read', block='a', fields={'block_hash':'a'})]
            events = [event('message_origin', 1, message_id=1),
                      event('message_origin', 2, message_id=1 if duplicate_id else 2),
                      event('frame_send', 3, frame_hash='f', message_id=1),
                      event('frame_receive', 4, B, frame_hash='f', receive_id=1),
                      event('message_decode', 5, B, receive_id=1),
                      event('message_decode', 6, B, receive_id=2)]
            transfers, _, messages = build_lineage(events, spans, {'a': 1}, 0)
            self.assertEqual(transfers[0]['blocks'], [])
            self.assertTrue(all(m['encode_membership'] == 'unknown' for m in messages))
        # No origin or decode marker: nearby codec scopes never supply membership.
        transfers, _, _ = build_lineage(events[2:4], spans, {'a': 1}, 0)
        self.assertEqual(transfers[0]['blocks'], [])

    def test_absent_invalid_origin_and_inherited_identity_do_not_claim_membership(self):
        spans = [dict(node=A, id=1, parent=None, name='network.codec.send_ref', block='a', fields={'block_hash':'a'}),
                 dict(node=A, id=2, parent=1, name='block.write', block='a', fields={})]
        for ordinal in [None, 0, False, 'private', -1]:
            fields = {} if ordinal is None else {'message_id':ordinal}
            _, _, messages = build_lineage([event('message_origin', 1, **fields)], spans, {'a':1}, 0)
            self.assertEqual(messages, [])
        spans += [dict(node=B, id=1, parent=None, name='network.codec.recv', block=None, fields={}),
                  dict(node=B, id=2, parent=1, name='simplex.proposal.read', block='a', fields={}),
                  dict(node=B, id=3, parent=1, name='simplex.proposal.read', block='b', fields={'block_hash':'b'})]
        events = [event('message_origin', 1, message_id=1),
                  event('frame_send', 2, frame_hash='f', message_id=1),
                  event('frame_receive', 3, B, frame_hash='f', receive_id=1),
                  event('message_decode', 4, B, receive_id=1)]
        transfers, _, messages = build_lineage(events, spans, {'a':1,'b':2}, 0)
        self.assertEqual(transfers[0]['encode_scope_blocks'], [])
        self.assertEqual(transfers[0]['encode_membership'], 'unknown')
        self.assertEqual(transfers[0]['decode_scope_blocks'], [2])
        self.assertEqual(transfers[0]['decode_membership'], 'observed')
        self.assertEqual(messages[0]['encode_membership'], 'unknown')

    def test_real_report_uses_own_codec_field_and_prunes_cutoff_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'; fixture(path)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            start = 1_000_000_000
            extra = [dict(type='start', id=201, ts=start+110, thread=1,
                          name='network.codec.recv', category='lifecycle', parent=1, fields={}),
                     dict(type='start', id=202, ts=start+120, thread=1,
                          name='simplex.proposal.read', category='lifecycle', parent=201, fields={}),
                     dict(type='fields', id=202, ts=start+150, fields={'block_hash':f'{2:024x}'}),
                     dict(type='end', id=202, ts=start+160),
                     dict(type='end', id=201, ts=start+170)]
            for stage, offset, ident, fields in [
                ('frame_send', 100, 0, dict(frame_hash='a'*24)),
                ('frame_receive', 105, 0, dict(frame_hash='a'*24, receive_id=1)),
                ('message_decode', 115, 201, dict(receive_id=1)),
                ('message_decode_result', 165, 201, dict(receive_id=1, accepted=0)),
            ]:
                extra.append(dict(type='event', id=ident, ts=start+offset, fields=dict(stage=stage, **fields)))
            records[-1:-1] = extra
            path.write_text('\n'.join(map(json.dumps, records)))
            data = build([path], warmup=0)
            self.assertEqual(data['transfers'][0]['decode_scope_blocks'], [2])
            self.assertFalse(data['transfers'][0]['decode_result'])
            out = Path(directory)/'report'; write_package(data, out)
            exported = json.loads((out/'network-lineage.json').read_text())
            self.assertEqual(exported['transfers'][0]['decode_scope_blocks'], [2])
            self.assertTrue(any(e.get('args',{}).get('decode_scope_blocks') == [2] for e in trace_events(data)))
            pruned = build([path], warmup=0, window={'backpressure':dict(ts=start+150,node=A)})
            self.assertEqual(pruned['transfers'][0]['decode_scope_blocks'], [])
            self.assertIsNone(pruned['transfers'][0]['decode_result'])

    def test_opaque_response_redelivery_uses_exact_ordinal_and_own_fields(self):
        events, spans = [], []
        for ordinal, block in [(11, 'a'), (22, 'b')]:
            events += [event('frame_send', ordinal, frame_hash=str(ordinal)),
                       event('frame_receive', ordinal+1, B, frame_hash=str(ordinal), receive_id=ordinal),
                       event('message_decode', ordinal+2, B, span=ordinal, receive_id=ordinal),
                       event('message_decode_result', ordinal+3, B, span=ordinal, receive_id=ordinal, accepted=1)]
            spans.append(dict(node=B,id=ordinal,parent=None,name='network.codec.recv',fields={}))
            for retry in [100,200]:
                ident = ordinal+retry
                spans += [dict(node=B,id=ident,parent=None,name='resolver.response.context',fields={'receive_id':ordinal}),
                          dict(node=B,id=ident+1,parent=ident,name='marshal.resolver.deliver',fields={}),
                          dict(node=B,id=ident+2,parent=ident+1,name='block.read_cfg',fields={'block_hash':block}),
                          dict(node=B,id=ident+3,parent=ident+1,name='simplex.proposal.read',block='other',fields={})]
        transfers, _, _ = build_lineage(events, spans, dict(a=1,b=2,other=3), 0)
        self.assertEqual([t['delivery_scope_blocks'] for t in transfers], [[1],[2]])
        self.assertEqual([t['decode_scope_blocks'] for t in transfers], [[],[]])
        self.assertEqual([t['decode_result'] for t in transfers], [True,True])
        self.assertTrue(all(t['delivery_membership']=='observed' for t in transfers))
        events += [event('frame_send', 40, frame_hash='duplicate'),
                   event('frame_receive',41,B,frame_hash='duplicate',receive_id=11)]
        transfers, _, _ = build_lineage(events, spans, dict(a=1,b=2,other=3), 0)
        self.assertEqual([t['delivery_scope_blocks'] for t in transfers], [[],[2],[]])

    def test_response_context_export_and_cutoff_do_not_infer_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'; fixture(path)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            start = 1_000_000_000
            extra = [dict(type='start',id=201,ts=start+110,thread=1,name='resolver.response.context',category='lifecycle',parent=1,fields={}),
                     dict(type='start',id=202,ts=start+120,thread=1,name='block.read_cfg',category='lifecycle',parent=201,fields={}),
                     dict(type='event',id=202,ts=start+140,fields=dict(stage='decode_done',block_hash=f'{2:024x}')),
                     dict(type='fields',id=201,ts=start+150,fields={'receive_id':11}),
                     dict(type='end',id=202,ts=start+160),dict(type='end',id=201,ts=start+170),
                     dict(type='event',id=0,ts=start+100,fields=dict(stage='frame_send',frame_hash='a'*24)),
                     dict(type='event',id=0,ts=start+105,fields=dict(stage='frame_receive',frame_hash='a'*24,receive_id=11))]
            records[-1:-1] = extra
            path.write_text('\n'.join(map(json.dumps,records)))
            data = build([path],warmup=0)
            transfer = data['transfers'][0]
            self.assertEqual(transfer['delivery_scope_blocks'],[2])
            self.assertIsNone(transfer['decode_result'])
            self.assertEqual(next(s for s in data['spans'] if s['id']==201)['timing_semantics'],'response_context_lifetime_not_service')
            self.assertTrue(any(e.get('args',{}).get('delivery_scope_blocks')==[2] for e in trace_events(data)))
            out = Path(directory)/'report'; write_package(data,out)
            self.assertEqual(json.loads((out/'network-lineage.json').read_text())['transfers'][0]['delivery_scope_blocks'],[2])
            pruned = build([path],warmup=0,window={'backpressure':dict(ts=start+150,node=A)})
            self.assertEqual(pruned['transfers'][0]['delivery_scope_blocks'],[])
            self.assertEqual(pruned['transfers'][0]['delivery_membership'],'unknown')

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
        spans = []
        for i, block in [(1, 'a'), (2, 'b')]:
            spans += [dict(node=B, id=i+10, parent=None, name='network.codec.recv', block=None),
                      dict(node=B, id=i+20, parent=i+10, name='block.read_cfg', block=block, fields={'block_hash':block})]
        transfers, rows, _ = build_lineage(events, spans, {'a':11, 'b':22}, 0)
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
                 dict(node=B, id=8, parent=7, name='block.read_cfg', block='a', fields={'block_hash':'a'}),
                 dict(node=B, id=9, parent=7, name='block.read_cfg', block='b', fields={'block_hash':'b'})]
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
