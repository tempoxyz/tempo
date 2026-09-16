"""Join private message/frame ordinals without guessing from temporal proximity."""
from collections import defaultdict

STAGES = frozenset(('message_origin', 'message_router_queue', 'message_peer_queue',
    'message_inbound_queue', 'message_dequeued', 'message_decode', 'message_decode_result',
    'message_decoded_queue', 'message_delivered', 'frame_authenticated', 'frame_send', 'frame_receive'))


def build_lineage(events, spans, aliases, first):
    origins, frames, receivers = defaultdict(list), defaultdict(list), defaultdict(list)
    records = []
    for event in events:
        fields = event['fields']
        stage = fields.get('stage')
        if stage not in STAGES:
            continue
        row = dict(node=event['node'], stage=stage, ts=(event['ts']-first)/1e6,
                   span=event.get('id'), blocks=[])
        for key in ('message_id', 'receive_id', 'accepted', 'bytes'):
            value = fields.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                row[key] = value
        block = aliases.get(event.get('block'))
        if block is not None:
            row['blocks'] = [block]
        if row.get('message_id'):
            if stage == 'message_origin':
                origins[(row['node'], row['message_id'])].append(row)
        if row.get('receive_id'):
            receivers[(row['node'], row['receive_id'])].append(row)
        if stage in ('frame_send', 'frame_receive') and fields.get('frame_hash'):
            frames[fields['frame_hash']].append(row)
        records.append(row)

    # Only explicit per-message decode scopes may contribute descendant block identities.
    decode_roots = {(e['node'], e['span']): e for e in records if e['stage'] == 'message_decode'}
    lookup = {(s['node'], s['id']): s for s in spans}
    for span in spans:
        if span['name'] != 'block.read_cfg' or span.get('block') not in aliases:
            continue
        key, seen = (span['node'], span['id']), set()
        while key in lookup and key not in seen:
            seen.add(key)
            if key in decode_roots:
                row = decode_roots[key]
                block = aliases[span['block']]
                if block not in row['blocks']:
                    row['blocks'].append(block)
                break
            key = (span['node'], lookup[key].get('parent'))

    origin_blocks = {key: list(value[0]['blocks']) for key, value in origins.items() if len(value) == 1}
    message_events = defaultdict(list)
    for row in records:
        if row.get('message_id'):
            message_events[(row['node'], row['message_id'])].append(row)
    transfers, messages = [], []
    for frame_id, group in enumerate(frames.values(), 1):
        sends = [e for e in group if e['stage'] == 'frame_send']
        receives = [e for e in group if e['stage'] == 'frame_receive']
        source_blocks, decode_scope_blocks = set(), set()
        origin = None
        if len(sends) == 1:
            source = origins.get((sends[0]['node'], sends[0].get('message_id')), [])
            if len(source) == 1:
                origin = source[0]
                source_blocks.update(origin_blocks[(sends[0]['node'], sends[0]['message_id'])])
        receiver_events = []
        if len(receives) == 1 and receives[0].get('receive_id'):
            candidates = receivers.get((receives[0]['node'], receives[0]['receive_id']), [])
            if sum(e['stage'] == 'frame_receive' for e in candidates) == 1:
                receiver_events = candidates
            decode_scope_blocks.update(b for e in receiver_events if e['stage'] == 'message_decode' for b in e['blocks'])
        blocks = sorted(source_blocks | decode_scope_blocks)
        associated = [*group, *receiver_events]
        if origin is not None:
            associated.append(origin)
        for row in associated:
            row['blocks'] = sorted(set(row['blocks']) | set(blocks))
            row.setdefault('frames', [])
            if frame_id not in row['frames']:
                row['frames'].append(frame_id)
        if len(sends) == 1 and len(receives) == 1 and receives[0]['ts'] >= sends[0]['ts']:
            transfers.append(dict(frame=frame_id, **{'from':sends[0]['node'], 'to':receives[0]['node']},
                start=sends[0]['ts'], end=receives[0]['ts'], bytes=sends[0].get('bytes', 0),
                message_id=sends[0].get('message_id') or None, receive_id=receives[0].get('receive_id') or None,
                blocks=blocks, source_blocks=sorted(source_blocks), decode_scope_blocks=sorted(decode_scope_blocks),
                authentication_observed=any(e['stage'] == 'frame_authenticated' for e in receiver_events),
                decode_result=next((bool(e['accepted']) for e in receiver_events if e['stage'] == 'message_decode_result' and 'accepted' in e), None),
                association='causal source/decode scope' if blocks else 'unassociated context'))
    # Source queue outcomes share the source's block set, but no recipient identity.
    for row in records:
        if row.get('message_id'):
            source = origins.get((row['node'], row['message_id']), [])
            if len(source) == 1:
                row['blocks'] = sorted(set(row['blocks']) | set(origin_blocks[(row['node'], row['message_id'])]))
    for (node, message_id), source in origins.items():
        rows = message_events[(node, message_id)]
        messages.append(dict(node=node, message_id=message_id, unique_origin=len(source) == 1,
            blocks=sorted({b for e in source for b in e['blocks']}) if len(source) == 1 else [],
            frame_count=sum(e['stage'] == 'frame_send' for e in rows),
            rejected_submissions=sum(e.get('accepted') == 0 for e in rows),
            status='frame observed' if any(e['stage'] == 'frame_send' for e in rows) else 'no frame observed in retained capture'))
    return transfers, records, messages
