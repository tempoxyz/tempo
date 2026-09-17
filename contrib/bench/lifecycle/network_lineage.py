"""Join private message/frame ordinals without guessing from temporal proximity."""
from collections import defaultdict

STAGES = frozenset(('message_origin', 'message_router_queue', 'message_peer_queue',
    'message_router_queue_start', 'message_peer_queue_start', 'message_inbound_queue_start',
    'message_decoded_queue_start', 'message_inbound_queue', 'message_dequeued', 'message_decode', 'message_decode_result',
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
        for key in ('message_id', 'receive_id', 'queue_id', 'accepted', 'bytes'):
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

    # Match only a unique per-message codec scope. Journal/local codec calls and
    # shared batching ancestors never establish message membership.
    lookup = {(s['node'], s['id']): s for s in spans}

    def ancestor(key, names):
        seen = set()
        while key in lookup and key not in seen:
            seen.add(key)
            if lookup[key]['name'] in names:
                return key
            key = (key[0], lookup[key].get('parent'))
        return None

    decode_candidates, encode_candidates = defaultdict(list), defaultdict(list)
    for row in records:
        if row['stage'] == 'message_decode':
            decode_candidates[(row['node'], row['span'])].append(row)
        elif row['stage'] == 'message_origin' and row.get('message_id'):
            root = ancestor((row['node'], row['span']), {'network.codec.send_ref'})
            if root is not None:
                encode_candidates[root].append(row)
    decode_roots = {k: rows[0] for k, rows in decode_candidates.items() if len(rows) == 1}
    encode_roots = {k: rows[0] for k, rows in encode_candidates.items()
                    if len(rows) == 1 and len(origins[(rows[0]['node'], rows[0]['message_id'])]) == 1}
    encoded, decoded, delivered = defaultdict(set), defaultdict(set), defaultdict(set)
    for span in spans:
        # Inherited causal identity is not evidence of encoded/decoded membership.
        own_block = span.get('fields', {}).get('block_hash')
        if own_block not in aliases:
            continue
        key = (span['node'], span['id'])
        block = aliases[own_block]
        if span['name'] in ('block.read_cfg', 'simplex.proposal.read'):
            seen = set()
            while key in lookup and key not in seen:
                seen.add(key)
                if key in decode_candidates:
                    if key in decode_roots:
                        row = decode_roots[key]
                        row['blocks'] = sorted(set(row['blocks']) | {block})
                        decoded[key].add(block)
                    break
                if lookup[key]['name'] == 'resolver.response.context':
                    receive_id = lookup[key].get('fields', {}).get('receive_id')
                    if type(receive_id) is int and receive_id > 0:
                        delivered[(span['node'], receive_id)].add(block)
                    break
                key = (span['node'], lookup[key].get('parent'))
        elif span['name'] in ('block.write', 'simplex.proposal.write'):
            root = ancestor(key, {'network.codec.send_ref'})
            if root in encode_roots:
                row = encode_roots[root]
                encoded[(row['node'], row['message_id'])].add(block)

    origin_blocks = {key: list(value[0]['blocks']) for key, value in origins.items() if len(value) == 1}
    message_events = defaultdict(list)
    for row in records:
        if row.get('message_id'):
            message_events[(row['node'], row['message_id'])].append(row)
    transfers, messages = [], []
    for frame_id, group in enumerate(frames.values(), 1):
        sends = [e for e in group if e['stage'] == 'frame_send']
        receives = [e for e in group if e['stage'] == 'frame_receive']
        source_blocks, encode_scope_blocks, decode_scope_blocks, delivery_scope_blocks = set(), set(), set(), set()
        origin = None
        if len(sends) == 1:
            source = origins.get((sends[0]['node'], sends[0].get('message_id')), [])
            if len(source) == 1:
                origin = source[0]
                source_blocks.update(origin_blocks[(sends[0]['node'], sends[0]['message_id'])])
                encode_scope_blocks.update(encoded[(sends[0]['node'], sends[0]['message_id'])])
        receiver_events = []
        if len(receives) == 1 and receives[0].get('receive_id'):
            candidates = receivers.get((receives[0]['node'], receives[0]['receive_id']), [])
            if sum(e['stage'] == 'frame_receive' for e in candidates) == 1:
                receiver_events = candidates
                delivery_scope_blocks.update(delivered[(receives[0]['node'], receives[0]['receive_id'])])
            decode_scope_blocks.update(b for e in receiver_events if e['stage'] == 'message_decode'
                                       for b in decoded[(e['node'], e['span'])])
        blocks = sorted(source_blocks | encode_scope_blocks | decode_scope_blocks | delivery_scope_blocks)
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
                blocks=blocks, source_blocks=sorted(source_blocks), encode_scope_blocks=sorted(encode_scope_blocks), decode_scope_blocks=sorted(decode_scope_blocks),
                delivery_scope_blocks=sorted(delivery_scope_blocks),
                delivery_membership='observed' if delivery_scope_blocks else 'unknown',
                encode_membership='observed' if encode_scope_blocks else 'unknown',
                decode_membership='observed' if decode_scope_blocks else 'unknown',
                authentication_observed=any(e['stage'] == 'frame_authenticated' for e in receiver_events),
                decode_result=next((bool(e['accepted']) for e in receiver_events if e['stage'] == 'message_decode_result' and 'accepted' in e), None),
                association='causal source or codec membership' if blocks else 'unassociated context'))
    # Source queue outcomes share the source's block set, but no recipient identity.
    for row in records:
        if row.get('message_id'):
            source = origins.get((row['node'], row['message_id']), [])
            if len(source) == 1:
                row['blocks'] = sorted(set(row['blocks']) | set(origin_blocks[(row['node'], row['message_id'])]) | encoded[(row['node'], row['message_id'])])
    for (node, message_id), source in origins.items():
        rows = message_events[(node, message_id)]
        messages.append(dict(node=node, message_id=message_id, unique_origin=len(source) == 1,
            blocks=sorted({b for e in source for b in e['blocks']}) if len(source) == 1 else [],
            encode_scope_blocks=sorted(encoded[(node, message_id)]) if len(source) == 1 else [],
            encode_membership='observed' if encoded[(node, message_id)] and len(source) == 1 else 'unknown',
            frame_count=sum(e['stage'] == 'frame_send' for e in rows),
            rejected_submissions=sum(e.get('accepted') == 0 for e in rows),
            status='frame observed' if any(e['stage'] == 'frame_send' for e in rows) else 'no frame observed in retained capture'))
    annotate_queues(records)
    return transfers, records, messages


QUEUE_CONSUMERS = {'message_router_queue': None, 'message_peer_queue': None,
    'message_inbound_queue': 'message_dequeued', 'message_decoded_queue': 'message_delivered'}


def annotate_queues(records):
    """Bound insertion between before/after call markers, never by nearest timestamp.

    The synchronous call envelope includes scheduling and marker overhead. Residence
    overlaps that envelope when a consumer dequeues before the outcome marker.
    """
    attempts, consumers, receive_attempts = defaultdict(list), defaultdict(list), defaultdict(list)
    for row in records:
        if row.get('queue_id'):
            attempts[(row['node'], row['queue_id'])].append(row)
        if row.get('receive_id'):
            consumers[(row['node'], row['receive_id'], row['stage'])].append(row)
            if row['stage'].endswith('_start') and row['stage'][:-6] in QUEUE_CONSUMERS:
                receive_attempts[(row['node'], row['receive_id'], row['stage'][:-6])].append(row)
    for group in attempts.values():
        starts = [r for r in group if r['stage'].endswith('_start') and r['stage'][:-6] in QUEUE_CONSUMERS]
        outcomes = [r for r in group if r['stage'] in QUEUE_CONSUMERS]
        for row in starts or outcomes:
            row['queue'] = dict(status='incomplete or ambiguous submission', residence_status='unknown')
        if len(starts) != 1 or len(outcomes) != 1 or len(group) != 2:
            continue
        start, end = starts[0], outcomes[0]
        kind = start['stage'][:-6]
        if end['stage'] != kind or any(start.get(k, 0) != end.get(k, 0) for k in ('message_id', 'receive_id')) or end['ts'] < start['ts']:
            continue
        result = start['queue']
        result.update(status='submission observed', submission_end=end['ts'],
                      submission_ms=end['ts']-start['ts'])
        if end.get('accepted') == 0:
            result['residence_status'] = 'not admitted'
            continue
        consumer_stage = QUEUE_CONSUMERS[kind]
        if end.get('accepted') != 1 or consumer_stage is None or not start.get('receive_id'):
            continue
        key = (start['node'], start['receive_id'])
        matching = consumers.get((*key, consumer_stage), [])
        if len(receive_attempts[(*key, kind)]) != 1 or len(matching) != 1:
            continue
        consumed = matching[0]['ts']
        if consumed < start['ts']:
            continue
        result.update(residence_status='bounded', consumer_observed_ts=consumed,
                      residence_lower_ms=0, residence_upper_ms=consumed-start['ts'],
                      insertion_to_observation_lower_ms=max(0, consumed-end['ts']),
                      insertion_to_observation_upper_ms=consumed-start['ts'])
