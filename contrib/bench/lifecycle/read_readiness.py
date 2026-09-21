"""Privacy-bounded parsing for Reth's read-readiness lifecycle events."""

READINESS_STAGES = {'read_totals', 'read_samples', 'read_sample', 'read_coverage', 'execution_cache_readiness', 'proof_dispatch_totals'}
U64 = (1 << 64) - 1
READ_FIELDS = {'read_role','read_class','read_calls','read_ns','read_max_ns','read_lt_10us','read_lt_100us','read_lt_1ms','read_lt_10ms','read_ge_10ms','read_samples_retained','read_samples_omitted','read_sample_cap','read_begin_ns','read_end_ns','read_thread','read_execution_mode'}
CACHE_FIELDS = {'cache_checkout_reason','cache_diag_keys_tracked','cache_diag_key_capacity','cache_diag_cap_reached','cache_diag_lock_contention','account_miss_prewarm_inflight','account_miss_prewarm_completed','account_miss_prewarm_never_observed','account_miss_prewarm_unknown_due_cap','account_miss_prewarm_unknown_contention','account_miss_prewarm_failed','storage_miss_prewarm_inflight','storage_miss_prewarm_completed','storage_miss_prewarm_never_observed','storage_miss_prewarm_unknown_due_cap','storage_miss_prewarm_unknown_contention','storage_miss_prewarm_failed','code_miss_prewarm_inflight','code_miss_prewarm_completed','code_miss_prewarm_never_observed','code_miss_prewarm_unknown_due_cap','code_miss_prewarm_unknown_contention','code_miss_prewarm_failed'}
PROOF_FIELDS = {'dispatches','targets','chunks','reason_unsplit','reason_force','reason_account_idle','reason_storage_idle','queue_samples','account_queue_high_water','storage_queue_high_water','account_queue_depth_0','account_queue_depth_1_8','account_queue_depth_9_32','account_queue_depth_33_plus','storage_queue_depth_0','storage_queue_depth_1_8','storage_queue_depth_9_32','storage_queue_depth_33_plus','split_when_queue_nonempty','outstanding_max'}

def _u64(value):
    return type(value) is int and 0 <= value <= U64

def _fields(stage, fields):
    allowed = READ_FIELDS if stage in ('read_totals','read_samples','read_sample','read_coverage') else CACHE_FIELDS if stage == 'execution_cache_readiness' else PROOF_FIELDS
    return {key: value for key, value in fields.items() if key in allowed and _u64(value)}

def build(events, headers, aliases, first, cutoff=None):
    modes = [h.get('read_readiness', 'disabled') for h in headers]
    valid = all(mode in ('v1', 'disabled') for mode in modes)
    mode = modes[0] if modes and valid and len(set(modes)) == 1 else ('mixed' if len(set(modes)) > 1 else 'invalid')
    result = {'mode': mode, 'mode_valid': mode in ('v1','disabled'), 'events': [], 'unattributed': [], 'read_samples_retained': 0, 'read_samples_omitted': 0, 'report_dropped_samples': 0, 'read_sample_cap': 8, 'by_block': {}}
    counts = {}
    for event in events:
        fields = event.get('fields', {}); stage = fields.get('stage')
        if stage not in READINESS_STAGES: continue
        if cutoff is not None and event.get('ts', cutoff) >= cutoff: continue
        clean = _fields(stage, fields)
        if stage == 'read_samples':
            result['read_samples_omitted'] += clean.get('read_samples_omitted', 0)
        if ('read_role' in clean and not 1 <= clean['read_role'] <= 4) or ('read_class' in clean and not 0 <= clean['read_class'] <= 9):
            continue
        if 'read_execution_mode' in clean and clean['read_execution_mode'] not in (1, 2):
            continue
        if stage == 'read_sample':
            begin, end = clean.get('read_begin_ns'), clean.get('read_end_ns')
            if (not _u64(begin) or not _u64(end) or end < begin or end > event.get('ts', -1) or (cutoff is not None and (event.get('ts', cutoff) >= cutoff or end >= cutoff))):
                result['report_dropped_samples'] += 1; continue
        record = {'stage': stage, 'node': event.get('node'), 'id': event.get('id'), 'ts_ns': event.get('ts'), 'fields': clean}
        block = event.get('block')
        if stage == 'read_sample':
            key = (event.get('node'), event.get('id'), clean.get('read_role'))
            if counts.get(key, 0) >= 8:
                result['report_dropped_samples'] += 1; continue
            counts[key] = counts.get(key, 0) + 1
            result['read_samples_retained'] += 1
        if block is None or block not in aliases:
            result['unattributed'].append(record); continue
        record['block'] = aliases[block]
        result['events'].append(record); result['by_block'].setdefault(record['block'], []).append(record)
    return result
