"""Select complete nonempty blocks from the sender's exact reported block range.

The private sender report is never copied into lifecycle artifacts. Only aggregate
counts and existing anonymous lifecycle block selections are returned.
"""
import json


def load(path):
    if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError('workload_report_unavailable')
    try:
        rows = json.loads(path.read_text())['blocks']
        if not isinstance(rows, list) or len(rows) > 100_000:
            raise ValueError()
        result = {}
        for row in rows:
            height, count = row['number'], row['tx_count']
            if (type(height) is not int or type(count) is not int or
                    not 0 <= height < 2**64 or not 0 <= count < 2**64 or height in result):
                raise ValueError()
            result[height] = count
        return result
    except (ValueError, KeyError, TypeError):
        raise ValueError('workload_report_invalid') from None


def select(eligible, by_block, aliases, wanted):
    candidates = {block['id']: block for block in eligible}
    selected, seen = [], set()
    completed_transactions = 0
    for key, ident in aliases.items():
        if ident not in candidates:
            continue
        heights = {e['fields']['height'] for e in by_block[key]
                   if type(e['fields'].get('height')) is int}
        if not heights.intersection(wanted):
            continue
        if len(heights) != 1:
            raise ValueError('workload_block_identity_ambiguous')
        height = next(iter(heights))
        if height in seen:
            raise ValueError('workload_block_identity_ambiguous')
        seen.add(height)
        expected = wanted[height]
        if not expected:
            continue
        block = candidates[ident]
        counts = {row['transactions'] for row in block['execution_totals']
                  if type(row.get('transactions')) is int}
        if counts != {expected}:
            raise ValueError('workload_transaction_count_mismatch')
        selected.append(block)
        completed_transactions += expected
    selected.sort(key=lambda b: b['start'])
    return selected, {'source':'sender_block_range_nonempty', 'matched_blocks':len(selected),
                      'completed_transactions':completed_transactions}
