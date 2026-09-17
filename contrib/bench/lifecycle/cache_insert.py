"""Exact-span cache insertion attempt counts; absent/invalid is unmeasured."""
FIELDS = tuple('cache_insert_'+name for name in (
    'measured', 'accounts_seen', 'accounts_skipped', 'accounts_attempted', 'accounts_removed',
    'contracts_attempted', 'slots_attempted', 'slots_changed', 'slots_unchanged',
    'outcome', 'counts_saturated'))


def valid_counts(fields):
    if any(type(fields.get(k)) is not int or not 0 <= fields[k] <= 2**53-1 for k in FIELDS):
        return False
    if fields['cache_insert_measured'] != 1 or fields['cache_insert_counts_saturated'] != 0:
        return False
    value = lambda key: fields['cache_insert_'+key]
    outcome = value('outcome')
    return (outcome in (1, 2, 3)
            and value('slots_attempted') == value('slots_changed') + value('slots_unchanged')
            and value('accounts_seen') == value('accounts_skipped') + value('accounts_attempted')
                + value('accounts_removed') + (outcome != 1))


def attach_cache_insert_details(rows, events, origin, modes=None):
    valid = True
    scopes = {(s['node'], s['id']): s for s in rows if s['name'] == 'insert_state'}
    summaries = {}
    for event in events:
        key = (event['node'], event['id'])
        if event['fields'].get('stage') == 'execution_cache_insert_totals':
            if key not in scopes:
                valid = False
            else:
                summaries.setdefault(key, []).append(event)
    for key, scope in scopes.items():
        found = summaries.get(key, [])
        scope['details']['cache_insert_summary_count'] = len(found)
        if modes is not None:
            mode = modes.get(scope['node'], 'disabled')
            if mode == 'disabled' and found:
                valid = False
            if mode == 'counts_v1' and not scope.get('right_censored') and len(found) != 1:
                valid = False
        if len(found) > 1:
            valid = False
        if len(found) == 1:
            event = found[0]
            if (scope['start'] <= (event['ts']-origin)/1e6 <= scope['end']
                    and valid_counts(event['fields'])):
                scope['details'].update({k: event['fields'][k] for k in FIELDS})
            else:
                valid = False
    return valid


def admission(paths, expected, timeout=0):
    """Before load, require both source headers to explicitly declare full/off-or-on."""
    import json
    import time
    from pathlib import Path
    if expected not in ('disabled', 'counts_v1') or len(paths) != 2 or not 0 <= timeout <= 30:
        return False
    deadline = time.monotonic() + timeout
    while True:
        ready = True
        for path in paths:
            try:
                with Path(path).open() as stream:
                    line = stream.readline(4097)
                if not line.endswith('\n'):
                    if len(line) > 4096:
                        return False
                    ready = False
                    continue
                header = json.loads(line)
                if (type(header) is not dict or header.get('type') != 'header'
                        or type(header.get('schema')) is not int or header['schema'] != 1
                        or header.get('clock') != 'shared_monotonic_relative_ns'
                        or header.get('detail') != 'full' or header.get('cache_insert') != expected):
                    return False
            except (FileNotFoundError, json.JSONDecodeError):
                ready = False
        if ready:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(.05)


if __name__ == '__main__':
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected', choices=('disabled', 'counts_v1'), required=True)
    parser.add_argument('--timeout', type=float, default=0)
    parser.add_argument('captures', type=Path, nargs=2)
    args = parser.parse_args()
    if not admission(args.captures, args.expected, args.timeout):
        raise SystemExit('cache_insert_admission_failed')
