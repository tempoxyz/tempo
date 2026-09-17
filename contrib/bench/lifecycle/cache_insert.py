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


def attach_cache_insert_details(rows, events, origin):
    scopes = {(s['node'], s['id']): s for s in rows if s['name'] == 'insert_state'}
    summaries = {}
    for event in events:
        key = (event['node'], event['id'])
        if event['fields'].get('stage') == 'execution_cache_insert_totals' and key in scopes:
            summaries.setdefault(key, []).append(event)
    for key, scope in scopes.items():
        found = summaries.get(key, [])
        scope['details']['cache_insert_summary_count'] = len(found)
        if len(found) == 1:
            event = found[0]
            if (scope['start'] <= (event['ts']-origin)/1e6 <= scope['end']
                    and valid_counts(event['fields'])):
                scope['details'].update({k: event['fields'][k] for k in FIELDS})
