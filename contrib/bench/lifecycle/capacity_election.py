"""Elect from a complete invocation-bound capacity receipt set; no runner actions."""
import argparse
import json
import re
import sys

MAX_BYTES = 65536
MAX_INTEGER = (1 << 53) - 1
MIB = 1 << 20
REQUIRED_MIB = 65536
SETUP_FAILURE_POLICY = 'setup_failure_v2'
# Exact vocabulary of capacity_preflight.py at f360; this module never probes paths.
ROLES = ('root', 'workspace', 'runner_temp', 'optional_scratch')
ROW_FIELDS = {'role', 'exists', 'filesystem', 'total_bytes', 'free_bytes',
              'read_only', 'writable', 'write_tested', 'status'}
STATUSES = {'unset', 'invalid_path', 'redirected', 'not_directory',
            'changed_directory', 'read_only', 'access_denied', 'writable',
            'write_failed', 'cleanup_failed', 'missing', 'unavailable'}


class InvalidReceipt(ValueError):
    pass


def require(condition):
    if not condition:
        raise InvalidReceipt()


def integer(value, minimum=0, maximum=MAX_INTEGER):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def keys(value, expected):
    require(type(value) is dict and set(value) == expected)


def binding(workflow_sha, run_id, run_attempt):
    require(type(workflow_sha) is str and re.fullmatch('[0-9a-f]{40}', workflow_sha))
    integer(run_id, 1)
    integer(run_attempt, 1)
    return workflow_sha, run_id, run_attempt


def capacity(report):
    keys(report, {'schema', 'locations'})
    require(integer(report['schema']) == 1)
    rows = report['locations']
    require(type(rows) is list and len(rows) == len(ROLES))
    seen_filesystems = set()
    for role, row in zip(ROLES, rows):
        keys(row, ROW_FIELDS)
        require(row['role'] == role)
        require(type(row['exists']) is bool and type(row['write_tested']) is bool)
        require(type(row['status']) is str and row['status'] in STATUSES)
        for name in ('read_only', 'writable'):
            require(row[name] is None or type(row[name]) is bool)
        measured = row['filesystem'] is not None
        if measured:
            fs = integer(row['filesystem'], 1, len(ROLES))
            if fs not in seen_filesystems:
                require(fs == len(seen_filesystems) + 1)
                seen_filesystems.add(fs)
            total = integer(row['total_bytes'])
            integer(row['free_bytes'], 0, total)
            require(row['exists'] and type(row['read_only']) is bool)
        else:
            require(all(row[name] is None for name in
                        ('total_bytes', 'free_bytes', 'read_only', 'writable')))
            require(not row['write_tested'])
        status = row['status']
        if status in ('unset', 'invalid_path'):
            require(not measured and not row['exists'])
        elif status in ('redirected', 'not_directory', 'changed_directory'):
            require(not measured and row['exists'])
        elif status == 'missing':
            require(not measured)
        elif status == 'unavailable':
            # OSError may occur after lstat or after a partial measured probe.
            require(not row['write_tested'] and row['writable'] is None)
        else:
            require(measured)
            if status == 'read_only':
                require(row['read_only'] and row['writable'] is False and not row['write_tested'])
            elif status == 'access_denied':
                require(not row['read_only'] and row['writable'] is False and not row['write_tested'])
            elif status == 'writable':
                require(not row['read_only'] and row['writable'] is True and row['write_tested'])
            elif status == 'write_failed':
                require(not row['read_only'] and row['writable'] in (False, None) and row['write_tested'])
            elif status == 'cleanup_failed':
                require(not row['read_only'] and row['writable'] is None and row['write_tested'])
        # Probe reports this as a failure even if unrelated to workspace eligibility.
        require(status != 'cleanup_failed')
    return rows[0], rows[1]


def elect(receipts, *, workflow_sha, run_id, run_attempt, slots=2, setup_failed_slots=None, prebuilt_plan=None):
    expected = binding(workflow_sha, run_id, run_attempt)
    proof = None
    if prebuilt_plan is not None:
        from prebuilt import budget
        require(type(prebuilt_plan) is str)
        proof = budget(prebuilt_plan.encode('utf-8'))
    required_bytes = REQUIRED_MIB * MIB if proof is None else proof['required_bytes']
    integer(slots, 2, 5)
    if proof is not None: require(slots == 5 and setup_failed_slots is not None)
    failures = [] if setup_failed_slots is None else setup_failed_slots
    require(type(failures) is list)
    if setup_failed_slots is not None:
        require(slots in (4, 5))
    require(all(integer(slot, 1, slots) for slot in failures))
    require(len(failures) == len(set(failures)) < slots)
    require(type(receipts) is list and len(receipts) + len(failures) == slots)
    seen_slots = set(failures)
    eligible = []
    for receipt in receipts:
        keys(receipt, {'schema', 'workflow_sha', 'run_id', 'run_attempt', 'slot', 'capacity'} | ({'prebuilt'} if proof is not None else set()))
        if proof is not None:
            require(json.dumps(receipt['prebuilt'],sort_keys=True)==json.dumps(proof,sort_keys=True))
        require(integer(receipt['schema']) == 1)
        require(binding(receipt['workflow_sha'], receipt['run_id'], receipt['run_attempt']) == expected)
        slot = integer(receipt['slot'], 1, slots)
        require(slot not in seen_slots)
        seen_slots.add(slot)
        root, workspace = capacity(receipt['capacity'])
        enough = all(row['free_bytes'] is not None and
                     row['free_bytes'] >= required_bytes for row in (root, workspace))
        root_ready = root['read_only'] is False and root['status'] in ('writable', 'access_denied')
        if enough and root_ready and workspace['status'] == 'writable':
            eligible.append((min(root['free_bytes'], workspace['free_bytes']), -slot, root, workspace))
    require(seen_slots == set(range(1, slots + 1)))
    if not eligible:
        return {'schema': 1, 'status': 2, 'selected_slot': 0,
                'root_free_mib': 0, 'workspace_free_mib': 0, 'minimum_free_mib': 0}
    score, negative_slot, root, workspace = max(eligible, key=lambda item: item[:2])
    return {'schema': 1, 'status': 0, 'selected_slot': -negative_slot,
            'root_free_mib': root['free_bytes'] // MIB,
            'workspace_free_mib': workspace['free_bytes'] // MIB,
            'minimum_free_mib': score // MIB}


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def parse(data):
    require(len(data) <= MAX_BYTES)
    def invalid_constant(_):
        raise InvalidReceipt()
    return json.loads(data, object_pairs_hook=object_pairs, parse_constant=invalid_constant)


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise InvalidReceipt()


def main(argv=None, stdin=None):
    try:
        parser = Arguments(add_help=False)
        parser.add_argument('--workflow-sha', required=True)
        parser.add_argument('--run-id', required=True)
        parser.add_argument('--run-attempt', required=True)
        parser.add_argument('--slots', choices=('2', '3', '4', '5'), default='2')
        parser.add_argument('--policy', choices=('strict_v1', SETUP_FAILURE_POLICY), default='strict_v1')
        parser.add_argument('--binary-mode', choices=('build_v1','prebuilt_v1'), default='build_v1')
        parser.add_argument('paths', nargs='*')
        args = parser.parse_args(argv)
        require(re.fullmatch('[1-9][0-9]{0,15}', args.run_id) is not None)
        require(re.fullmatch('[1-9][0-9]{0,15}', args.run_attempt) is not None)
        if args.paths:
            require(args.policy == 'strict_v1')
            require(len(args.paths) == int(args.slots))
            inputs = []
            remaining = MAX_BYTES
            for path in args.paths:
                with open(path, 'rb') as source:
                    data = source.read(remaining + 1)
                require(len(data) <= remaining)
                remaining -= len(data)
                inputs.append(parse(data))
        else:
            source = sys.stdin.buffer if stdin is None else stdin
            inputs = parse(source.read(MAX_BYTES + 1))
        failures = None
        prebuilt_plan = None
        if args.binary_mode == 'prebuilt_v1':
            require(not args.paths and args.policy == SETUP_FAILURE_POLICY)
            keys(inputs, {'schema','receipts','setup_failed_slots','prebuilt_plan'})
            prebuilt_plan = inputs.pop('prebuilt_plan')
        if args.policy == SETUP_FAILURE_POLICY:
            keys(inputs, {'schema', 'receipts', 'setup_failed_slots'})
            require(integer(inputs['schema']) == 2)
            failures = inputs['setup_failed_slots']
            inputs = inputs['receipts']
        result = elect(inputs, workflow_sha=args.workflow_sha,
                       run_id=int(args.run_id), run_attempt=int(args.run_attempt),
                       slots=int(args.slots), setup_failed_slots=failures, prebuilt_plan=prebuilt_plan)
        print(json.dumps(result, separators=(',', ':')))
        return 0 if result['status'] == 0 else 3
    except (InvalidReceipt, ValueError, TypeError, KeyError, OSError, RecursionError, OverflowError):
        print('{"schema":1,"status":1,"selected_slot":0,"root_free_mib":0,"workspace_free_mib":0,"minimum_free_mib":0}')
        return 2


if __name__ == '__main__':
    sys.exit(main())
