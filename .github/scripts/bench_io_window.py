"""Bounded read-only Tempo/DB-device counters. No argv/env or payload reads are emitted."""
import base64
import datetime
import gzip
import hashlib
import json
import os
import pathlib
import re
import subprocess
import time

PROCESS_FIELDS = ('rchar', 'wchar', 'syscr', 'syscw', 'read_bytes', 'write_bytes',
                  'cancelled_write_bytes')
VM_FIELDS = ('nr_dirty', 'nr_writeback', 'nr_dirtied', 'nr_written', 'pgmajfault',
             'pgpgin', 'pgpgout', 'pswpin', 'pswpout', 'nr_dirty_threshold',
             'nr_dirty_background_threshold')
MEM_FIELDS = ('MemTotal', 'MemAvailable', 'Dirty', 'Writeback', 'Cached', 'SwapTotal', 'SwapFree')
DISK_FIELDS = ('reads_completed', 'reads_merged', 'sectors_read_512', 'read_ms',
               'writes_completed', 'writes_merged', 'sectors_written_512', 'write_ms',
               'ios_in_progress', 'io_ms', 'weighted_io_ms', 'discards_completed',
               'discards_merged', 'sectors_discarded_512', 'discard_ms',
               'flushes_completed', 'flush_ms')
PSI_FIELDS = tuple(f'{kind}_{field}' for kind in ('some', 'full')
                   for field in ('avg10', 'avg60', 'avg300', 'total_us'))


def read(path, bound=65536):
    with pathlib.Path(path).open('rb') as handle:
        value = handle.read(bound + 1)
    if len(value) > bound:
        raise ValueError('Metadata exceeds bound')
    return value.decode('utf-8', errors='strict')


def command(args):
    return subprocess.check_output(args, text=True, timeout=5).strip()


def identity():
    pid = int(command(['systemctl', 'show', 'tempo-node.service', '--property=MainPID', '--value']))
    if pid <= 0:
        raise ValueError('Tempo not running')
    start = int(read(f'/proc/{pid}/stat', 4096).rsplit(')', 1)[1].split()[19])
    return pid, start


def devices_for(pid):
    args = read(f'/proc/{pid}/cmdline').split('\0')
    paths = []
    for index, arg in enumerate(args):
        if arg == '--datadir' and index + 1 < len(args):
            paths.append(args[index + 1])
        elif arg.startswith('--datadir='):
            paths.append(arg.split('=', 1)[1])
    del args
    if len(paths) != 1 or not re.fullmatch(r'/[A-Za-z0-9/_.-]{1,300}', paths[0]):
        raise ValueError('Missing safe datadir')
    mount = json.loads(command(['findmnt', '--json', '--task', str(pid), '--target',
                               paths[0].rstrip('/') + '/db', '--output', 'SOURCE,TARGET,FSTYPE,MAJ:MIN']))['filesystems']
    if len(mount) != 1 or not re.fullmatch(r'\d+:\d+', mount[0]['maj:min']):
        raise ValueError('Unidentified database mount')
    tree = json.loads(command(['lsblk', '--json', '--bytes', '--paths', '--inverse',
                              '--output', 'KNAME,TYPE,MAJ:MIN,SIZE,MODEL',
                              '/dev/block/' + mount[0]['maj:min']]))['blockdevices']
    pending, leaves, visited = list(tree), {}, 0
    while pending:
        item = pending.pop()
        visited += 1
        if visited > 64:
            raise ValueError('Ancestry exceeds bound')
        pending.extend(item.get('children', []))
        name = pathlib.Path(item['kname']).name
        if item['type'] == 'disk' and re.fullmatch(r'nvme\d+n\d+', name):
            leaves[name] = {'name': name, 'major_minor': item['maj:min'],
                            'size_bytes': item['size'], 'model': str(item.get('model') or '').strip()[:100]}
    if not 1 <= len(leaves) <= 8:
        raise ValueError('Expected one to eight NVMe backing devices')
    return mount[0], sorted(leaves.values(), key=lambda item: item['name'])


def selected_numbers(path, fields, errors, label):
    try:
        values = {}
        for line in read(path).splitlines():
            parts = line.replace(':', ' ').split()
            if parts and parts[0] in fields:
                values[parts[0]] = int(parts[1])
        return [values.get(field) for field in fields]
    except (OSError, ValueError, IndexError) as error:
        errors[label] = type(error).__name__
        return [None] * len(fields)


def pressure(path, errors, label):
    try:
        values = {}
        for line in read(path, 4096).splitlines():
            parts = line.split()
            if parts[0] not in ('some', 'full'):
                continue
            for pair in parts[1:]:
                key, value = pair.split('=', 1)
                if key in ('avg10', 'avg60', 'avg300', 'total'):
                    key = 'total_us' if key == 'total' else key
                    values[f'{parts[0]}_{key}'] = int(value) if key == 'total_us' else float(value)
        return [values.get(field) for field in PSI_FIELDS]
    except (OSError, ValueError, IndexError) as error:
        errors[label] = type(error).__name__
        return [None] * len(PSI_FIELDS)


def disk_stats(device, errors):
    try:
        current_number = read(f"/sys/class/block/{device['name']}/dev", 100).strip()
        if current_number != device['major_minor']:
            raise ValueError('Device identity changed')
        fields = [int(value) for value in read(f"/sys/class/block/{device['name']}/stat", 4096).split()]
        if not 11 <= len(fields) <= 32:
            raise ValueError('Unexpected disk statistics layout')
        return (fields + [None] * len(DISK_FIELDS))[:len(DISK_FIELDS)]
    except (OSError, ValueError) as error:
        errors['disk_' + device['name']] = type(error).__name__
        return [None] * len(DISK_FIELDS)


def sample_window():
    original = identity()
    mount, devices = devices_for(original[0])
    if identity() != original:
        raise ValueError('Process changed during discovery')
    result = {'schema_version': 1, 'pid': original[0], 'process_start_ticks': original[1],
              'mount': mount, 'devices': devices, 'page_size_bytes': os.sysconf('SC_PAGE_SIZE'),
              'requested_samples': 25, 'interval_seconds': 5, 'state': 'complete',
              'columns': {'process_io': PROCESS_FIELDS, 'vmstat': VM_FIELDS,
                          'meminfo_kib': MEM_FIELDS, 'disk_stat': DISK_FIELDS,
                          'pressure': PSI_FIELDS}, 'samples': [],
              'notes': ['Raw counters; detect resets before computing deltas.',
                        'Whole backing NVMe includes other partitions/processes; process I/O includes all Tempo files.',
                        'ios_in_progress, nr_* current page counts, meminfo and PSI averages are gauges.',
                        'Disk io_ms is not an exact saturation measure on parallel NVMe; flush_ms is block-layer aggregate, not msync latency.',
                        'No metrics scrape, payload I/O, profiling, writes, argv/env output or runtime changes.']}
    begin = time.monotonic()
    for index in range(25):
        time.sleep(max(0, begin + index * 5 - time.monotonic()))
        row = {'index': index, 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'elapsed_seconds': time.monotonic() - begin, 'errors': {}}
        capture_start = time.monotonic()
        try:
            if identity() != original:
                raise ValueError('Process changed')
            row['process_io'] = selected_numbers(f'/proc/{original[0]}/io', PROCESS_FIELDS, row['errors'], 'process_io')
            row['vmstat'] = selected_numbers('/proc/vmstat', VM_FIELDS, row['errors'], 'vmstat')
            row['meminfo_kib'] = selected_numbers('/proc/meminfo', MEM_FIELDS, row['errors'], 'meminfo')
            row['disk_stat'] = {device['name']: disk_stats(device, row['errors']) for device in devices}
            row['io_pressure'] = pressure('/proc/pressure/io', row['errors'], 'io_pressure')
            row['memory_pressure'] = pressure('/proc/pressure/memory', row['errors'], 'memory_pressure')
            if identity() != original:
                raise ValueError('Process changed during sample')
            row['process_stable'] = True
        except (OSError, ValueError, subprocess.SubprocessError, IndexError) as error:
            row['process_stable'] = False
            row['errors']['identity'] = type(error).__name__
            result['state'] = 'process_changed_or_unavailable'
        row['capture_seconds'] = time.monotonic() - capture_start
        result['samples'].append(row)
        if not row['process_stable']:
            break
    return result


def encode(result):
    raw = json.dumps(result, separators=(',', ':'), allow_nan=False).encode()
    if len(raw) > 128 * 1024:
        raise ValueError('Sample data exceeds bound')
    envelope = {'encoding': 'gzip+base64', 'decoded_size': len(raw),
                'decoded_sha256': hashlib.sha256(raw).hexdigest(),
                'data': base64.b64encode(gzip.compress(raw, mtime=0)).decode()}
    value = json.dumps(envelope, separators=(',', ':'))
    if len(value.encode()) > 18000:
        raise ValueError('SSM output exceeds bound')
    return value


if __name__ == '__main__':
    try:
        print(encode(sample_window()))
    except Exception as error:
        print(json.dumps({'state': 'inspection_failed', 'error_type': type(error).__name__}))
        raise SystemExit(1)
