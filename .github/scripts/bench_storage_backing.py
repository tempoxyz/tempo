"""Read metadata for the running Tempo database's device ancestry; never print argv/env."""
import datetime
import json
import os
import pathlib
import re
import subprocess


def output(command):
    return subprocess.check_output(command, text=True, timeout=10).strip()


def main():
    pid = int(output(['systemctl', 'show', 'tempo-node.service', '--property=MainPID', '--value']))
    if pid <= 0:
        raise ValueError('Tempo service is not running')
    process = pathlib.Path(f'/proc/{pid}')
    started = (process / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    with (process / 'cmdline').open('rb') as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        raise ValueError('Process command line exceeds inspection bound')
    args = raw.decode(errors='strict').split('\0')
    paths = []
    disable_write_map = False
    sync_mode = None
    for index, arg in enumerate(args):
        if arg == '--db.disable-write-map':
            disable_write_map = True
        elif arg.startswith('--db.disable-write-map='):
            value = arg.split('=', 1)[1]
            if value not in ('true', 'false'):
                raise ValueError('Unexpected database flag value')
            disable_write_map = value == 'true'
        elif arg == '--db.sync-mode' and index + 1 < len(args):
            sync_mode = args[index + 1]
        elif arg.startswith('--db.sync-mode='):
            sync_mode = arg.split('=', 1)[1]
        if arg == '--datadir' and index + 1 < len(args):
            paths.append(args[index + 1])
        elif arg.startswith('--datadir='):
            paths.append(arg.split('=', 1)[1])
    del args, raw
    if sync_mode is not None and not re.fullmatch(r'[a-zA-Z-]{1,32}', sync_mode):
        raise ValueError('Unexpected database synchronization mode')
    if len(paths) != 1 or not re.fullmatch(r'/[A-Za-z0-9/_.-]{1,300}', paths[0]):
        raise ValueError('Could not identify one safe absolute Tempo datadir')
    datadir = paths[0]
    database = datadir.rstrip('/') + '/db'
    mount = json.loads(output(['findmnt', '--json', '--task', str(pid), '--target', database,
                              '--output', 'SOURCE,TARGET,FSTYPE,MAJ:MIN']))['filesystems']
    if len(mount) != 1 or not re.fullmatch(r'\d+:\d+', mount[0]['maj:min']):
        raise ValueError('Database mount is not one identifiable block device')
    number = mount[0]['maj:min']
    tree = json.loads(output(['lsblk', '--json', '--bytes', '--paths', '--inverse',
                             '--output', 'NAME,KNAME,TYPE,MAJ:MIN,PKNAME,SIZE,MODEL',
                             '/dev/block/' + number]))['blockdevices']
    devices = {}
    edges = set()

    def visit(item, consumer=None):
        key = item['maj:min']
        if consumer is not None:
            edges.add((consumer, key))
        name = pathlib.Path(item['kname']).name
        if not re.fullmatch(r'[A-Za-z0-9_.!-]{1,100}', name):
            raise ValueError('Unexpected block device name')
        if key not in devices:
            if len(devices) >= 64:
                raise ValueError('Block ancestry exceeds64devices')
            row = {field: item.get(field) for field in
                   ('name', 'kname', 'type', 'maj:min', 'pkname', 'size', 'model')}
            for field in ('name', 'kname', 'pkname', 'model'):
                if row[field] is not None:
                    row[field] = str(row[field]).strip()[:300]
            sysdir = pathlib.Path('/sys/class/block') / name
            slaves = sysdir / 'slaves'
            row['sysfs_slaves'] = sorted(child.name for child in slaves.iterdir()) if slaves.exists() else []
            for attribute in ('scheduler', 'rotational'):
                attr = sysdir / 'queue' / attribute
                row[attribute] = attr.read_text().strip()[:200] if attr.exists() else None
            raid = sysdir / 'md/level'
            row['raid_level'] = raid.read_text().strip()[:40] if raid.exists() else None
            if (sysdir / 'partition').exists():
                row['partition_parent'] = sysdir.resolve().parent.name
            model = (row['model'] or '').lower()
            row['model_classification'] = ('ebs' if 'elastic block store' in model else
                'local_nvme_instance_store' if 'instance storage' in model else
                'ram_block_device' if name.startswith('ram') else 'unclassified')
            devices[key] = row
        for parent in item.get('children', []):
            visit(parent, key)

    for item in tree:
        visit(item)
    # Read only the service's unified cgroup path and its ancestors, never recurse into siblings.
    cgroup_lines = (process / 'cgroup').read_text().splitlines()
    unified = [line[3:] for line in cgroup_lines if line.startswith('0::')]
    controls = {'unified': len(unified) == 1, 'ancestors': []}
    if unified:
        root = pathlib.Path('/sys/fs/cgroup').resolve()
        current = (root / unified[0].lstrip('/')).resolve()
        if not current.is_relative_to(root):
            raise ValueError('Unexpected cgroup path')
        for _ in range(32):
            row = {'path': '/' + str(current.relative_to(root)).removeprefix('.')}
            for name in ('io.max', 'io.weight'):
                attr = current / name
                if attr.exists():
                    with attr.open() as source:
                        content = source.read(4097)
                    row[name] = content[:4096].strip()
                    row[name + '_truncated'] = len(content) > 4096
                else:
                    row[name] = None
            controls['ancestors'].append(row)
            if current == root:
                break
            current = current.parent
        else:
            controls['ancestor_limit_reached'] = True
    mappings = []
    maps_bytes = 0
    with (process / 'maps').open() as source:
        for line in source:
            maps_bytes += len(line)
            if maps_bytes > 2 * 1024 * 1024:
                raise ValueError('Process mapping metadata exceeds bound')
            fields = line.split(None, 5)
            if len(fields) != 6:
                continue
            pathname = fields[5].strip()
            clean_path = pathname.removesuffix(' (deleted)')
            if pathlib.Path(clean_path).name in ('mdbx.dat', 'data.mdb'):
                if len(mappings) >= 32:
                    raise ValueError('Too many MDBX file mappings')
                mappings.append({'permissions': fields[1], 'pathname': pathname})
    after_pid = int(output(['systemctl', 'show', 'tempo-node.service', '--property=MainPID', '--value']))
    after_started = (process / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    if pid != after_pid or started != after_started:
        raise ValueError('Tempo process changed during inspection; mapping is not stable')
    result = {'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'process_stable': True, 'pid': pid, 'datadir': datadir, 'database_path': database,
              'db_flags': {'disable_write_map': disable_write_map, 'sync_mode_explicit': sync_mode},
              'mdbx_mappings': mappings, 'cgroup_io_controls': controls,
              'mount': mount[0], 'device_ancestry': sorted(devices.values(), key=lambda row: row['maj:min']),
              'consumer_to_backing_edges': sorted(edges),
              'notes': ['Metadata only: no payload I/O, writes, benchmarks or dmsetup table.',
                        'Model classification describes ancestry, not I/O latency or write distribution.',
                        'Device-mapper roles/layout are not inferred from dependency order.']}
    encoded = json.dumps(result, separators=(',', ':'))
    if len(encoded.encode()) > 18000:
        raise ValueError('Sanitized metadata exceeds SSM output bound')
    print(encoded)


try:
    main()
except Exception as error:
    # Do not expose command arguments/outputs in exceptions.
    print(json.dumps({'state': 'inspection_failed', 'error_type': type(error).__name__}))
    raise SystemExit(1)
