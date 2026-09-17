"""Lossless, verified phase retention. No filtering or capture-data transformation."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import sys
import tempfile
import unicodedata
import zipfile

FORMAT = 'tempo-lifecycle-phase'
VERSION = 1
PHASE = re.compile(r'(?:(?:full|milestones)-)?(?:baseline|feature)(?:-[1-9][0-9]{0,3})?\Z')
CHUNK = 1024 * 1024
MAX_METADATA = 16 * CHUNK
MAX_FILES = 100_000
MAX_FILE = 16 * 1024**3
MAX_TOTAL = 64 * 1024**3


def phase_name(value):
    if not isinstance(value, str) or not PHASE.fullmatch(value):
        raise ValueError('invalid phase name')
    return value


def relative_name(value):
    if not isinstance(value, str) or not value or '\\' in value or ':' in value or '\x00' in value:
        raise ValueError('invalid relative path')
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in ('', '.', '..') for p in value.split('/')):
        raise ValueError('unsafe relative path')
    for part in value.split('/'):
        device = part.split('.')[0].upper()
        if device in ('CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$') or re.fullmatch(r'(COM|LPT)[0-9¹²³]', device):
            raise ValueError('reserved device path')
    return value


def digest_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def fingerprint(path):
    s = path.lstat()
    return s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink


def inventory(root):
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError('phase must be a real directory')
    files, directories, identities = [], [], {}
    for path in sorted(root.rglob('*')):
        name = relative_name(path.relative_to(root).as_posix())
        info = fingerprint(path)
        identities[name] = info
        if stat.S_ISDIR(info[2]):
            directories.append(name)
        elif stat.S_ISREG(info[2]) and info[-1] == 1:
            files.append(name)
        else:
            raise ValueError('links and special files are forbidden')
    return files, directories, identities


def exclusive_publish(temporary, destination):
    # Hard-link publication is atomic and refuses an existing name; both are on
    # the same filesystem. Never overwrite another phase or a prior attempt.
    os.link(temporary, destination, follow_symlinks=False)
    temporary.unlink()


def publish_directory(temporary, destination):
    """Atomically publish a directory without replacing even an empty collision."""
    if os.name == 'nt':
        os.rename(temporary, destination)  # Windows rename refuses existing destinations.
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith('linux') and hasattr(libc, 'renameat2'):
        rename = libc.renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        args = (-100, os.fsencode(temporary), -100, os.fsencode(destination), 1)  # RENAME_NOREPLACE
    elif sys.platform == 'darwin' and hasattr(libc, 'renamex_np'):
        rename = libc.renamex_np
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        args = (os.fsencode(temporary), os.fsencode(destination), 4)  # RENAME_EXCL
    else:
        raise ValueError('atomic exclusive directory publication unavailable')
    rename.restype = ctypes.c_int
    if rename(*args) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def write_json_exclusive(path, value):
    temporary = path.with_name(path.name + '.partial')
    owned = False
    try:
        with temporary.open('x') as stream:
            owned = True
            json.dump(value, stream, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        exclusive_publish(temporary, path)
    finally:
        if owned:
            temporary.unlink(missing_ok=True)


def read_json(path):
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > MAX_METADATA:
        raise ValueError('invalid manifest file')
    return json.loads(path.read_text())


def validate_contents(contents, expected, max_total=MAX_TOTAL):
    if contents.get('format') != FORMAT or contents.get('version') != VERSION:
        raise ValueError('unsupported archive format')
    if phase_name(contents.get('phase')) != expected:
        raise ValueError('phase mismatch')
    files, directories = contents.get('files'), contents.get('directories')
    if not isinstance(files, list) or not isinstance(directories, list) or len(files) + len(directories) > MAX_FILES:
        raise ValueError('invalid archive entry count')
    names, portable = set(), set()
    total = 0
    for entry in [*files, *({'path': p} for p in directories)]:
        name = relative_name(entry['path'])
        # Avoid aliases/collisions when the artifact is opened on macOS/Windows.
        folded = unicodedata.normalize('NFC', name).casefold()
        if name in names or folded in portable or any(p.endswith((' ', '.')) for p in name.split('/')):
            raise ValueError('duplicate or nonportable path')
        names.add(name)
        portable.add(folded)
    file_names = {entry['path'] for entry in files}
    for name in names:
        if any(parent.as_posix() in file_names for parent in PurePosixPath(name).parents if parent.as_posix() != '.'):
            raise ValueError('file and directory collision')
    for entry in files:
        size = entry.get('size')
        if type(size) is not int or not 0 <= size <= MAX_FILE or not re.fullmatch('[0-9a-f]{64}', entry.get('sha256', '')):
            raise ValueError('invalid file metadata')
        total += size
    if total > max_total or contents.get('total_bytes') != total:
        raise ValueError('archive expansion limit or size mismatch')
    return total


def check_directory_bound(archive):
    """Bound central-directory memory before ZipFile builds its member objects."""
    with archive.open('rb') as stream:
        size = archive.stat().st_size
        offset = max(0, size - 65535 - 22)
        stream.seek(offset)
        tail = stream.read()
        pos = tail.rfind(b'PK\x05\x06')
        if pos < 0 or len(tail) - pos < 22:
            raise ValueError('missing ZIP directory')
        _, disk, start_disk, disk_count, count, directory_size, directory_offset, comment = struct.unpack('<4s4H2LH', tail[pos:pos+22])
        if disk or start_disk or disk_count != count or pos + 22 + comment != len(tail):
            raise ValueError('invalid ZIP directory')
        end_offset = offset + pos
        if count == 65535 or directory_size == 0xffffffff or directory_offset == 0xffffffff:
            stream.seek(end_offset - 20)
            locator = stream.read(20)
            if len(locator) != 20:
                raise ValueError('invalid ZIP64 locator')
            signature, disk, wide_offset, disks = struct.unpack('<4sLQL', locator)
            if signature != b'PK\x06\x07' or disk or disks != 1 or wide_offset > end_offset - 76:
                raise ValueError('invalid ZIP64 locator')
            stream.seek(wide_offset)
            wide = stream.read(56)
            if len(wide) != 56:
                raise ValueError('invalid ZIP64 directory')
            signature, length, _, _, disk, start_disk, disk_count, count, directory_size, directory_offset = struct.unpack('<4sQ2H2L4Q', wide)
            if signature != b'PK\x06\x06' or length != 44 or disk or start_disk or disk_count != count:
                raise ValueError('invalid ZIP64 directory')
            end_offset = wide_offset
        if count > MAX_FILES + 1 or directory_size > 64 * CHUNK or directory_offset + directory_size > end_offset:
            raise ValueError('ZIP directory exceeds bounds')
        # Do not trust the declared count: ZipFile walks the whole directory.
        # Count fixed headers without materializing names/member objects first.
        stream.seek(directory_offset)
        remaining, observed = directory_size, 0
        while remaining:
            header = stream.read(46)
            if len(header) != 46 or header[:4] != b'PK\x01\x02':
                raise ValueError('invalid central-directory member')
            lengths = struct.unpack_from('<3H', header, 28)
            width = 46 + sum(lengths)
            remaining -= width
            observed += 1
            if remaining < 0 or observed > MAX_FILES + 1:
                raise ValueError('ZIP directory member count exceeds bounds')
            stream.seek(sum(lengths), os.SEEK_CUR)
        if observed != count:
            raise ValueError('ZIP directory member count mismatch')


def inspect_archive(archive, receipt, expected, max_total=MAX_TOTAL, destination=None, temporary=False):
    if receipt.get('format') != FORMAT or receipt.get('version') != VERSION or receipt.get('phase') != expected:
        raise ValueError('invalid archive receipt')
    if receipt.get('archive') != expected + '.zip' or archive.name != receipt['archive'] + ('.partial' if temporary else ''):
        raise ValueError('archive name mismatch')
    if (not stat.S_ISREG(archive.lstat().st_mode) or archive.stat().st_size != receipt.get('archive_bytes')
            or archive.stat().st_size > MAX_TOTAL + 128 * CHUNK):
        raise ValueError('archive size mismatch')
    if digest_file(archive) != receipt.get('archive_sha256'):
        raise ValueError('archive digest mismatch')
    check_directory_bound(archive)
    contents = receipt['contents']
    total = validate_contents(contents, expected, max_total)
    manifest_name = expected + '.archive-manifest.json'
    entries = {expected + '/' + e['path']: e for e in contents['files']}
    directory_names = {expected + '/' + d + '/' for d in contents['directories']}
    wanted = set(entries) | directory_names | {manifest_name}
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        if len(infos) > MAX_FILES + 1 or len({i.filename for i in infos}) != len(infos) or {i.filename for i in infos} != wanted:
            raise ValueError('archive members differ from manifest')
        for info in infos:
            mode = info.external_attr >> 16
            if info.flag_bits & 1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise ValueError('unsupported archive member')
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR) or info.is_dir() != (info.filename in directory_names):
                raise ValueError('links and special archive members are forbidden')
        embedded = z.getinfo(manifest_name)
        if embedded.file_size > MAX_METADATA or json.loads(z.read(embedded)) != contents:
            raise ValueError('embedded manifest mismatch')
        if destination is not None:
            if shutil.disk_usage(destination.parent).free < total + 1024**3:
                raise ValueError('insufficient extraction space')
            for name in contents['directories']:
                (destination / name).mkdir(parents=True, exist_ok=True)
        for name, entry in entries.items():
            info = z.getinfo(name)
            if info.file_size != entry['size']:
                raise ValueError('member expansion size mismatch')
            digest, count = hashlib.sha256(), 0
            output = None
            try:
                if destination is not None:
                    target = destination / entry['path']
                    target.parent.mkdir(parents=True, exist_ok=True)
                    output = target.open('xb')
                with z.open(info) as stream:
                    while chunk := stream.read(CHUNK):
                        count += len(chunk)
                        if count > entry['size']:
                            raise ValueError('member expansion exceeds limit')
                        digest.update(chunk)
                        if output is not None:
                            output.write(chunk)
                if count != entry['size'] or digest.hexdigest() != entry['sha256']:
                    raise ValueError('member digest mismatch')
            finally:
                if output is not None:
                    output.close()
    return total


def pack(source, remove_source=False):
    source = Path(source).absolute()
    phase = phase_name(source.name)
    archive = source.with_name(phase + '.zip')
    receipt_path = source.with_name(phase + '.archive.json')
    if archive.exists() or archive.is_symlink() or receipt_path.exists() or receipt_path.is_symlink():
        raise FileExistsError('archive or receipt already exists')
    files, directories, identities = inventory(source)
    validate_contents(dict(format=FORMAT, version=VERSION, phase=phase, directories=directories,
        files=[dict(path=n, size=identities[n][3], sha256='0'*64) for n in files],
        total_bytes=sum(identities[n][3] for n in files)), phase)
    root_identity = fingerprint(source)
    temporary = archive.with_name(archive.name + '.partial')
    owned = False
    try:
        with temporary.open('xb') as stream:
            owned = True
            contents = dict(format=FORMAT, version=VERSION, phase=phase, files=[], directories=directories, total_bytes=0)
            with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=1, allowZip64=True) as z:
                for directory in directories:
                    z.writestr(phase + '/' + directory + '/', b'')
                for name in files:
                    digest, size = hashlib.sha256(), 0
                    with (source / name).open('rb') as original, z.open(phase + '/' + name, 'w', force_zip64=True) as output:
                        while chunk := original.read(CHUNK):
                            digest.update(chunk)
                            size += len(chunk)
                            output.write(chunk)
                    if fingerprint(source / name) != identities[name]:
                        raise ValueError('source changed during compression')
                    contents['files'].append(dict(path=name, size=size, sha256=digest.hexdigest()))
                    contents['total_bytes'] += size
                validate_contents(contents, phase)
                z.writestr(phase + '.archive-manifest.json', json.dumps(contents, separators=(',', ':')))
            stream.flush()
            os.fsync(stream.fileno())
        receipt = dict(format=FORMAT, version=VERSION, phase=phase, archive=archive.name,
                       archive_bytes=temporary.stat().st_size, archive_sha256=digest_file(temporary), contents=contents)
        # Publish only a fully verified archive. Any failure leaves originals.
        inspect_archive(temporary, receipt, phase, temporary=True)
        if inventory(source) != (files, directories, identities) or fingerprint(source) != root_identity:
            raise ValueError('source changed before retention')
        exclusive_publish(temporary, archive)
        write_json_exclusive(receipt_path, receipt)
        directory_fd = os.open(source.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        write_index(source.parent)
        if remove_source:
            shutil.rmtree(source)
        return receipt
    finally:
        if owned:
            temporary.unlink(missing_ok=True)


def unpack(archive, out, expected, max_total=MAX_TOTAL):
    archive, out = Path(archive).absolute(), Path(out).absolute()
    expected = phase_name(expected)
    if archive.name != expected + '.zip':
        raise ValueError('archive phase mismatch')
    out.mkdir(parents=True, exist_ok=True)
    if out.is_symlink() or out.resolve() != out:
        raise ValueError('redirected output directory')
    target = out / expected
    if target.exists() or target.is_symlink():
        raise FileExistsError('phase destination already exists')
    receipt = read_json(archive.with_name(expected + '.archive.json'))
    temporary = Path(tempfile.mkdtemp(prefix='.' + expected + '.extract-', dir=out))
    try:
        inspect_archive(archive, receipt, expected, max_total, temporary)
        # A fresh sibling destination makes all extracted paths private until
        # complete verification; never merge into a previous phase directory.
        if target.exists() or target.is_symlink():
            raise FileExistsError('phase destination appeared during extraction')
        publish_directory(temporary, target)
        return {k: receipt[k] for k in ('format', 'version', 'phase', 'archive', 'archive_sha256', 'archive_bytes')}
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def write_index(root):
    receipts = sorted(root.glob('*.archive.json'))
    links = []
    for path in receipts:
        record = read_json(path)
        phase = phase_name(record['phase'])
        links.append(f'<li><a href="{phase}.zip">{phase}</a> — lossless phase archive</li>')
    (root / 'index.html').write_text('<!doctype html><meta charset="utf-8"><title>Block lifecycle archives</title>'
        '<h1>Block lifecycle archives</h1><p>Each archive preserves every pruned source and offline report file. '
        'Extract a phase ZIP here, then open its index.html. Individual blocks and p50/p90/p99 pages remain offline.</p>'
        '<p>For verified extraction: <code>python3 phase_archive.py unpack-all .</code>. '
        'Extraction refuses existing phase folders. Use a fresh folder for another copy.</p><ul>' + ''.join(links) + '</ul>')
    if Path(__file__).resolve() != (root / 'phase_archive.py').resolve():
        shutil.copyfile(Path(__file__), root / 'phase_archive.py')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    pack_parser = commands.add_parser('pack')
    pack_parser.add_argument('source', type=Path)
    pack_parser.add_argument('--remove-source', action='store_true')
    for name in ('unpack', 'unpack-all'):
        sub = commands.add_parser(name)
        sub.add_argument('source', type=Path)
        sub.add_argument('--out', type=Path)
        sub.add_argument('--max-total-bytes', type=int, default=MAX_TOTAL)
        sub.add_argument('--expect-phases', nargs='+', required=name == 'unpack')
    args = parser.parse_args()
    if args.command == 'pack':
        result = pack(args.source, args.remove_source)
        print(json.dumps({k: result[k] for k in ('format', 'version', 'phase', 'archive_bytes', 'archive_sha256')}))
        return
    archives = [args.source] if args.command == 'unpack' else sorted(args.source.glob('*.zip'))
    phases = [phase_name(p.stem) for p in archives]
    if not phases or len(set(phases)) != len(phases) or (args.expect_phases is not None and sorted(phases) != sorted(args.expect_phases)):
        raise ValueError('archive phase set differs from expected phases')
    total = sum(validate_contents(read_json(path.with_name(phase + '.archive.json'))['contents'], phase)
                for path, phase in zip(archives, phases))
    if total > args.max_total_bytes:
        raise ValueError('combined archive expansion exceeds limit')
    out = args.out or archives[0].parent
    out.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(out).free < total + 1024**3:
        raise ValueError('insufficient combined extraction space')
    results = [unpack(path, args.out or path.parent, phase, args.max_total_bytes) for path, phase in zip(archives, phases)]
    print(json.dumps(dict(format=FORMAT, version=VERSION, extracted=results)))


if __name__ == '__main__':
    main()
