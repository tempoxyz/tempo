"""Bounded anonymous scheduler spools and stable external ordering."""
import heapq
import os
import struct
import tempfile

from binary_transport import EVENT

MAGIC = b'SCHEDS02'
WAIT_MAGIC = b'SCHEDS03'
WAIT_FOOTER = struct.Struct('<8s10Q')
FOOTER = struct.Struct('<8s9Q')
FIELDS = ('retained', 'emitted', 'lost', 'invalid', 'overflow', 'io_error', 'received', 'observed_duration_ns', 'probe_misses')
MAX_BYTES = 1024 * 1024 * 1024
CHUNK_RECORDS = 65536
MERGE_FAN_IN = 32


def footer(data):
    if len(data) == WAIT_FOOTER.size:
        magic,*values=WAIT_FOOTER.unpack(data)
        if magic!=WAIT_MAGIC or values.pop()!=1:raise ValueError('unexpected binary scheduler output')
        wait_enabled=True
    elif len(data)==FOOTER.size:
        magic,*values=FOOTER.unpack(data)
        if magic!=MAGIC:raise ValueError('unexpected binary scheduler output')
        wait_enabled=False
    else:raise ValueError('unexpected binary scheduler output')
    result = dict(zip(FIELDS, values))
    if wait_enabled:result['wait_reasons']=1
    if result['retained'] > MAX_BYTES // EVENT.size:
        raise ValueError('unexpected binary scheduler output')
    return result


def integrity(counts, source):
    if counts['probe_misses']:
        raise ValueError('capture tool reported probe misses')
    if counts['io_error']:
        raise ValueError('scheduler spool I/O failed')
    if counts['overflow']:
        raise ValueError('scheduler spool limit exceeded')
    if os.fstat(source.fileno()).st_size != counts['retained'] * EVENT.size:
        raise ValueError('unexpected binary scheduler output')
    if counts['invalid']:
        raise ValueError('unexpected ordinal/event')
    if counts['lost'] or counts['retained'] != counts['emitted'] or counts['received'] != counts['emitted']:
        raise ValueError('capture tool reported event loss')


def rows(source, record=EVENT):
    source.seek(0)
    while data := source.read(record.size * CHUNK_RECORDS):
        if len(data) % record.size:
            raise ValueError('unexpected binary scheduler output')
        yield from record.iter_unpack(data)


def sorted_rows(source, directory, *, record=EVENT, key=lambda row: row[0]):
    """Stable timestamp order with bounded chunks and at most 32 open merge inputs.

    Every run is an unnamed inode on the explicitly supplied capture filesystem.
    Adjacent-run merging preserves original arrival order for timestamp ties.
    """
    levels = []
    owned = set()

    def merge(group):
        output = tempfile.TemporaryFile(dir=directory)
        owned.add(output)
        for row in heapq.merge(*(rows(part, record) for _, part in group), key=key):
            output.write(record.pack(*row))
        output.seek(0)
        for _, part in group:
            part.close()
            owned.remove(part)
        return group[0][0], output

    try:
        source.seek(0)
        sequence = 0
        while data := source.read(record.size * CHUNK_RECORDS):
            if len(data) % record.size:
                raise ValueError('unexpected binary scheduler output')
            chunk = list(record.iter_unpack(data))
            chunk.sort(key=key)
            run = tempfile.TemporaryFile(dir=directory)
            owned.add(run)
            for row in chunk:
                run.write(record.pack(*row))
            run.seek(0)
            item = sequence, run
            sequence += 1
            level = 0
            while True:
                if level == len(levels):
                    levels.append([])
                levels[level].append(item)
                if len(levels[level]) < MERGE_FAN_IN:
                    break
                item = merge(levels[level])
                levels[level] = []
                level += 1
        runs = sorted((item for level in levels for item in level), key=lambda item: item[0])
        while len(runs) > 1:
            runs = [merge(runs[start:start + MERGE_FAN_IN]) for start in range(0, len(runs), MERGE_FAN_IN)]
        if runs:
            yield from rows(runs[0][1], record)
    finally:
        for run in owned:
            run.close()
