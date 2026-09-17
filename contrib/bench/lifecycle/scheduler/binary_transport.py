"""Private binary protocol; never writes source events or native identities."""
import struct
from diagnostic import KINDS, decode_records

MAGIC = b'SCHEDB01'
HEADER = struct.Struct('<8s6Q')
EVENT = struct.Struct('<QIHH')
MAX_BYTES = 256 * 1024 * 1024


def decode_binary(data, origin, cutoff_ns, *, expected_threads=None):
    if len(data) < HEADER.size or len(data) > MAX_BYTES + HEADER.size:
        raise ValueError('unexpected binary scheduler output')
    magic, collected, emitted, lost, invalid, overflow, status = HEADER.unpack_from(data)
    if magic != MAGIC or len(data) != HEADER.size + collected * EVENT.size:
        raise ValueError('unexpected binary scheduler output')
    if status:
        raise ValueError('scheduler capture tool exited unsuccessfully')
    if overflow:
        raise ValueError('scheduler memory limit exceeded; diagnostic unavailable')
    if invalid:
        raise ValueError('unexpected ordinal/event')
    if lost or collected != emitted:
        raise ValueError('capture tool reported event loss')
    records = []
    for ts, ordinal, kind, state in EVENT.iter_unpack(memoryview(data)[HEADER.size:]):
        if not 0 < ordinal <= 8192 or kind not in KINDS or (expected_threads is not None and ordinal not in expected_threads):
            raise ValueError('unexpected ordinal/event')
        if (kind != 1 and state) or state > 256:
            raise ValueError('unexpected scheduler state')
        records.append({'ts': ts - origin, 'thread': ordinal, 'kind': KINDS[kind], 'state_bits': state})
    # The shared decoder retains its original BEGIN-count/footer convention.
    return decode_records(records, [], [emitted + 1], expected_threads=expected_threads, cutoff_ns=cutoff_ns)
