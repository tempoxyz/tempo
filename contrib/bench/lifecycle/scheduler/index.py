"""Bounded JSON ingestion and anonymous disk indexes for exact scheduler rows."""
import json
import gzip
from pathlib import Path
import sqlite3
import tempfile

try:
    from .budget import INDEX_BYTES
except ImportError:
    from budget import INDEX_BYTES

CHUNK = 64 * 1024
MAX_VALUE = 4096


class Reader:
    def __init__(self, source):
        self.source, self.buffer, self.position = source, '', 0
        self.decoder = json.JSONDecoder(object_pairs_hook=self.unique)

    @staticmethod
    def unique(pairs):
        result = {}
        for key,value in pairs:
            if key in result:
                raise ValueError('duplicate scheduler JSON key')
            result[key] = value
        return result

    def fill(self):
        self.buffer = self.buffer[self.position:] + self.source.read(CHUNK)
        self.position = 0

    def peek(self):
        while True:
            while self.position < len(self.buffer) and self.buffer[self.position].isspace():
                self.position += 1
            if self.position < len(self.buffer):
                return self.buffer[self.position]
            self.fill()
            if not self.buffer:
                return ''

    def take(self, token):
        if self.peek() != token:
            raise ValueError('invalid scheduler JSON')
        self.position += 1

    def value(self):
        self.peek()
        while True:
            try:
                value, end = self.decoder.raw_decode(self.buffer, self.position)
                # A token must include its delimiter before accepting a split number.
                if end == len(self.buffer):
                    before = len(self.buffer)-self.position
                    self.fill()
                    if len(self.buffer) > before:
                        continue
                    end = len(self.buffer)
                if end-self.position > MAX_VALUE:
                    raise ValueError('oversized scheduler JSON value')
                self.position = end
                return value
            except json.JSONDecodeError:
                if len(self.buffer)-self.position > MAX_VALUE:
                    raise ValueError('oversized scheduler JSON value') from None
                before = len(self.buffer)-self.position
                self.fill()
                if len(self.buffer) == before:
                    raise ValueError('truncated scheduler JSON') from None


def read_capture(path, sink):
    """Parse the fixed top-level object without materializing either row array."""
    metadata, seen = {}, set()
    opener = gzip.open if Path(path).suffix == '.gz' else open
    with opener(path,'rt') as source:
        reader = Reader(source)
        reader.take('{')
        while reader.peek() != '}':
            key = reader.value()
            if not isinstance(key,str) or key in seen:
                raise ValueError('invalid scheduler JSON key')
            if key not in {'schema','scope','process','clock','cutoff_ns','records','intervals','quality',
                           'registered_window_edges_complete','cutoff_reason','registration','wait_reasons'}:
                raise ValueError('unknown scheduler JSON key')
            seen.add(key)
            reader.take(':')
            if key in ('records','intervals'):
                reader.take('[')
                while reader.peek() != ']':
                    sink(key,reader.value())
                    if reader.peek() == ']':
                        break
                    reader.take(',')
                    if reader.peek() == ']':
                        raise ValueError('invalid scheduler JSON array')
                reader.take(']')
            else:
                metadata[key] = reader.value()
            if reader.peek() == '}':
                break
            reader.take(',')
            if reader.peek() == '}':
                raise ValueError('invalid scheduler JSON object')
        reader.take('}')
        if reader.peek() or not {'records','intervals'} <= seen:
            raise ValueError('invalid scheduler JSON suffix/arrays')
    return metadata


class DiskRows:
    def __init__(self, owner, table):
        self.owner, self.table = owner, table

    def __iter__(self):
        for payload, in self.owner.db.execute(f'SELECT payload FROM {self.table} ORDER BY sequence'):
            yield json.loads(payload)

    def __len__(self):
        return self.owner.counts[self.table]

    def overlap(self, low, high):
        # Per-thread start index preserves source ordering without a SQL sort.
        # max_width narrows each range without excluding any long interval.
        for thread in self.owner.registrations:
            width = self.owner.max_width.get(thread,0)
            for payload, in self.owner.db.execute(
                    'SELECT payload FROM intervals WHERE thread=? AND start>? AND start<? AND end>? ORDER BY start',
                    (thread,low-width,high,low)):
                yield json.loads(payload)

    def threads(self, low, high):
        for thread in self.owner.registrations:
            if self.owner.db.execute(
                    'SELECT 1 FROM intervals WHERE thread=? AND start>? AND start<? AND end>? LIMIT 1',
                    (thread,low-self.owner.max_width.get(thread,0),high,low)).fetchone():
                yield thread

    def registrations(self):
        return dict(self.owner.registrations)

    def wait_totals(self):
        return dict(self.owner.wait_totals)

    def totals(self):
        return dict(self.owner.totals)


class CaptureIndex:
    def __init__(self, directory):
        self.directory = tempfile.TemporaryDirectory(prefix='.scheduler-index-', dir=directory)
        self.db = sqlite3.connect(str(Path(self.directory.name)/'anonymous.sqlite'))
        self.db.execute('PRAGMA page_size=4096')
        self.db.execute(f'PRAGMA max_page_count={INDEX_BYTES//4096}')
        self.db.execute('PRAGMA journal_mode=OFF')
        self.db.execute('PRAGMA synchronous=OFF')
        self.db.execute('PRAGMA cache_size=-8192')
        self.db.execute('PRAGMA temp_store=FILE')
        self.db.execute('CREATE TABLE records(sequence INTEGER PRIMARY KEY, payload TEXT)')
        self.db.execute('CREATE TABLE intervals(sequence INTEGER PRIMARY KEY, thread INTEGER, start INTEGER, end INTEGER, payload TEXT)')
        # Create before inserts: avoid a separate unbounded sort/temp filesystem.
        self.db.execute('CREATE INDEX interval_start ON intervals(thread,start)')
        self.counts = {'records':0,'intervals':0}
        self.registrations, self.totals = {}, {}
        self.max_width = {}
        self.wait_totals = {}

    def add(self, table, row):
        payload = json.dumps(row,separators=(',',':'))
        if table == 'records':
            self.db.execute('INSERT INTO records VALUES(?,?)',(self.counts[table],payload))
            if row['kind'] == 'register':
                if row['thread'] in self.registrations:
                    raise ValueError('ordinal reused')
                self.registrations[row['thread']] = row['ts']
        else:
            width = row['end']-row['start']
            if 'wait_status' in row:
                try:
                    from .wait_reasons import REASONS
                except ImportError:
                    from wait_reasons import REASONS
                name=REASONS[row['wait_reason']]
                self.wait_totals[name]=self.wait_totals.get(name,0)+width
            self.max_width[row['thread']] = max(self.max_width.get(row['thread'],0),width)
            self.totals[row['kind']] = self.totals.get(row['kind'],0)+width
            self.db.execute('INSERT INTO intervals VALUES(?,?,?,?,?)',
                            (self.counts[table],row['thread'],row['start'],row['end'],payload))
        self.counts[table] += 1

    def finish(self, metadata):
        self.db.commit()
        return dict(metadata,records=DiskRows(self,'records'),intervals=DiskRows(self,'intervals'))

    def close(self):
        self.db.close()
        self.directory.cleanup()
