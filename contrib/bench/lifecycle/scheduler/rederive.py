"""Explicit schema-2 to schema-3 interpretation; never rewrite source captures."""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from budget import Budget, CappedSink, SOURCE_BYTES, COMPRESSED_SOURCE_BYTES
from index import read_capture

_spec = importlib.util.spec_from_file_location('_scheduler_derivation_report', Path(__file__).with_name('report.py'))
report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(report)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024*1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(row):
    return json.dumps(row, sort_keys=True, separators=(',', ':')).encode() + b'\n'


class Rows:
    def __init__(self):
        self.hashes = {key: hashlib.sha256() for key in ('records','intervals')}
        self.counts = dict.fromkeys(self.hashes, 0)
        self.bytes = 0

    def add(self, table, row):
        encoded = canonical(row)
        self.bytes += len(encoded)
        require(self.bytes <= SOURCE_BYTES, 'source row expansion limit exceeded')
        self.hashes[table].update(encoded)
        self.counts[table] += 1

    def summary(self):
        return {key: dict(count=self.counts[key], sha256=value.hexdigest()) for key,value in self.hashes.items()}


def independent_arrays(path):
    """Separate readback of the completed gzip verifies CRC and ordered arrays."""
    rows = Rows()
    metadata = read_capture(path, rows.add)
    return metadata, rows.summary()


class RetainedState:
    def __init__(self, cutoff):
        self.cutoff = cutoff
        self.states = {}
        self.last = -1
        self.running_wakes = self.unmatched = 0
        self.interval_ends = {}
        self.rows = Rows()

    def add(self, table, row):
        self.rows.add(table, row)
        if table == 'intervals':
            report.validate_interval(row,self.cutoff,self.interval_ends)
            require(row['thread'] in self.states, 'interval lacks retained registration')
            return
        report.validate_record(row,self.cutoff)
        ts, thread, kind = row['ts'], row['thread'], row['kind']
        require(ts >= self.last, 'source records out of timestamp order')
        self.last = ts
        require(kind == 'switch_out' or row['state_bits'] == 0, 'unexpected scheduler state')
        if kind == 'register':
            require(thread not in self.states, 'ordinal reused')
            self.states[thread] = dict(running=True, out=None, wake=False, exited=False)
            return
        require(thread in self.states and not self.states[thread]['exited'], 'registration/exit gap')
        state = self.states[thread]
        if kind == 'switch_out':
            require(state['running'] and state['out'] is None, 'missing switch-in')
            state.update(running=False,out=row['state_bits'],wake=False)
        elif kind == 'switch_in':
            require(state['out'] is not None, 'missing switch-out')
            require(state['out'] in (0,256) or state['wake'], 'missing sleep wake')
            state.update(running=True,out=None,wake=False)
        elif kind == 'wakeup':
            if state['out'] is not None and not state['wake']:
                state['wake'] = True
            elif state['running'] and state['out'] is None:
                self.running_wakes += 1
            else:
                self.unmatched += 1
        elif kind == 'exit':
            require(state['out'] is None, 'unclosed interval at retained exit')
            state.update(running=False,exited=True)


def rederive(source, destination, *, source_sha256, exporter_sha, process, cutoff, reason):
    """Return provenance; destination must be a new directory outside the source."""
    source, destination = Path(source), Path(destination)
    require(re.fullmatch(r'[0-9a-f]{64}',source_sha256) is not None, 'invalid source digest')
    require(re.fullmatch(r'[0-9a-f]{40}',exporter_sha) is not None, 'invalid exporter revision')
    require(type(process) is int and process in (1,2), 'invalid process ordinal')
    require(type(cutoff) is int and 0 < cutoff < 2**64, 'invalid source cutoff')
    require(reason in ('backpressure','load_finished'), 'invalid cutoff reason')
    require(source.name == f'scheduler-{"ab"[process-1]}.json.gz', 'invalid source name')
    require(source.is_file() and not source.is_symlink(), 'redirected source')
    require(source.stat().st_size <= COMPRESSED_SOURCE_BYTES, 'compressed source limit exceeded')
    require(not destination.exists() and not destination.is_symlink(), 'destination already exists')
    require(not destination.resolve().is_relative_to(source.parent.resolve()), 'destination must be outside source directory')
    require(file_hash(source) == source_sha256, 'source identity mismatch')
    state = RetainedState(cutoff)
    original = read_capture(source,state.add)  # Full gzip read checks CRC.
    report.validate(dict(original,records=[],intervals=[]),process,cutoff,reason)
    require(original['schema'] == 2, 'derivation requires original schema 2')
    quality = original['quality']
    require(quality['unclassified_off_cpu_intervals'] == 0 and quality['unclosed_intervals_excluded'] == 0,
            'source has unresolved off-CPU edges')
    require(0 < len(state.states) <= quality['registered_threads'], 'registration count mismatch')
    require(state.running_wakes + state.unmatched == quality['unmatched_wakeups'], 'original wake count mismatch')
    require(state.unmatched == 0, 'unresolved off-CPU wake remains')
    expected_arrays = state.rows.summary()
    updated = dict(original,schema=3,quality=dict(quality,wakeups_while_running=state.running_wakes,unmatched_wakeups=0),registered_window_edges_complete=True)
    report.validate(dict(updated,records=[],intervals=[]),process,cutoff,reason)
    destination.parent.mkdir(parents=True,exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='.scheduler-derive-',dir=destination.parent))
    try:
        captures = temporary/'capture';captures.mkdir()
        output = captures/source.name
        with output.open('xb') as raw:
            with gzip.GzipFile(filename='',mode='wb',fileobj=CappedSink(raw,Budget(COMPRESSED_SOURCE_BYTES)),compresslevel=1,mtime=0) as compressed:
                budget = Budget(SOURCE_BYTES)
                budget.write(compressed,json.dumps(updated,separators=(',',':')).encode()[:-1])
                table = None;first = False;written = Rows()
                def emit(kind,row):
                    nonlocal table,first
                    written.add(kind,row)
                    if kind != table:
                        require(table is None and kind=='records' or table=='records' and kind=='intervals', 'unexpected array ordering')
                        if table is not None:budget.write(compressed,b']')
                        budget.write(compressed,(','+json.dumps(kind)+':[').encode())
                        table,first = kind,True
                    if not first:budget.write(compressed,b',')
                    budget.write(compressed,json.dumps(row,separators=(',',':')).encode())
                    first=False
                second_metadata = read_capture(source,emit)
                require(table == 'intervals', 'missing source intervals')
                budget.write(compressed,b']}')
            raw.flush();os.fsync(raw.fileno())
        require(second_metadata == original and written.summary() == expected_arrays, 'source changed during derivation')
        require(file_hash(source) == source_sha256, 'source identity changed')
        actual_metadata, actual_arrays = independent_arrays(output)
        require(actual_metadata == updated and actual_arrays == expected_arrays, 'derived arrays or metadata changed')
        provenance = dict(schema=1,operation='scheduler_running_wake_reinterpretation',
            source_file=source.name,source_sha256=source_sha256,output_file='capture/'+source.name,
            output_sha256=file_hash(output),exporter_sha=exporter_sha,source_schema=2,output_schema=3,
            process=process,cutoff_ns=cutoff,cutoff_reason=reason,
            original_quality=quality,derived_quality=updated['quality'],arrays=expected_arrays,
            changed_fields=['schema','quality.wakeups_while_running','quality.unmatched_wakeups','registered_window_edges_complete'],
            inherited_evidence='original post-cutoff transport/probe/footer evidence; omitted edges were not recaptured')
        with (temporary/'provenance.json').open('x') as stream:
            json.dump(provenance,stream,indent=2);stream.flush();os.fsync(stream.fileno())
        # A nonempty destination would fail rename, but even an empty existing
        # destination is a collision. renameat2 gives atomic no-replace semantics.
        import ctypes
        libc=ctypes.CDLL(None,use_errno=True)
        libc.renameat2.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
        libc.renameat2.restype=ctypes.c_int
        if libc.renameat2(-100,os.fsencode(temporary),-100,os.fsencode(destination),1):
            error=ctypes.get_errno();raise OSError(error,'derived directory publication failed')
        return provenance
    finally:
        if temporary.exists():shutil.rmtree(temporary)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source',type=Path);parser.add_argument('destination',type=Path)
    parser.add_argument('--source-sha256',required=True);parser.add_argument('--exporter-sha',required=True)
    parser.add_argument('--process',type=int,choices=(1,2),required=True)
    parser.add_argument('--cutoff-ns',type=int,required=True)
    parser.add_argument('--cutoff-reason',choices=('backpressure','load_finished'),required=True)
    args=parser.parse_args()
    repo=Path(__file__).resolve().parents[4]
    actual=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
    require(actual==args.exporter_sha,'exporter checkout revision mismatch')
    subprocess.run(['git','diff','--quiet','HEAD','--','contrib/bench/lifecycle/scheduler'],cwd=repo,check=True)
    result=rederive(args.source,args.destination,source_sha256=args.source_sha256,
        exporter_sha=args.exporter_sha,process=args.process,cutoff=args.cutoff_ns,reason=args.cutoff_reason)
    print(json.dumps(dict(schema=result['output_schema'],arrays=result['arrays'],source_sha256=result['source_sha256'],output_sha256=result['output_sha256'])))


if __name__=='__main__':main()
