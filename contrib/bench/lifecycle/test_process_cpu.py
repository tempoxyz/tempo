import copy
import json
from pathlib import Path
import tempfile
import unittest

import process_cpu as cpu
import phase_archive
from backpressure import prepare_captures
from report import build, write_report
from test_prewarm import captures


def sample(sequence, start, end, status=0, missed=0):
    row = dict(type='process_cpu', sequence=sequence, read_start_ns=start, read_end_ns=end,
               status=status, missed_deadlines=missed)
    if status == 0:
        row.update(user_cpu_us=sequence*10, system_cpu_us=sequence*3)
    return row


def stream(rows, failures=0):
    observer = cpu.Stream()
    observer.observe(dict(type='header', process_cpu=cpu.MODE, process_cpu_period_ns=cpu.PERIOD_NS))
    for row in rows:
        observer.observe(row)
    observer.observe(dict(type='footer', dropped=0, io_error=False, process_cpu_samples=len(rows),
        process_cpu_unavailable=sum(r['status'] != 0 for r in rows),
        process_cpu_missed_deadlines=sum(r['missed_deadlines'] for r in rows), process_cpu_failures=failures))
    return observer.finish()


def fixture(root, rows, cutoff=None, failures=0):
    paths = captures(root, cutoff)
    for path in paths:
        events = [json.loads(line) for line in path.read_text().splitlines()]
        events[0].update(process_cpu=cpu.MODE, process_cpu_period_ns=cpu.PERIOD_NS)
        events[-1].update(process_cpu_samples=len(rows), process_cpu_unavailable=sum(r['status'] != 0 for r in rows),
            process_cpu_missed_deadlines=sum(r['missed_deadlines'] for r in rows), process_cpu_failures=failures,
            written=events[-1]['written']+len(rows))
        events[-1:-1] = copy.deepcopy(rows)
        path.write_text(''.join(json.dumps(r)+'\n' for r in events))
    return paths


class ProcessCpuTests(unittest.TestCase):
    def test_adjacent_brackets_gaps_and_window_bounds(self):
        rows=[sample(1,1,2),sample(2,10,12),sample(3,20,21,1),sample(4,30,32),sample(5,40,44,missed=2)]
        source=stream(rows)
        data=cpu.inspect([('Validator A',source)],dict(start_ns=0,end_ns=50),expected=cpu.MODE)
        node=data['nodes'][0]
        self.assertEqual([(r['from_sequence'],r['to_sequence']) for r in node['intervals']],[(1,2),(4,5)])
        self.assertEqual([r['elapsed_min_ns'] for r in node['intervals']],[8,8])
        self.assertEqual([r['elapsed_max_ns'] for r in node['intervals']],[11,14])
        self.assertEqual(node['summary']['covered_inner_ns'],16)
        self.assertEqual(node['summary']['user_cpu_us'],20)
        self.assertEqual(len(node['gaps']),3)
        narrowed=cpu.inspect([('Validator A',source)],dict(start_ns=2,end_ns=44))['nodes'][0]
        self.assertEqual(narrowed['intervals'],[])
        self.assertIsNone(narrowed['summary']['user_cpu_us'])
        self.assertEqual(narrowed['summary']['excluded_window_pairs'],1)
        self.assertEqual(narrowed['pruning']['process_cpu_pruned_samples'],1)

    def test_zero_and_one_samples_are_unknown_but_observed_zero_is_zero(self):
        for rows in ([],[sample(1,1,1)]):
            result=cpu.inspect([('Validator A',stream(rows))])['nodes'][0]
            self.assertIsNone(result['summary']['system_cpu_us'])
        rows=[sample(1,1,1),sample(2,1,1)]
        rows[1].update(user_cpu_us=10,system_cpu_us=3)
        result=cpu.inspect([('Validator A',stream(rows))])['nodes'][0]
        self.assertEqual(result['summary']['system_cpu_us'],0)

    def test_closed_schema_numbers_order_counter_and_failure_reject(self):
        base=[sample(1,1,2),sample(2,10,12)]
        mutations=[lambda r:r[0].update(sequence=True),lambda r:r[1].update(sequence=3),
            lambda r:r[1].update(read_start_ns=1),lambda r:r[0].update(read_end_ns=-1),
            lambda r:r[0].update(native_pid=99),lambda r:r[1].update(user_cpu_us=1),
            lambda r:r[0].update(status=1),lambda r:r[0].update(missed_deadlines=2**64),
            lambda r:r[0].update(status=2)]
        for mutate in mutations:
            rows=copy.deepcopy(base);mutate(rows)
            with self.assertRaises(ValueError):stream(rows)
        with self.assertRaises(ValueError):stream(base,failures=1)
        with self.assertRaises(ValueError):cpu.inspect([('Validator A',stream(base))],expected='disabled')
        observer=cpu.Stream();observer.observe(dict(type='header',process_cpu='disabled'))
        with self.assertRaises(ValueError):observer.observe(base[0])

    def test_monotonicity_across_failure_and_cap(self):
        rows=[sample(1,1,2),sample(2,4,5,1),sample(3,8,9)]
        rows[2]['user_cpu_us']=9
        with self.assertRaises(ValueError):stream(rows)
        from unittest.mock import patch
        with patch.object(cpu,'CAP',1):
            with self.assertRaises(ValueError):stream([sample(1,1,2),sample(2,4,5)])

    def test_pruned_and_original_sidecars_equal_strict_end_and_global_cutoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            rows=[sample(1,1,2),sample(2,10,12),sample(3,20,25,1),sample(4,30,40),sample(5,45,46)]
            paths=fixture(root,rows,cutoff=40)
            window=dict(start_ns=0,end_ns=35)
            before=build(paths,warmup=0,window=window,expected_process_cpu=cpu.MODE)['process_cpu']
            clean,clean_window=prepare_captures(paths,root/'pruned',window)
            after=build(clean,warmup=0,window=clean_window,expected_process_cpu=cpu.MODE)['process_cpu']
            self.assertEqual(before,after)
            self.assertEqual(before['cutoff_ns'],35)
            for path in clean:
                records=[json.loads(line) for line in path.read_text().splitlines()]
                self.assertEqual([r['sequence'] for r in records if r['type']=='process_cpu'],[1,2,3])
                self.assertEqual(records[-1]['process_cpu_pruned_samples'],2)
            exact=cpu.inspect([('Validator A',stream(rows))],dict(start_ns=0,end_ns=12))['nodes'][0]
            self.assertEqual(len(exact['samples']),1)

    def test_postcutoff_integrity_cannot_disappear(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=fixture(root,[sample(1,1,2),sample(2,100,101)],cutoff=40,failures=1)
            self.assertTrue(build(paths,expected_process_cpu=cpu.MODE)['bad_capture'])
            with self.assertRaises(ValueError):prepare_captures(paths,root/'out')
            self.assertFalse((root/'out'/'a.jsonl').exists())

    def test_package_and_archive_preserve_cpu_sidecars_and_no_block_attachment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=fixture(root,[sample(1,1,2),sample(2,10,12),sample(3,40,42)])
            out=root/'feature-1'
            result=write_report(paths,out,warmup=0,window=dict(start_ns=0,end_ns=120),prune=True,expected_process_cpu=cpu.MODE)
            self.assertFalse(result['bad_capture'])
            self.assertTrue(all('process_cpu' not in block for block in result['blocks']))
            manifest=json.loads((out/'manifest.json').read_text())
            self.assertEqual(manifest['process_cpu'],dict(data='process-cpu.json',page='process-cpu.html'))
            self.assertIn('process-cpu.html',(out/'index.html').read_text())
            original={p.name:p.read_bytes() for p in (out/'process-cpu.json',out/'process-cpu.html')}
            phase_archive.pack(out,True)
            phase_archive.unpack(root/'feature-1.zip',root,'feature-1')
            for name,value in original.items():self.assertEqual((out/name).read_bytes(),value)
            self.assertEqual(json.loads(original['process-cpu.json']),result['process_cpu'])

    def test_legacy_disabled_creates_no_optional_sidecars(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=captures(root)
            self.assertTrue(build(paths,expected_process_cpu='disabled')['bad_capture'])
            result=write_report(paths,root/'out',warmup=0)
            self.assertEqual(result['process_cpu_mode'],'disabled')
            self.assertFalse((root/'out'/'process-cpu.json').exists())
            self.assertNotIn('process_cpu',json.loads((root/'out'/'manifest.json').read_text()))

    def test_rewrite_tighter_cutoff_then_disabled_removes_exact_owned_sidecars(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=fixture(root,[sample(1,1,2),sample(2,10,12),sample(3,40,42)])
            out=root/'out'
            write_report(paths,out,warmup=0,window=dict(start_ns=0,end_ns=120))
            write_report(paths,out,warmup=0,window=dict(start_ns=0,end_ns=12))
            data=json.loads((out/'process-cpu.json').read_text())
            self.assertTrue(all(len(n['samples'])==1 and n['intervals']==[] for n in data['nodes']))
            unrelated=out/'unrelated.json';unrelated.write_text('preserve')
            # Return the source to the ordinary disabled capture; reuse output.
            paths=captures(root)
            write_report(paths,out,warmup=0)
            self.assertFalse((out/'process-cpu.json').exists())
            self.assertFalse((out/'process-cpu.html').exists())
            self.assertEqual(unrelated.read_text(),'preserve')
            self.assertNotIn('process_cpu',json.loads((out/'manifest.json').read_text()))
            for name in ('process-cpu.json','process-cpu.html'):(out/name).write_text('stale')
            cpu.write_view(dict(mode='invalid'),out)
            self.assertFalse((out/'process-cpu.json').exists())
            self.assertFalse((out/'process-cpu.html').exists())

    def test_footer_pruning_evidence_is_closed_and_checked(self):
        def checked(mutate):
            observer=cpu.Stream()
            observer.observe(dict(type='header',process_cpu=cpu.MODE,process_cpu_period_ns=cpu.PERIOD_NS))
            observer.observe(sample(1,1,2))
            footer=dict(type='footer',dropped=0,io_error=False,process_cpu_samples=2,
                process_cpu_unavailable=1,process_cpu_missed_deadlines=3,process_cpu_failures=0,
                process_cpu_pruned_samples=1,process_cpu_pruned_unavailable=1,
                process_cpu_pruned_missed_deadlines=3)
            mutate(footer);observer.observe(footer)
            return observer.finish()
        self.assertEqual(checked(lambda f:None)['footer']['process_cpu_samples'],2)
        for mutate in (lambda f:f.update(process_cpu_samples=True),
                       lambda f:f.update(process_cpu_pruned_samples=0),
                       lambda f:f.update(process_cpu_pruned_unavailable=2),
                       lambda f:f.pop('process_cpu_pruned_missed_deadlines'),
                       lambda f:f.update(process_cpu_hidden=1),
                       lambda f:f.update(process_cpu_samples=cpu.CAP+1),
                       lambda f:f.update(process_cpu_failures=1),
                       lambda f:f.update(dropped=1),lambda f:f.update(io_error=True)):
            with self.assertRaises(ValueError):checked(mutate)
