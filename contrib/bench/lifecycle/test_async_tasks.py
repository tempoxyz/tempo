import json
from pathlib import Path
import tempfile
import unittest
from async_tasks import inspect, admission, write_observations
from backpressure import prepare_captures
from report import build

HEADER = dict(type='header', schema=1, clock='shared_monotonic_relative_ns', detail='full', async_tasks='selected_v1')
FOOTER = dict(type='footer', dropped=0, io_error=False, async_coverage_failures=0)


def event(ts, stage, thread=1, **fields):
    return dict(type='event', id=0, thread=thread, ts=ts,
                fields=dict(stage='async_task_'+stage, **fields))


def registrations():
    return [event(i, 'register', task_id=i, task_role=i) for i in range(1, 7)] + [event(7,'terminal',task_id=i,task_outcome=2) for i in range(2,7)]


def capture(path, events, header=HEADER, footer=FOOTER):
    path.write_text('\n'.join(map(json.dumps, [header, *events, footer]))+'\n')


class AsyncTaskTests(unittest.TestCase):
    def test_observed_wake_poll_and_migration_are_separate(self):
        events = registrations() + [
            event(10,'poll_begin',task_id=1,task_poll=1,task_wakes=0),
            event(12,'wake',task_id=1,task_poll=2),
            event(15,'poll_end',task_id=1,task_poll=1,task_outcome=0),
            event(20,'poll_begin',thread=2,task_id=1,task_poll=2,task_wakes=2),
            event(25,'poll_end',thread=2,task_id=1,task_poll=2,task_outcome=1),
            event(26,'terminal',thread=2,task_id=1,task_outcome=1)]
        result = inspect(events, HEADER, FOOTER)
        self.assertTrue(result['valid'], result['errors'])
        self.assertEqual([(r['start'],r['end'],r['thread'],r['kind']) for r in result['intervals']],
                         [(10,15,1,'poll'),(20,25,2,'poll'),(12,20,0,'wake request to poll')])
        self.assertEqual(result['observations'][0]['status'], 'initial_poll')

    def test_publication_after_begin_and_terminal_never_reopens(self):
        events = registrations() + [
            event(10,'poll_begin',task_id=1,task_poll=1,task_wakes=0),
            event(15,'poll_end',task_id=1,task_poll=1,task_outcome=0),
            event(20,'poll_begin',task_id=1,task_poll=2,task_wakes=1),
            event(25,'poll_end',task_id=1,task_poll=2,task_outcome=1),
            event(26,'terminal',task_id=1,task_outcome=1),
            event(30,'wake',task_id=1,task_poll=2),
            event(31,'wake',task_id=1,task_poll=3)]
        result = inspect(events, HEADER, FOOTER)
        self.assertTrue(result['valid'], result['errors'])
        self.assertTrue(all(r['kind']=='poll' for r in result['intervals']))
        self.assertEqual(result['observations'][-2]['status'],'wake_publication_raced')
        self.assertEqual(result['observations'][-1]['status'],'unconsumed_or_terminal_race')

    def test_cutoff_discards_exact_boundary_and_censors_open_poll(self):
        events = registrations()+[
            event(10,'poll_begin',task_id=1,task_poll=1,task_wakes=0),
            event(15,'poll_end',task_id=1,task_poll=1,task_outcome=0),
            event(20,'poll_begin',task_id=1,task_poll=2,task_wakes=1),
            event(30,'wake',task_id=1,task_poll=2),
            event(31,'poll_end',task_id=1,task_poll=2,task_outcome=0)]
        result = inspect(events, HEADER, FOOTER, cutoff=30)
        self.assertTrue(result['valid'], result['errors'])
        self.assertEqual(result['observations'][-1]['status'],'wake_missing_or_cutoff')
        self.assertFalse(result['observations'][-1]['end_observed'])
        self.assertTrue(all(i['end'] < 30 for i in result['intervals']))
        self.assertEqual(result['events'],14)

    def test_unknown_fields_missing_roles_and_duplicate_ids_fail(self):
        cases = [[e for e in registrations() if e['fields']['task_id'] != 6], registrations()+[registrations()[0]],
                 registrations()+[event(10,'wake',task_id=1,task_poll=1,secret=7)],
                 registrations()+[event(10,'poll_begin',task_id=1,task_poll=True,task_wakes=0)]]
        for events in cases:
            self.assertFalse(inspect(events,HEADER,FOOTER)['valid'])

    def test_failures_survive_pruning_and_unsupported_binary_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'
            capture(path, registrations(), header=dict(type='header',schema=1))
            self.assertFalse(admission([path],'selected_v1'))
            capture(path, registrations())
            self.assertTrue(admission([path],'selected_v1'))
            for outcome in (3,4,5,6):
                capture(path, registrations()+[event(30,'coverage',task_outcome=outcome)],
                        footer=dict(FOOTER,async_coverage_failures=1))
                paths,window=prepare_captures([path],Path(directory)/'out',dict(backpressure=dict(ts=30,node='Validator A')))
                raw=[json.loads(line) for line in paths[0].read_text().splitlines()]
                self.assertEqual(raw[-1]['async_coverage_failures'],1)
                self.assertTrue(all(e.get('ts',0)<30 for e in raw))
                report=build(paths,window=window,expected_async_tasks='selected_v1')
                self.assertTrue(report['bad_capture'])
                self.assertIn('coverage_failure',report['quality'][0]['async_task_errors'])
            for bad in (None, True, -1, '0'):
                self.assertFalse(inspect(registrations(),HEADER,dict(FOOTER,async_coverage_failures=bad))['valid'])

    def test_missing_end_and_terminal_inconsistency_fail_without_rejecting_cutoff(self):
        begin = event(10,'poll_begin',task_id=1,task_poll=1,task_wakes=0)
        pending = event(12,'poll_end',task_id=1,task_poll=1,task_outcome=0)
        ready = event(12,'poll_end',task_id=1,task_poll=1,task_outcome=1)
        terminal = event(13,'terminal',task_id=1,task_outcome=1)
        next_begin = event(14,'poll_begin',task_id=1,task_poll=2,task_wakes=0)
        for tail in ([begin,next_begin], [begin,terminal], [begin,terminal,ready],
                     [begin,ready,next_begin], [begin,pending,terminal]):
            result=inspect(registrations()+tail,HEADER,FOOTER)
            self.assertFalse(result['valid'], tail)
        self.assertTrue(inspect(registrations()+[begin],HEADER,FOOTER,cutoff=11)['valid'])
        self.assertTrue(inspect(registrations()+[begin,pending,event(13,'terminal',task_id=1,task_outcome=2)],HEADER,FOOTER)['valid'])
        self.assertTrue(inspect(registrations()+[event(9,'terminal',task_id=1,task_outcome=2)],HEADER,FOOTER)['valid'])

    def test_uncut_shutdown_requires_terminal_even_without_poll(self):
        self.assertFalse(inspect(registrations(),HEADER,FOOTER)['valid'])
        self.assertTrue(inspect(registrations(),HEADER,FOOTER,cutoff=20)['valid'])
        self.assertTrue(inspect(registrations()+[event(8,'terminal',task_id=1,task_outcome=2)],HEADER,FOOTER)['valid'])

    def test_context_tracks_reuse_lanes_and_never_claim_block_association(self):
        events=registrations()
        for poll in range(1,1001):
            events += [event(10*poll,'poll_begin',task_id=1,task_poll=poll,task_wakes=0),
                       event(10*poll+1,'poll_end',task_id=1,task_poll=poll,task_outcome=0)]
        events.append(event(10002,'terminal',task_id=1,task_outcome=2))
        result=inspect(events,HEADER,FOOTER)
        self.assertTrue(result['valid'],result['errors'])
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)
            stale=out/'async-tasks-9999.json'
            stale.write_text('stale data from an earlier cutoff')
            write_observations({'Validator A':result},out)
            self.assertFalse(stale.exists())
            trace=json.loads((out/'async-tasks-0001.json').read_text())
            tracks={(e['pid'],e['tid']) for e in trace['traceEvents']}
            self.assertLessEqual(len(tracks),2)
            self.assertTrue(all(e['args'].get('block') is None for e in trace['traceEvents']))


if __name__ == '__main__': unittest.main()
