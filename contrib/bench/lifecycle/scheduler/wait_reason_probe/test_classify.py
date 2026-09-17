import unittest
from classify import Reason, classify, admit_sample, covered


class ClassifyTests(unittest.TestCase):
    def test_positive_exact_paths(self):
        for symbol, reason in [(b'futex_wait',Reason.FUTEX_WAIT),(b'io_schedule',Reason.KERNEL_IO_SCHEDULE),(b'hrtimer_nanosleep',Reason.TIMER_SLEEP),(b'pipe_read',Reason.PIPE_READ),(b'ep_poll',Reason.POLL_WAIT)]:
            self.assertEqual(classify([b'schedule',symbol,b'private_nonallowlisted_symbol']),reason)

    def test_absent_failed_ambiguous_and_variants_unknown(self):
        for symbols in [[],[b'0xPRIVATE'],[b'futex_wait.isra.0'],[b'futex_wait',b'io_schedule']]:
            self.assertEqual(classify(symbols),Reason.UNKNOWN)

    def test_no_private_strings_can_escape(self):
        self.assertIsInstance(classify([b'PRIVATE_PATH_AND_ADDRESS']),Reason)
        with self.assertRaises(ValueError) as error:
            admit_sample(1,2,1,'PRIVATE_SYMBOL')
        self.assertNotIn('PRIVATE',str(error.exception))

    def test_strict_cutoff_and_sleep_only(self):
        self.assertEqual(admit_sample(9,10,1,1),1)
        self.assertEqual(admit_sample(9,10,2,0),0)
        for timestamp,state in [(10,1),(11,2),(9,0),(9,256),(9,4)]:
            self.assertIsNone(admit_sample(timestamp,10,state,1))

    def test_closed_numeric_contract(self):
        for values in [(True,10,1,1),(1,10,1,True),(1,10,512,1),(1,10,1,99),(-1,10,1,1)]:
            with self.assertRaises(ValueError):admit_sample(*values)

    def test_empty_and_partial_marker_paths_are_not_success(self):
        for registrations,samples in [([0,0,0],[0,0,0]),([1,0,1],[24,0,24]),([1,1,1],[24,0,24]),([1,2,1],[24,24,24])]:
            self.assertFalse(covered(registrations,samples))
        self.assertTrue(covered([1,1,1],[1,24,2]))

    def test_coverage_is_strictly_numeric(self):
        for registrations,samples in [([1,True,1],[1,1,1]),([1,1,1],[-1,1,1]),([1,1],[1,1,1])]:
            with self.assertRaises(ValueError):covered(registrations,samples)

if __name__=='__main__':unittest.main()
